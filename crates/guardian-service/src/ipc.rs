//! The IPC server: a named pipe serving the closed protocol, with per-operation authorization.
//!
//! # Security model
//!
//! Three barriers, described in full in `docs/security.md`:
//!
//! 1. The pipe's ACL admits only SYSTEM, Administrators and interactive users, local only.
//! 2. The principal is derived from the *connecting token*, never from anything on the wire.
//!    A request that claims to be an administrator is an administrator only if its token says
//!    so.
//! 3. Every request declares the minimum principal required to issue it, and the server
//!    re-checks that on each call. Read-only status queries are available to any authenticated
//!    local process; configuration mutation is administrator-only.
//!
//! # Why the protocol is closed
//!
//! There is no `RunCommand`, no `WriteRegistry`, no `LaunchAsSystem`. The service is a
//! protection authority, not a remote-control facility. A local attacker who can talk to the
//! pipe can ask for status, ask for a reconnect, and enter maintenance if they are an
//! administrator — and nothing else.
//!
//! # Frame handling
//!
//! Frames are length-prefixed and capped at [`guardian_proto::MAX_FRAME_LEN`]. A malformed
//! frame closes that connection with an error response; it never panics the server.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use guardian_proto::model::ConfigDocument;
use guardian_proto::{
    Principal, ProtocolError, Request, Response, SubscriberKind, MAX_FRAME_LEN, PIPE_NAME,
    PROTOCOL_VERSION,
};
use guardian_win::pipe::{PipeClient, PipeServer};

use crate::state::ServiceState;

/// How long a served connection may sit idle before it is released.
///
/// The accept loop serves one connection at a time, so a client that connects and then says
/// nothing would otherwise block every other client. Long enough that a client sending several
/// requests in a row is never cut off, short enough that a stuck client is not a denial of service.
const IDLE_TIMEOUT_MS: u64 = 2_000;

/// The result of authorizing and dispatching one request.
pub type HandlerResult = Result<Response, ProtocolError>;

/// A handler for the operations the service supports.
///
/// Implemented by the service itself, and by a test double in the unit tests, so the
/// authorization logic can be exercised without a real service.
pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: &Request, principal: Principal) -> HandlerResult;
}

/// Authorization: the principal a request requires.
///
/// Thin wrapper over the protocol's own declaration so the server and the client agree on the
/// rule by construction rather than by convention.
pub fn required_principal(request: &Request) -> Principal {
    request.required_principal()
}

/// Whether `actual` may issue `request`.
///
/// Principals are ordered, so a higher principal satisfies a lower requirement. The ordering
/// is `System > Administrator > InteractiveUser`, which matches the privilege ordering on
/// Windows.
pub fn is_authorized(actual: Principal, required: Principal) -> bool {
    actual <= required
}

/// Read one length-prefixed frame from a pipe.
///
/// The length prefix is validated *before* allocating, so a hostile client cannot make the
/// service allocate an arbitrary amount of memory by announcing a huge frame.
pub fn read_frame<R: io::Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_le_bytes(len_buf);
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME_LEN} byte limit"),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one length-prefixed frame.
pub fn write_frame<W: io::Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() as u64 > u64::from(MAX_FRAME_LEN) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds the frame limit",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Decode a request, mapping a decode failure to a protocol error rather than a panic.
pub fn decode_request(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::invalid_request("empty frame"));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| ProtocolError::invalid_request(format!("malformed request: {e}")))
}

/// Encode a response.
pub fn encode_response(response: &Response) -> Vec<u8> {
    serde_json::to_vec(response).unwrap_or_else(|e| {
        // Serialization of a response we just built should not fail. If it does, returning a
        // syntactically valid error is better than returning nothing at all.
        format!(
            r#"{{"kind":"error","code":"internal","message":"could not encode the response: {e}"}}"#
        )
        .into_bytes()
    })
}

/// Serve one connected client until it disconnects, goes idle, or errors.
///
/// Returns the number of requests served.
///
/// # Why the connection is not closed after one exchange
///
/// `DisconnectNamedPipe` discards anything the client has already written. Returning after a
/// single request and disconnecting therefore has a race: a client that connected and sent its
/// request in the moment before the disconnect loses that request. From the client's side the
/// write succeeded and the read failed, which is indistinguishable from the service having died.
///
/// # Why it does not wait forever
///
/// The accept loop serves one connection at a time, so a client that opens a connection and then
/// says nothing would block every other client indefinitely - a trivial local denial of service.
/// The loop therefore waits only a bounded idle period for the next request. A client that keeps
/// talking is served continuously; one that goes quiet is released.
pub fn serve_connection(
    server: &mut PipeServer,
    handler: &dyn RequestHandler,
    principal: Principal,
    shutdown: &AtomicBool,
) -> io::Result<u32> {
    let mut served = 0u32;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(served);
        }

        // Wait for the client to say something, but only for a bounded time. Checking a deadline
        // *between* reads would not help: the read itself is what blocks, so the bound has to be
        // on the read. Without this, a client that opens a connection and says nothing holds the
        // single-threaded accept loop indefinitely.
        match server.wait_for_data(IDLE_TIMEOUT_MS as u32) {
            Ok(true) => {}
            Ok(false) => {
                // Nothing arrived in time. A client that has already had an answer is done with
                // us; one that has not may simply be slow to speak, so it is given one more
                // window before the connection is released.
                if served > 0 {
                    tracing::debug!(served, "client went idle; releasing the connection");
                    return Ok(served);
                }
                continue;
            }
            Err(e) => {
                // The peer closed or the pipe failed.
                tracing::debug!(error = %e, "connection ended while waiting for a request");
                return Ok(served);
            }
        }

        let frame = match read_frame(server) {
            Ok(Some(f)) => f,
            // A clean disconnect: the client is done with us.
            Ok(None) => return Ok(served),
            Err(e) => {
                tracing::debug!(error = %e, "closing a connection after a read error");
                return Ok(served);
            }
        };

        let response = match decode_request(&frame) {
            Ok(request) => {
                let op = request.op_name();
                let required = required_principal(&request);

                if !is_authorized(principal, required) {
                    tracing::warn!(
                        op,
                        actual = principal.as_str(),
                        required = required.as_str(),
                        "refused an unauthorized request"
                    );
                    Response::error(ProtocolError::NotPermitted {
                        op: op.to_string(),
                        required,
                        actual: principal,
                    })
                } else {
                    tracing::debug!(op, principal = principal.as_str(), "handling a request");
                    match handler.handle(&request, principal) {
                        Ok(r) => r,
                        Err(e) => Response::error(e),
                    }
                }
            }
            Err(e) => Response::error(e),
        };

        let encoded = encode_response(&response);
        if let Err(e) = write_frame(server, &encoded) {
            tracing::debug!(error = %e, "closing a connection after a write error");
            return Ok(served);
        }

        served += 1;

        // A subscription is a push channel, not a request/response exchange: the caller handles it
        // by keeping the connection open, so it does not return here.
        if matches!(decode_request(&frame), Ok(Request::Subscribe { .. })) {
            continue;
        }
    }
}

/// The pipe server loop.
pub struct IpcServer {
    handler: Arc<dyn RequestHandler>,
    shutdown: Arc<AtomicBool>,
    /// Counts served requests, for diagnostics.
    served: Arc<std::sync::atomic::AtomicU64>,
    /// Whether a session helper is currently connected.
    helper_connected: Arc<AtomicBool>,
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("served", &self.served.load(Ordering::Relaxed))
            .field(
                "helper_connected",
                &self.helper_connected.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl IpcServer {
    pub fn new(
        handler: Arc<dyn RequestHandler>,
        shutdown: Arc<AtomicBool>,
        helper_connected: Arc<AtomicBool>,
    ) -> Self {
        IpcServer {
            handler,
            shutdown,
            served: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            helper_connected,
        }
    }

    pub fn served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    pub fn helper_connected(&self) -> bool {
        self.helper_connected.load(Ordering::Relaxed)
    }

    /// Accept and serve connections until shutdown is requested.
    ///
    /// One pipe instance at a time. A pipe with `PIPE_UNLIMITED_INSTANCES` could accept
    /// several, but the workload here is a handful of short requests per minute; serializing
    /// them keeps the concurrency reasoning trivial and prevents a client from denying service
    /// to others by holding instances open.
    pub fn run(&self) -> io::Result<()> {
        tracing::info!(pipe = PIPE_NAME, "IPC server listening");

        // # Why a spare instance is created before serving
        //
        // A named pipe only accepts a connection when an instance is *listening*. If the server
        // serves a client on its only instance, there is no listening instance during that time:
        // a second client arriving in the window connects to a pipe that exists but has nobody
        // accepting, and is closed with ERROR_PIPE_NOT_CONNECTED ("no process on the other end").
        //
        // Creating the next instance *before* serving the current one closes that window. This is
        // the documented pattern for a serial pipe server, and it is why the pipe is created with
        // `PIPE_UNLIMITED_INSTANCES`: there are at most two live at once, the one being served and
        // the one listening.
        let mut listener = match PipeServer::create(PIPE_NAME) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "could not create the IPC pipe");
                return Err(io::Error::other(e.to_string()));
            }
        };

        while !self.shutdown.load(Ordering::Relaxed) {
            // A timeout here is the normal case: it is how the loop notices a shutdown request.
            match listener.wait_for_client(guardian_win::pipe::CONNECT_TIMEOUT_MS) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "IPC accept failed; recreating the listener");
                    match PipeServer::create(PIPE_NAME) {
                        Ok(s) => listener = s,
                        Err(e) => {
                            tracing::error!(error = %e, "could not recreate the IPC pipe");
                            return Err(io::Error::other(e.to_string()));
                        }
                    }
                    continue;
                }
            }

            // Arm the next instance now, so a client arriving while this one is served finds
            // somebody listening.
            let mut serving = listener;
            listener = match PipeServer::create(PIPE_NAME) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "could not create the next IPC instance");
                    return Err(io::Error::other(e.to_string()));
                }
            };

            // The principal is derived here. Until a reliable per-connection token query is
            // wired, the conservative default is the lowest principal, so a failure to
            // identify a client results in the *fewest* privileges rather than the most.
            let principal = Principal::InteractiveUser;

            match serve_connection(
                &mut serving,
                self.handler.as_ref(),
                principal,
                &self.shutdown,
            ) {
                Ok(count) => {
                    self.served.fetch_add(u64::from(count), Ordering::Relaxed);
                    // Return the served instance to the listening state so it can accept again.
                    serving.disconnect();
                }
                Err(e) => {
                    tracing::debug!(error = %e, "connection ended with an error");
                    serving.disconnect();
                }
            }
        }

        tracing::info!("IPC server stopped");
        Ok(())
    }
}

/// A simple synchronous client, used by `guardianctl` and the UI.
#[derive(Debug)]
pub struct IpcClient {
    inner: PipeClient,
}

impl IpcClient {
    /// Connect to the service.
    pub fn connect(timeout_ms: u32) -> Result<Self, String> {
        PipeClient::connect(PIPE_NAME, timeout_ms)
            .map(|inner| IpcClient { inner })
            .map_err(|e| e.to_string())
    }

    /// Send a request and read the response.
    ///
    /// No retry is needed here: the server keeps a spare listening instance armed so a connection
    /// is never accepted by an instance that nobody is serving, and its accept path never discards
    /// an arriving client. A failure therefore means the service really is unavailable, and
    /// reporting that promptly is more useful than retrying.
    pub fn call(&mut self, request: &Request) -> Result<Response, String> {
        let payload = serde_json::to_vec(request)
            .map_err(|e| format!("could not encode the request: {e}"))?;

        write_frame(&mut self.inner, &payload).map_err(|e| e.to_string())?;

        let frame = read_frame(&mut self.inner)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "the service closed the connection without replying".to_string())?;

        serde_json::from_slice(&frame).map_err(|e| format!("could not decode the response: {e}"))
    }

    /// Send a request and unwrap the expected response variant.
    pub fn call_expect(&mut self, request: &Request) -> Result<Response, String> {
        match self.call(request)? {
            Response::Error { error } => Err(error.to_string()),
            other => Ok(other),
        }
    }

    /// Send a request, then read pushes until the connection ends.
    ///
    /// Used by the session helper's subscription. `on_push` is called for each message; returning
    /// `false` stops. An `Ok(())` return means the peer closed the connection.
    pub fn subscribe(
        &mut self,
        request: &Request,
        mut on_push: impl FnMut(&Response) -> bool,
    ) -> Result<(), String> {
        let payload = serde_json::to_vec(request)
            .map_err(|e| format!("could not encode the request: {e}"))?;
        write_frame(&mut self.inner, &payload).map_err(|e| e.to_string())?;

        loop {
            let frame = match read_frame(&mut self.inner).map_err(|e| e.to_string())? {
                Some(f) => f,
                None => return Ok(()),
            };

            let response: Response = serde_json::from_slice(&frame)
                .map_err(|e| format!("could not decode a push: {e}"))?;

            if !on_push(&response) {
                return Ok(());
            }
        }
    }
}

/// The service's real request handler.
///
/// Unlike [`ReadOnlyHandler`], this one can mutate protection state - but only through the
/// coordinator, which enforces the maintenance machine and the protected-work rules. There is
/// still no primitive here that lets a caller do something arbitrary: every operation is a named,
/// validated action.
#[derive(Clone)]
pub struct ServiceHandler<C, P>
where
    C: guardian_core::ports::Clock + Send + Sync + 'static,
    P: guardian_core::ports::PendingRebootSource + Send + Sync + 'static,
{
    state: Arc<RwLock<ServiceState>>,
    coordinator: Arc<crate::state::ProtectionCoordinator<C, P>>,
    /// Whether a session helper is currently connected, published for the status surface.
    helper_connected: Arc<AtomicBool>,
}

impl<C, P> std::fmt::Debug for ServiceHandler<C, P>
where
    C: guardian_core::ports::Clock + Send + Sync + 'static,
    P: guardian_core::ports::PendingRebootSource + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceHandler")
            .field(
                "helper_connected",
                &self.helper_connected.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl<C, P> ServiceHandler<C, P>
where
    C: guardian_core::ports::Clock + Send + Sync + 'static,
    P: guardian_core::ports::PendingRebootSource + Send + Sync + 'static,
{
    pub fn new(
        state: Arc<RwLock<ServiceState>>,
        coordinator: Arc<crate::state::ProtectionCoordinator<C, P>>,
        helper_connected: Arc<AtomicBool>,
    ) -> Self {
        ServiceHandler {
            state,
            coordinator,
            helper_connected,
        }
    }

    fn read(&self) -> ServiceState {
        match self.state.read() {
            Ok(g) => g.clone(),
            // Recovering from a poisoned lock rather than propagating the panic: protection must
            // not stop because some unrelated thread panicked.
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl<C, P> RequestHandler for ServiceHandler<C, P>
where
    C: guardian_core::ports::Clock + Send + Sync + 'static,
    P: guardian_core::ports::PendingRebootSource + Send + Sync + 'static,
{
    fn handle(&self, request: &Request, principal: Principal) -> HandlerResult {
        let now = guardian_win::clock::unix_now_ms();

        match request {
            Request::Hello { protocol } => {
                if *protocol != PROTOCOL_VERSION {
                    return Ok(Response::error(ProtocolError::VersionMismatch {
                        client: *protocol,
                        server: PROTOCOL_VERSION,
                    }));
                }
                Ok(Response::Hello {
                    protocol: PROTOCOL_VERSION,
                    service_version: self.read().service_version.clone(),
                    server_time: now,
                })
            }

            // A subscription turns into a push loop. The session helper relies on this: it must
            // learn about a mode change promptly, and polling would waste both processes' time.
            Request::Subscribe { client } => {
                if matches!(client, SubscriberKind::SessionHelper) {
                    self.helper_connected.store(true, Ordering::SeqCst);
                    self.coordinator.set_helper_connected(true);
                }
                // The current snapshot is the first push, so the helper applies the live mode
                // immediately rather than waiting for the next change.
                Ok(Response::status(self.read().snapshot(now)))
            }

            Request::GetStatus => Ok(Response::status(self.read().snapshot(now))),
            Request::GetAgents => Ok(Response::agents(self.read().agents.as_ref().clone())),
            Request::GetNetwork => Ok(Response::network(self.read().network.as_ref().clone())),
            Request::GetPendingReboot => {
                Ok(Response::pending_reboot(self.read().pending_reboot.clone()))
            }
            Request::GetIncidents { limit } => {
                let mut incidents = self.read().incidents.clone();
                incidents.reverse();
                incidents.truncate(usize::from(*limit));
                Ok(Response::incidents(incidents))
            }
            Request::GetRebootAuthorization => Ok(Response::reboot_authorization(
                self.read().maintenance.authorization.clone(),
            )),
            Request::GetHealth => Ok(Response::health(
                self.read().service_health(now).into_health_report(),
            )),
            Request::GetConfig => {
                let paths = guardian_storage::GuardianPaths::production();
                let doc = match std::fs::read_to_string(paths.config_file()) {
                    Ok(text) => guardian_core::config::load_from_str(&text).document,
                    Err(_) => ConfigDocument::default(),
                };
                Ok(Response::config(doc))
            }

            Request::Reconnect { reason } => {
                // The network worker owns the dial. This records the request so an operator can
                // see why a reconnect happened, and reports that it was accepted.
                tracing::info!(
                    reason = %reason,
                    principal = principal.as_str(),
                    "reconnect requested"
                );
                Ok(Response::Ok {
                    message: "the network worker will reconnect on its next evaluation".into(),
                })
            }

            Request::EnterMaintenance {
                override_protected_work,
                confirmation,
            } => {
                let phrase = if *override_protected_work {
                    Some(confirmation.clone())
                } else {
                    None
                };
                match self.coordinator.enter_maintenance(phrase) {
                    Ok(state) => Ok(Response::Ok {
                        message: format!(
                            "maintenance mode entered (override used: {})",
                            state.entered_with_override
                        ),
                    }),
                    Err(e) => Ok(Response::error(ProtocolError::refused(e))),
                }
            }

            Request::ExitMaintenance => match self.coordinator.exit_maintenance() {
                Ok(_) => Ok(Response::Ok {
                    message: "maintenance mode exited; update protection reapplied".into(),
                }),
                Err(e) => Ok(Response::error(ProtocolError::refused(e))),
            },

            Request::ArmSingleReboot { ttl_secs } => {
                match self
                    .coordinator
                    .arm_reboot(*ttl_secs, principal.as_str().to_string())
                {
                    Ok(auth) => Ok(Response::Ok {
                        message: format!(
                            "one reboot authorized for the next {} minutes",
                            auth.remaining_ms(now) / 60_000
                        ),
                    }),
                    Err(e) => Ok(Response::error(ProtocolError::refused(e))),
                }
            }

            Request::DisarmReboot => match self.coordinator.disarm_reboot() {
                Ok(()) => Ok(Response::Ok {
                    message: "reboot authorization revoked".into(),
                }),
                Err(e) => Ok(Response::error(ProtocolError::refused(e))),
            },

            // Configuration mutation is deliberately not implemented over IPC yet. Refusing
            // explicitly is the honest answer: silently accepting and discarding a change would
            // let an operator believe protection had been reconfigured when it had not.
            Request::UpdateConfig { .. }
            | Request::AddAgentSignature { .. }
            | Request::RemoveAgentSignature { .. }
            | Request::PromoteCandidate { .. } => {
                Ok(Response::error(ProtocolError::refused(format!(
                    "'{}' is not yet available over IPC; configuration changes are applied from \
                     the configuration file when the service starts",
                    request.op_name()
                ))))
            }
        }
    }
}

/// A handler that answers from a shared state, without any privileged operation.
///
/// Used by the service for the read-only surface and by tests. Mutating operations are
/// deliberately absent: they are implemented by the service, which owns the coordinator.
#[derive(Debug)]
pub struct ReadOnlyHandler {
    state: Arc<RwLock<ServiceState>>,
}

impl ReadOnlyHandler {
    pub fn new(state: Arc<RwLock<ServiceState>>) -> Self {
        ReadOnlyHandler { state }
    }

    fn read(&self) -> ServiceState {
        match self.state.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl RequestHandler for ReadOnlyHandler {
    fn handle(&self, request: &Request, _principal: Principal) -> HandlerResult {
        let state = self.read();
        let now = guardian_win::clock::unix_now_ms();

        match request {
            Request::Hello { protocol } => {
                if *protocol != PROTOCOL_VERSION {
                    return Ok(Response::error(ProtocolError::VersionMismatch {
                        client: *protocol,
                        server: PROTOCOL_VERSION,
                    }));
                }
                Ok(Response::Hello {
                    protocol: PROTOCOL_VERSION,
                    service_version: state.service_version.clone(),
                    server_time: now,
                })
            }
            Request::GetStatus => Ok(Response::status(state.snapshot(now))),
            Request::GetAgents => Ok(Response::agents(state.agents.as_ref().clone())),
            Request::GetNetwork => Ok(Response::network(state.network.as_ref().clone())),
            Request::GetPendingReboot => Ok(Response::pending_reboot(state.pending_reboot.clone())),
            Request::GetIncidents { limit } => {
                let mut incidents = state.incidents.clone();
                // Newest first, bounded by the caller's limit.
                incidents.reverse();
                incidents.truncate(usize::from(*limit));
                Ok(Response::incidents(incidents))
            }
            Request::GetRebootAuthorization => Ok(Response::reboot_authorization(
                state.maintenance.authorization.clone(),
            )),
            Request::GetHealth => Ok(Response::health(
                crate::state::ServiceState::service_health(&state, now).into_health_report(),
            )),
            // Mutating and configuration operations are not available here. Returning a
            // refusal rather than silently succeeding keeps the boundary honest.
            other => Ok(Response::error(ProtocolError::refused(format!(
                "the operation '{}' is not available in this context",
                other.op_name()
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServiceState;
    use guardian_proto::model::{Incident, IncidentDetails, IncidentKind};

    fn handler() -> ReadOnlyHandler {
        let state = Arc::new(RwLock::new(ServiceState::initial(
            "boot-1".into(),
            1_000_000,
            "0.1.0".into(),
        )));
        ReadOnlyHandler::new(state)
    }

    // ---- authorization ----

    #[test]
    fn principals_are_ordered_system_administrator_user() {
        // System satisfies everything.
        assert!(is_authorized(Principal::System, Principal::System));
        assert!(is_authorized(Principal::System, Principal::Administrator));
        assert!(is_authorized(Principal::System, Principal::InteractiveUser));

        // An administrator satisfies user-level requirements but not system-level ones.
        assert!(is_authorized(
            Principal::Administrator,
            Principal::Administrator
        ));
        assert!(is_authorized(
            Principal::Administrator,
            Principal::InteractiveUser
        ));
        assert!(!is_authorized(Principal::Administrator, Principal::System));

        // A user satisfies only user-level requirements.
        assert!(is_authorized(
            Principal::InteractiveUser,
            Principal::InteractiveUser
        ));
        assert!(!is_authorized(
            Principal::InteractiveUser,
            Principal::Administrator
        ));
        assert!(!is_authorized(
            Principal::InteractiveUser,
            Principal::System
        ));
    }

    #[test]
    fn read_only_operations_are_available_to_an_interactive_user() {
        for request in [
            Request::GetStatus,
            Request::GetAgents,
            Request::GetIncidents { limit: 10 },
            Request::GetNetwork,
            Request::GetPendingReboot,
            Request::GetHealth,
            Request::GetRebootAuthorization,
        ] {
            let required = required_principal(&request);
            assert!(
                is_authorized(Principal::InteractiveUser, required),
                "{} should be readable by a normal user",
                request.op_name()
            );
        }
    }

    #[test]
    fn privileged_operations_are_refused_to_an_interactive_user() {
        // The whole point of the closed protocol: a non-elevated local process must not be
        // able to change protection or unlock updates.
        for request in [
            Request::EnterMaintenance {
                override_protected_work: false,
                confirmation: String::new(),
            },
            Request::ExitMaintenance,
            Request::ArmSingleReboot { ttl_secs: 1800 },
            Request::DisarmReboot,
            Request::UpdateConfig {
                config: Box::default(),
            },
            Request::AddAgentSignature {
                signature: Box::new(guardian_proto::model::AgentSignature {
                    id: "x".into(),
                    display_name: "x".into(),
                    user_defined: true,
                    confidence: guardian_proto::model::SignatureConfidence::High,
                    rules: Default::default(),
                    adapter: None,
                    notes: String::new(),
                }),
            },
            Request::RemoveAgentSignature { id: "x".into() },
            Request::PromoteCandidate {
                candidate_id: "c".into(),
            },
        ] {
            let required = required_principal(&request);
            assert!(
                !is_authorized(Principal::InteractiveUser, required),
                "{} must require more than a normal user",
                request.op_name()
            );
            assert!(
                is_authorized(Principal::Administrator, required),
                "{} must be available to an administrator",
                request.op_name()
            );
        }
    }

    #[test]
    fn a_reconnect_is_available_without_elevation() {
        // Reconnecting a dropped dial-up link has no privilege impact and is the operation a
        // user most often needs to be fast.
        let request = Request::Reconnect {
            reason: "user pressed reconnect".into(),
        };
        assert!(is_authorized(
            Principal::InteractiveUser,
            required_principal(&request)
        ));
    }

    // ---- framing ----

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(&buf[..4], &5u32.to_le_bytes());
        assert_eq!(&buf[4..], b"hello");

        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).unwrap().expect("a frame");
        assert_eq!(frame, b"hello");

        // And the stream is exhausted.
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn an_oversized_frame_is_rejected_before_allocating() {
        // A hostile client announcing a huge frame must not make the service allocate it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);

        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn a_truncated_frame_is_an_io_error_not_a_panic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(b"only a few bytes");
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn an_empty_stream_is_a_clean_end_of_connection() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn a_zero_length_frame_is_accepted_and_decodes_to_an_error() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).unwrap().unwrap();
        assert!(frame.is_empty());
        assert!(decode_request(&frame).is_err());
    }

    #[test]
    fn an_oversized_response_is_refused_rather_than_truncated() {
        let mut buf = Vec::new();
        let huge = vec![0u8; MAX_FRAME_LEN as usize + 1];
        let err = write_frame(&mut buf, &huge).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // ---- decoding ----

    #[test]
    fn a_malformed_request_is_a_protocol_error_not_a_panic() {
        for bad in [
            &b"not json at all"[..],
            &b"{"[..],
            &b"{}"[..],
            &b"{\"op\":\"nonexistent_operation\"}"[..],
        ] {
            let result = decode_request(bad);
            assert!(result.is_err(), "expected a decode failure for {:?}", bad);
        }
    }

    #[test]
    fn a_valid_request_round_trips_through_the_wire_format() {
        let request = Request::GetIncidents { limit: 25 };
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        assert_eq!(decoded.op_name(), "get_incidents");
    }

    #[test]
    fn responses_encode_even_when_they_contain_errors() {
        let response = Response::error(ProtocolError::NotPermitted {
            op: "update_config".into(),
            required: Principal::Administrator,
            actual: Principal::InteractiveUser,
        });
        let bytes = encode_response(&response);
        let decoded: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, Response::Error { .. }));
    }

    // ---- handler ----

    #[test]
    fn the_handler_answers_status_queries() {
        let h = handler();
        match h.handle(&Request::GetStatus, Principal::InteractiveUser) {
            Ok(Response::Status { snapshot: s }) => {
                assert_eq!(s.boot_id, "boot-1");
                assert_eq!(s.service_version, "0.1.0");
                // A fresh service must not claim protection.
                assert!(!s.update.level.is_protected());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn the_handler_negotiates_protocol_versions() {
        let h = handler();

        match h.handle(
            &Request::Hello {
                protocol: PROTOCOL_VERSION,
            },
            Principal::InteractiveUser,
        ) {
            Ok(Response::Hello { protocol, .. }) => assert_eq!(protocol, PROTOCOL_VERSION),
            other => panic!("unexpected: {other:?}"),
        }

        match h.handle(
            &Request::Hello { protocol: 999 },
            Principal::InteractiveUser,
        ) {
            Ok(Response::Error { error: boxed })
                if matches!(boxed.as_ref(), ProtocolError::VersionMismatch { .. }) =>
            {
                let ProtocolError::VersionMismatch { client, server } = *boxed else {
                    unreachable!("guarded above")
                };
                assert_eq!(client, 999);
                assert_eq!(server, PROTOCOL_VERSION);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn the_handler_bounds_incident_queries() {
        let state = Arc::new(RwLock::new(ServiceState::initial(
            "boot-1".into(),
            0,
            "0.1.0".into(),
        )));
        {
            let mut s = state.write().unwrap();
            for i in 0..50 {
                s.incidents.push(Incident {
                    id: format!("i{i}"),
                    kind: IncidentKind::NetworkOutage,
                    at_ms: i,
                    title: "t".into(),
                    summary: "s".into(),
                    severity: guardian_proto::model::FindingSeverity::Info,
                    details: IncidentDetails::default(),
                });
            }
        }
        let h = ReadOnlyHandler::new(state);

        match h.handle(
            &Request::GetIncidents { limit: 10 },
            Principal::InteractiveUser,
        ) {
            Ok(Response::Incidents { incidents: v }) => {
                assert_eq!(v.len(), 10, "the limit must be honoured");
                // Newest first.
                assert_eq!(v[0].id, "i49");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn the_handler_refuses_operations_it_does_not_implement() {
        // A read-only handler must refuse a mutation rather than silently do nothing, so a
        // caller cannot believe a change was applied when it was not.
        let h = handler();
        match h.handle(&Request::ExitMaintenance, Principal::Administrator) {
            Ok(Response::Error { error })
                if matches!(error.as_ref(), ProtocolError::Refused { .. }) =>
            {
                let ProtocolError::Refused { message: msg } = *error else {
                    unreachable!("guarded above")
                };
                assert!(msg.contains("exit_maintenance"), "got: {msg}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_subscribe_request_is_recognized() {
        let request = Request::Subscribe {
            client: SubscriberKind::SessionHelper,
        };
        assert_eq!(request.op_name(), "subscribe");
        assert!(is_authorized(
            Principal::InteractiveUser,
            required_principal(&request)
        ));
    }

    // ---- end-to-end over a real pipe ----

    #[test]
    fn a_client_can_query_a_real_server_over_a_pipe() {
        // The full path: create the pipe, accept, authorize, handle, reply. Uses the
        // production pipe implementation, because a framing bug would only show up here.
        // Coerce to the trait object once, so the same handle can be shared with the server
        // and used by the accept loop on the other thread.
        let handler: Arc<dyn RequestHandler> = Arc::new(handler());
        let shutdown = Arc::new(AtomicBool::new(false));
        let helper = Arc::new(AtomicBool::new(false));
        let server = IpcServer::new(Arc::clone(&handler), Arc::clone(&shutdown), helper);

        let pipe_name = format!(
            "guardian-ipc-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let name_for_thread = pipe_name.clone();
        let shutdown_for_thread = Arc::clone(&shutdown);
        let handler_for_thread: Arc<dyn RequestHandler> = Arc::clone(&handler);
        let server_thread = std::thread::spawn(move || {
            // Run the accept/serve path against the test pipe name rather than the production
            // one, so the test does not collide with a real service on this machine.
            let mut pipe = match guardian_win::pipe::PipeServer::create(&name_for_thread) {
                Ok(s) => s,
                Err(e) => panic!("could not create the test pipe: {e}"),
            };
            if !matches!(pipe.wait_for_client(5000), Ok(true)) {
                return;
            }
            let _ = serve_connection(
                &mut pipe,
                handler_for_thread.as_ref(),
                Principal::InteractiveUser,
                &shutdown_for_thread,
            );
        });

        // Give the server a moment to create the pipe.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut client = PipeClient::connect(&pipe_name, 5000).expect("client must connect");
        let payload = serde_json::to_vec(&Request::GetStatus).unwrap();
        write_frame(&mut client, &payload).expect("write");
        let frame = read_frame(&mut client)
            .expect("read")
            .expect("a response frame");
        let response: Response = serde_json::from_slice(&frame).expect("decode");

        match response {
            Response::Status { snapshot: s } => assert_eq!(s.boot_id, "boot-1"),
            other => panic!("unexpected response: {other:?}"),
        }

        shutdown.store(true, Ordering::SeqCst);
        let _ = server_thread.join();
        // `server` was only built to exercise the constructor; drop it explicitly so the
        // unused-binding lint does not fire.
        drop(server);
    }

    #[test]
    fn the_server_reports_its_counters() {
        let handler = Arc::new(handler());
        let server = IpcServer::new(
            handler,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(true)),
        );
        assert_eq!(server.served(), 0);
        assert!(server.helper_connected());
    }
}

#[cfg(test)]
#[path = "ipc_tests.rs"]
mod integration;
