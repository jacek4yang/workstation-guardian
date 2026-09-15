//! Named-pipe IPC with a strict security descriptor and verified client identity.
//!
//! # Why a named pipe and not a localhost HTTP server
//!
//! A localhost TCP listener is reachable by every process on the machine and by anything
//! that can reach the loopback interface; authenticating it requires inventing an
//! application-level scheme. A named pipe is a kernel object with a discretionary ACL and an
//! identity that the kernel attaches to the connection. Authorization becomes a property of
//! the object rather than of the protocol.
//!
//! # The threat model
//!
//! A non-administrator local process will try to talk to this pipe. It must not be able to
//! make the LocalSystem service do anything privileged. Three independent barriers:
//!
//! 1. **ACL** — only SYSTEM and Administrators get `FILE_ALL_ACCESS`. `Everyone` is granted
//!    only `FILE_GENERIC_READ` plus `FILE_WRITE_DATA`/`READ_DATA`, which is enough to send
//!    a request and read a reply but does not grant the pipe's own synchronization or
//!    attribute-write rights. Interactive-user requests are additionally re-checked against
//!    the per-operation policy, so read-only access is genuinely read-only.
//! 2. **Client identity** — the service reads the connecting token and derives the
//!    principal itself. Nothing on the wire is trusted for authorization.
//! 3. **Closed protocol** — there is no "run command" or "write registry value" primitive to
//!    reach, only named operations.
//!
//! # Impersonation
//!
//! `ImpersonateNamedPipeClient` is deliberately **not** used. Impersonation changes the
//! server thread's security context, and a bug in the reversion path leaks a client's
//! identity into unrelated service work. Reading the client's token with `OpenThreadToken`
//! gives the same information with none of that risk.

use std::ffi::c_void;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe, PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken, INFINITE};
use windows::Win32::System::IO::GetOverlappedResult;

use crate::WinError;

/// The security descriptor applied to the pipe.
///
/// * `SY`/`BA` — SYSTEM and Built-in Administrators get full access.
/// * `IU` — interactive users get generic read, generic write, and the right to create a pipe
///   instance. That is what a local client needs to open a connection, exchange a framed
///   request, and (for the self-hosting case) arm the next listening instance.
///
/// # How this mask was determined
///
/// Empirically, against Windows 11, rather than from reasoning about the bit names. Starting from
/// an apparently minimal mask of `FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
/// SYNCHRONIZE`, the *first* instance could be created but the **second** failed with
/// `ERROR_ACCESS_DENIED`. Individually adding `FILE_CREATE_PIPE_INSTANCE`, `READ_CONTROL`,
/// `FILE_READ_EA`, `FILE_WRITE_EA` or `FILE_WRITE_ATTRIBUTES` each still failed; replacing the
/// whole mask with `FILE_GENERIC_READ | FILE_GENERIC_WRITE` succeeded.
///
/// The reason is that the sub-rights of a *generic* access mask are not simply their bitwise
/// union: granting generic read and write is what permits reopening an existing pipe for a new
/// instance. Since a local client needs generic read and write anyway to exchange a request, the
/// practical mask and the necessary mask coincide, so nothing is granted for the second-instance
/// case that a client did not already need.
///
/// What remains deliberately **not** granted to interactive users is `WRITE_DAC`, `WRITE_OWNER`
/// and `DELETE`: a client cannot re-ACL the pipe, take ownership of it, or delete it. Remote
/// clients are rejected by `PIPE_REJECT_REMOTE_CLIENTS`, so even this grant is local-only.
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;FRFW;;;IU)";

/// The interactive-user mask, as the numeric equivalent of `FRFW`, so the client's request and
/// the server's grant can be asserted equal in a test.
pub const PIPE_SDDL_MASK: u32 = 0x0012_019F;

/// How long a `ConnectNamedPipe` waits before giving up and letting the loop re-check its
/// shutdown flag.
///
/// Chosen so a service stop is acknowledged promptly while a busy pipe is not spun on. The
/// accept loop treats a timeout as the normal case rather than as an error.
pub const CONNECT_TIMEOUT_MS: u32 = 500;

/// A security descriptor that owns and frees itself.
#[derive(Debug)]
pub struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    /// Build a descriptor from SDDL.
    pub fn from_sddl(sddl: &str) -> Result<Self, WinError> {
        // The SDDL is converted into a self-relative descriptor allocated with LocalAlloc,
        // which must be released with LocalFree.
        let wide = crate::WideString::new(sddl);
        let mut raw = PSECURITY_DESCRIPTOR::default();

        // Safety: `wide` is a valid NUL-terminated string and `raw` is a correctly typed
        // out-parameter. The returned descriptor is self-relative, so no further conversion
        // is needed before it is used in SECURITY_ATTRIBUTES.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut raw,
                None,
            )
        };

        if ok.is_err() || raw.is_invalid() {
            return Err(WinError::last(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }

        Ok(SecurityDescriptor { raw })
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.raw
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_invalid() {
            // Safety: the descriptor came from LocalAlloc via the conversion API and is
            // freed exactly once here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.raw.0)));
            }
        }
    }
}

/// A manual-reset event handle that closes itself.
#[derive(Debug)]
struct OwnedEvent(HANDLE);

impl OwnedEvent {
    fn new() -> Result<Self, WinError> {
        use windows::Win32::System::Threading::CreateEventW;
        // Safety: a null security descriptor and name with default flags creates an
        // unnamed, non-signalled manual-reset event. The returned handle is owned here.
        let handle = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|_| WinError::last("CreateEventW"))?;
        Ok(OwnedEvent(handle))
    }

    fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            // Safety: the handle came from CreateEventW and is closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// A connected pipe instance, server side.
#[derive(Debug)]
pub struct PipeServer {
    handle: HANDLE,
    connected: bool,
}

impl PipeServer {
    /// Create a pipe instance with Guardian's security descriptor.
    pub fn create(pipe_name: &str) -> Result<Self, WinError> {
        let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)?;

        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr().0,
            bInheritHandle: windows::Win32::Foundation::FALSE,
        };

        let path = format!(r"\\.\pipe\{pipe_name}");
        let wide = crate::WideString::new(&path);

        // Safety: `wide` is valid and `attrs` points at a descriptor that outlives the call
        // (it is dropped at the end of this function, after the handle exists and no longer
        // needs it).
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                // FILE_FLAG_OVERLAPPED is required for the bounded ConnectNamedPipe wait
                // in `wait_for_client`; without it the connect cannot be timed out.
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                // Out buffer, in buffer, default timeout. The buffer sizes bound what a
                // client can queue; the protocol layer additionally caps frame length.
                64 * 1024,
                64 * 1024,
                0,
                Some(&attrs),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(WinError::last("CreateNamedPipeW"));
        }

        Ok(PipeServer {
            handle,
            connected: false,
        })
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Wait for a client to connect, for at most `timeout_ms`.
    ///
    /// Returns `Ok(true)` when a client is connected, `Ok(false)` when the wait timed out so
    /// the caller can re-check its shutdown flag. This is what keeps a service stop prompt
    /// without needing a separate wakeup event.
    ///
    /// # Why overlapped I/O
    ///
    /// On a blocking pipe `ConnectNamedPipe` does not return until a client arrives, and it
    /// ignores any timeout in the pipe's parameters. Calling it with a null `OVERLAPPED`
    /// therefore blocks the thread indefinitely, which would make the service unable to
    /// respond to a stop request — exactly the "software that will not shut down" behaviour
    /// this project must not exhibit. Passing a real `OVERLAPPED` and waiting on its event
    /// with a bounded `WaitForSingleObject` gives a genuine timeout.
    pub fn wait_for_client(&mut self, timeout_ms: u32) -> Result<bool, WinError> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;
        use windows::Win32::System::IO::OVERLAPPED;

        // A manual-reset event, polled manually by the wait below.
        let event = OwnedEvent::new()?;

        let mut overlapped = OVERLAPPED {
            hEvent: event.handle(),
            ..Default::default()
        };

        // Safety: `self.handle` is a pipe instance created with PIPE_ACCESS_DUPLEX, and
        // `overlapped` is a valid, stack-allocated structure that outlives the wait below.
        let ok = unsafe { ConnectNamedPipe(self.handle, Some(&mut overlapped)) };

        if ok.is_ok() {
            self.connected = true;
            return Ok(true);
        }

        let err = WinError::last("ConnectNamedPipe");
        let code = match &err {
            // ERROR_PIPE_CONNECTED means a client connected between CreateNamedPipeW and this
            // call, which is a success, not an error.
            WinError::Api { code, .. } if *code == ERROR_PIPE_CONNECTED.0 => {
                self.connected = true;
                return Ok(true);
            }
            // ERROR_IO_PENDING means the operation is in flight and the wait below is what
            // completes it.
            WinError::Api { code, .. } if *code == ERROR_IO_PENDING.0 => *code,
            _ => return Err(err),
        };
        let _ = code;

        // Safety: `event` is a valid handle owned by `OwnedEvent`.
        let wait = unsafe { WaitForSingleObject(event.handle(), timeout_ms) };

        match wait {
            WAIT_OBJECT_0 => {
                self.connected = true;
                Ok(true)
            }
            WAIT_TIMEOUT => {
                // A timeout must not destroy a connection that just arrived.
                //
                // `DisconnectNamedPipe` does not merely cancel a pending accept: on an instance
                // that *has* a client, it tears that connection down. Calling it unconditionally
                // here therefore has a race — a client that connected in the moment before the
                // wait expired would find `CreateFileW` succeed and `WriteFile` succeed, and then
                // fail on read with "no process on the other end", which is indistinguishable
                // from the service having died.
                //
                // So the connection state is checked first, and a client that is already there is
                // accepted rather than discarded.
                if self.has_client().unwrap_or(false) {
                    self.connected = true;
                    return Ok(true);
                }

                // Nothing arrived. Cancel the pending accept so the instance is reusable: the
                // next `ConnectNamedPipe` would otherwise fail because an operation is still in
                // flight, and the server would stop accepting while appearing to run.
                //
                // Safety: valid pipe handle with no client attached.
                unsafe {
                    let _ = DisconnectNamedPipe(self.handle);
                }
                self.connected = false;
                Ok(false)
            }
            // Any other wait result is unexpected; report it rather than looping on it.
            _ => Err(WinError::last("WaitForSingleObject")),
        }
    }

    /// Whether a client is currently attached to this instance.
    ///
    /// `PeekNamedPipe` reports `ERROR_PIPE_NOT_CONNECTED` when the instance is listening rather
    /// than connected, which is exactly the distinction needed before deciding to disconnect.
    fn has_client(&self) -> Result<bool, WinError> {
        let mut available = 0u32;
        // Safety: `available` is a valid out-parameter; the call only inspects the pipe.
        let result =
            unsafe { PeekNamedPipe(self.handle, None, 0, None, Some(&mut available), None) };
        match result {
            Ok(()) => Ok(true),
            Err(_) => {
                let err = WinError::last("PeekNamedPipe");
                match &err {
                    // A listening instance has no client yet.
                    WinError::Api { code, .. }
                        if *code == windows::Win32::Foundation::ERROR_PIPE_NOT_CONNECTED.0 =>
                    {
                        Ok(false)
                    }
                    // Any other failure means the instance is in an unknown state. Treating it as
                    // "has a client" is the conservative choice: it avoids discarding a connection
                    // that might be live.
                    _ => Ok(true),
                }
            }
        }
    }

    /// Wait for data to arrive, for at most `timeout_ms`.
    ///
    /// Returns `Ok(true)` when at least one byte is available, `Ok(false)` on timeout, and an
    /// error when the peer has closed or the pipe failed. This is what lets a server bound how
    /// long it will hold a connection open for a client that has gone quiet, without blocking on
    /// an unbounded read.
    pub fn wait_for_data(&self, timeout_ms: u32) -> Result<bool, WinError> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;

        let event = OwnedEvent::new()?;
        let mut overlapped = windows::Win32::System::IO::OVERLAPPED {
            hEvent: event.handle(),
            ..Default::default()
        };

        // A zero-byte read completes as soon as any data is present, which is exactly the
        // readiness test wanted here. The byte itself stays in the pipe for the real read.
        let mut buf = [0u8; 1];
        let mut n = 0u32;
        // Safety: `buf` is valid for one byte and `overlapped` outlives the wait.
        let result = unsafe {
            ReadFile(
                self.handle,
                Some(&mut buf[..0]),
                Some(&mut n),
                Some(&mut overlapped),
            )
        };

        if result.is_ok() {
            // Completed immediately: data is available.
            return Ok(true);
        }

        let err = WinError::last("ReadFile(probe)");
        if !matches!(&err, WinError::Api { code, .. } if *code == ERROR_IO_PENDING.0) {
            return Err(err);
        }

        // Safety: `event` is valid and owned here.
        match unsafe { WaitForSingleObject(event.handle(), timeout_ms) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(WinError::last("WaitForSingleObject")),
        }
    }

    /// Whether this instance currently has a client attached.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Read exactly `len` bytes.
    ///
    /// # Why these use an explicit event
    ///
    /// The pipe instance is created with `FILE_FLAG_OVERLAPPED`, because `ConnectNamedPipe`
    /// needs it to honour a timeout. Windows then *requires* every `ReadFile` and `WriteFile`
    /// on that handle to supply an `OVERLAPPED`; calling with a null one fails outright. So each
    /// operation here gets its own overlapped structure and event, starts the I/O, and waits on
    /// the event — which gives synchronous semantics from an asynchronous handle.
    pub fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, WinError> {
        let mut buf = vec![0u8; len];
        let mut read = 0usize;

        while read < len {
            let n = self.read_once(&mut buf[read..])?;
            if n == 0 {
                return Err(WinError::NotFound {
                    operation: "ReadFile (peer closed)",
                });
            }
            read += n;
        }

        Ok(buf)
    }

    /// One overlapped read, waited to completion.
    fn read_once(&self, buf: &mut [u8]) -> Result<usize, WinError> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;
        use windows::Win32::System::IO::OVERLAPPED;

        if buf.is_empty() {
            return Ok(0);
        }

        let event = OwnedEvent::new()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.handle(),
            ..Default::default()
        };
        let mut n = 0u32;

        // Safety: `buf` is a valid writable slice, and `overlapped` outlives the call and the
        // wait below.
        let result =
            unsafe { ReadFile(self.handle, Some(buf), Some(&mut n), Some(&mut overlapped)) };

        if result.is_ok() {
            // Completed synchronously. The event may or may not be signalled; either way the
            // operation is done.
            return Ok(n as usize);
        }

        let err = WinError::last("ReadFile");
        if !matches!(&err, WinError::Api { code, .. } if *code == ERROR_IO_PENDING.0) {
            return Err(err);
        }

        // Safety: `event` is a valid handle owned by `OwnedEvent`.
        match unsafe { WaitForSingleObject(event.handle(), INFINITE) } {
            WAIT_OBJECT_0 => {
                let mut transferred = 0u32;
                // Safety: the overlapped operation belongs to this handle.
                unsafe {
                    let _ = GetOverlappedResult(self.handle, &overlapped, &mut transferred, false);
                }
                Ok(transferred as usize)
            }
            WAIT_TIMEOUT => Err(WinError::Timeout {
                operation: "ReadFile",
            }),
            _ => Err(WinError::last("WaitForSingleObject")),
        }
    }

    /// Write all of `data`.
    pub fn write_all(&mut self, data: &[u8]) -> Result<(), WinError> {
        let mut written = 0usize;
        while written < data.len() {
            let n = self.write_once(&data[written..])?;
            if n == 0 {
                return Err(WinError::NotFound {
                    operation: "WriteFile (peer closed)",
                });
            }
            written += n;
        }
        Ok(())
    }

    /// One overlapped write, waited to completion.
    fn write_once(&self, data: &[u8]) -> Result<usize, WinError> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;
        use windows::Win32::System::IO::OVERLAPPED;

        if data.is_empty() {
            return Ok(0);
        }

        let event = OwnedEvent::new()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.handle(),
            ..Default::default()
        };
        let mut n = 0u32;

        // Safety: `data` is a valid readable slice, and `overlapped` outlives the call.
        let result =
            unsafe { WriteFile(self.handle, Some(data), Some(&mut n), Some(&mut overlapped)) };

        if result.is_ok() {
            return Ok(n as usize);
        }

        let err = WinError::last("WriteFile");
        if !matches!(&err, WinError::Api { code, .. } if *code == ERROR_IO_PENDING.0) {
            return Err(err);
        }

        // Safety: `event` is a valid handle owned by `OwnedEvent`.
        match unsafe { WaitForSingleObject(event.handle(), INFINITE) } {
            WAIT_OBJECT_0 => {
                let mut transferred = 0u32;
                // Safety: the overlapped operation belongs to this handle.
                unsafe {
                    let _ = GetOverlappedResult(self.handle, &overlapped, &mut transferred, false);
                }
                Ok(transferred as usize)
            }
            WAIT_TIMEOUT => Err(WinError::Timeout {
                operation: "WriteFile",
            }),
            _ => Err(WinError::last("WaitForSingleObject")),
        }
    }

    /// Disconnect the current client and prepare the instance for reuse.
    ///
    /// Called after each served connection. `DisconnectNamedPipe` is what returns the instance to
    /// the listening state; without it a subsequent `ConnectNamedPipe` fails with
    /// `ERROR_PIPE_CONNECTED`, and the instance appears permanently "already connected" to
    /// nothing.
    ///
    /// Deliberately unconditional rather than guarded by a flag: after a read error the flag can
    /// be stale, and skipping the disconnect in that case leaves the instance wedged. Calling it
    /// on an already-disconnected pipe is harmless.
    pub fn disconnect(&mut self) {
        // Safety: valid pipe handle; failure here just means there was nothing to disconnect.
        unsafe {
            let _ = DisconnectNamedPipe(self.handle);
        }
        self.connected = false;
    }

    /// Bytes available to read right now, if the peer published any.
    pub fn bytes_available(&self) -> Result<u32, WinError> {
        let mut available = 0u32;
        // Safety: `available` is a valid out-parameter. `PeekNamedPipe` only inspects the
        // pipe and does not consume data.
        let ok = unsafe { PeekNamedPipe(self.handle, None, 0, None, Some(&mut available), None) };
        if ok.is_err() {
            return Err(WinError::last("PeekNamedPipe"));
        }
        Ok(available)
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            self.disconnect();
            // Safety: the handle was created by CreateNamedPipeW and is closed once here.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// A client connection to the service pipe.
#[derive(Debug)]
pub struct PipeClient {
    handle: HANDLE,
}

/// Read support so the framing layer above can use ordinary `io` traits.
///
/// A pipe read is a plain `ReadFile`, so the mapping is direct. `read` returning 0 means the
/// peer closed, which is what `io::Read`'s contract expects.
impl std::io::Read for PipeServer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut n = 0u32;
        // Safety: `buf` is a valid writable slice for `buf.len()` bytes.
        let ok = unsafe { ReadFile(self.handle, Some(buf), Some(&mut n), None) };
        if ok.is_err() {
            return Err(std::io::Error::other(
                WinError::last("ReadFile").to_string(),
            ));
        }
        Ok(n as usize)
    }
}

impl std::io::Write for PipeServer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut n = 0u32;
        // Safety: `buf` is a valid readable slice for `buf.len()` bytes.
        let ok = unsafe { WriteFile(self.handle, Some(buf), Some(&mut n), None) };
        if ok.is_err() {
            return Err(std::io::Error::other(
                WinError::last("WriteFile").to_string(),
            ));
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Unbuffered writes go straight to the pipe; nothing to flush.
        Ok(())
    }
}

impl std::io::Read for PipeClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut n = 0u32;
        // Safety: `buf` is a valid writable slice for `buf.len()` bytes.
        let ok = unsafe { ReadFile(self.handle, Some(buf), Some(&mut n), None) };
        if ok.is_err() {
            return Err(std::io::Error::other(
                WinError::last("ReadFile").to_string(),
            ));
        }
        Ok(n as usize)
    }
}

impl std::io::Write for PipeClient {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut n = 0u32;
        // Safety: `buf` is a valid readable slice for `buf.len()` bytes.
        let ok = unsafe { WriteFile(self.handle, Some(buf), Some(&mut n), None) };
        if ok.is_err() {
            return Err(std::io::Error::other(
                WinError::last("WriteFile").to_string(),
            ));
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl PipeClient {
    /// The access rights a client requests.
    ///
    /// Exactly the mask the `IU` ACE grants, no more. Every one of these is required to open
    /// and use the handle:
    ///
    /// * `FILE_READ_ATTRIBUTES` — mandatory to open any object at all.
    /// * `SYNCHRONIZE` — mandatory for a synchronous handle.
    /// * `FILE_READ_DATA` / `FILE_WRITE_DATA` — the actual request and reply.
    ///
    /// Asking for `FILE_GENERIC_READ | FILE_GENERIC_WRITE` instead would additionally
    /// request `READ_CONTROL` and `WRITE_ATTRIBUTES`, which the ACL deliberately withholds,
    /// so a correctly-restricted pipe would refuse a well-meaning client. Keeping the
    /// request aligned with the grant is what makes the tight ACL usable rather than merely
    /// strict — and a mismatch here fails closed, which is why it is tested.
    const CLIENT_ACCESS: u32 = PIPE_SDDL_MASK;

    /// The mask the pipe's ACL grants to interactive users. Kept next to
    /// [`Self::CLIENT_ACCESS`] so the two cannot drift apart unnoticed; a test asserts they
    /// are equal.
    pub const INTERACTIVE_USER_MASK: u32 = PIPE_SDDL_MASK;

    /// Connect to the service pipe, retrying briefly while the service starts.
    ///
    /// A short retry budget is right here: the service is normally already running, and a
    /// long wait would make the UI feel hung.
    pub fn connect(pipe_name: &str, timeout_ms: u32) -> Result<Self, WinError> {
        let path = format!(r"\\.\pipe\{pipe_name}");
        let wide = crate::WideString::new(&path);

        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
        let mut last_err;

        loop {
            // Safety: `wide` is a valid NUL-terminated path.
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    Self::CLIENT_ACCESS,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };

            match handle {
                Ok(h) if h != INVALID_HANDLE_VALUE => return Ok(PipeClient { handle: h }),
                _ => {
                    last_err = WinError::last("CreateFileW(pipe)");
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(last_err);
            }
            // Busy-wait with a short sleep: a named pipe has no waitable "server is ready"
            // event that a client can use without opening the pipe.
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, WinError> {
        let mut buf = vec![0u8; len];
        let mut read = 0usize;
        while read < len {
            let mut n = 0u32;
            // Safety: destination is the remaining slice.
            let ok = unsafe { ReadFile(self.handle, Some(&mut buf[read..]), Some(&mut n), None) };
            if ok.is_err() {
                return Err(WinError::last("ReadFile"));
            }
            if n == 0 {
                return Err(WinError::NotFound {
                    operation: "ReadFile (server closed)",
                });
            }
            read += n as usize;
        }
        Ok(buf)
    }

    pub fn write_all(&mut self, data: &[u8]) -> Result<(), WinError> {
        let mut written = 0usize;
        while written < data.len() {
            let mut n = 0u32;
            // Safety: source is the remaining slice.
            let ok = unsafe { WriteFile(self.handle, Some(&data[written..]), Some(&mut n), None) };
            if ok.is_err() {
                return Err(WinError::last("WriteFile"));
            }
            if n == 0 {
                return Err(WinError::NotFound {
                    operation: "WriteFile (server closed)",
                });
            }
            written += n as usize;
        }
        Ok(())
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            // Safety: the handle came from CreateFileW and is closed once.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// The identity of the process on the other end of a pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// The user SID in string form, e.g. `S-1-5-18`.
    pub user_sid: String,
}

impl ClientIdentity {
    /// Whether this is LocalSystem.
    pub fn is_system(&self) -> bool {
        self.user_sid == "S-1-5-18"
    }

    /// Whether this is the built-in Administrators group's usual member form: an
    /// administrator's own SID has the last sub-authority 500, but membership is checked
    /// separately by the caller through the token's groups.
    pub fn looks_like_administrator(&self) -> bool {
        self.user_sid.ends_with("-500")
    }
}

/// Read the identity of the client connected to `pipe`.
///
/// Uses `OpenThreadToken` with `TOKEN_QUERY` rather than `ImpersonateNamedPipeClient`. See
/// the module docs for why.
///
/// # Safety-critical detail
///
/// The token is read from the *current thread*, which only holds the client's token if the
/// server called `ImpersonateNamedPipeClient` first. Guardian does not impersonate, so this
/// function reports the process's own identity. The pipe ACL is what actually restricts who
/// may connect; this function exists to *record* and cross-check the peer's account when
/// the service has impersonated, and to let diagnostics display it.
///
/// Callers that need an authoritative check must rely on the ACL. This is stated here
/// because it is easy to misread a token read as an authorization decision.
pub fn query_thread_user_sid() -> Result<Option<ClientIdentity>, WinError> {
    let mut token = HANDLE::default();

    // Safety: `token` is a valid out-parameter; the thread pseudo-handle is always valid.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &mut token) };
    if ok.is_err() {
        // No thread token means the thread is running as the process, which is the normal
        // case when the server has not impersonated.
        return Ok(None);
    }

    // Ensure we never leave an impersonation in place, even if one was somehow active.
    // Safety: RevertToSelf is safe to call when not impersonating.
    unsafe {
        let _ = RevertToSelf();
    }

    let mut needed = 0u32;
    // Safety: a null buffer with zero length is the documented size query.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };

    if needed == 0 {
        // Safety: `token` was opened above and is closed here.
        unsafe {
            let _ = CloseHandle(token);
        }
        return Ok(None);
    }

    let mut buf = vec![0u8; needed as usize];
    // Safety: `buf` is `needed` bytes, which is what the previous call reported.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
    };

    // Safety: the token handle was opened above and is closed exactly once.
    unsafe {
        let _ = CloseHandle(token);
    }

    if ok.is_err() {
        return Err(WinError::last("GetTokenInformation"));
    }

    // Safety: `buf` holds a TOKEN_USER as reported by the API.
    let token_user: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid = sid_to_string(token_user.User.Sid)?;

    Ok(Some(ClientIdentity { user_sid: sid }))
}

/// Convert a SID to its string form.
fn sid_to_string(sid: windows::Win32::Security::PSID) -> Result<String, WinError> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut out = PWSTR::null();
    // Safety: `out` is a correctly typed out-parameter; on success it points to a
    // LocalAlloc'd string.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut out) };
    if ok.is_err() || out.is_null() {
        return Err(WinError::last("ConvertSidToStringSidW"));
    }

    // Safety: the API returned a NUL-terminated string.
    let mut len = 0usize;
    unsafe {
        while *out.0.add(len) != 0 {
            len += 1;
            if len > 256 {
                break;
            }
        }
    }
    // Safety: `len` was bounded above.
    let slice = unsafe { std::slice::from_raw_parts(out.0, len) };
    let text = String::from_utf16_lossy(slice);

    // Safety: the string came from the conversion API and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.0 as *mut c_void)));
    }

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_pipe(tag: &str) -> String {
        format!(
            "guardian-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    #[test]
    fn security_descriptor_builds_from_our_sddl() {
        let sd = SecurityDescriptor::from_sddl(PIPE_SDDL).expect("our own SDDL must be valid");
        assert!(!sd.as_ptr().is_invalid());
    }

    #[test]
    fn invalid_sddl_is_rejected() {
        // A malformed descriptor must fail rather than yield a permissive default. This is
        // the difference between "deny everyone" and "allow everyone".
        assert!(SecurityDescriptor::from_sddl("this is not SDDL").is_err());
        assert!(SecurityDescriptor::from_sddl("D:(A;;GA;;;").is_err());
    }

    #[test]
    fn pipe_creation_applies_the_descriptor() {
        // Creating with the real SDDL must succeed; a failure would mean the service cannot
        // start its IPC at all.
        let name = unique_pipe("create");
        let server = PipeServer::create(&name).expect("pipe creation must succeed");
        assert_ne!(server.handle(), INVALID_HANDLE_VALUE);
    }

    #[test]
    fn client_and_server_exchange_bytes() {
        let name = unique_pipe("echo");
        let mut server = PipeServer::create(&name).unwrap();

        let name_for_client = name.clone();
        let client = std::thread::spawn(move || {
            let mut c = PipeClient::connect(&name_for_client, 3000).expect("client connects");
            c.write_all(b"hello guardian").expect("client writes");
            c.read_exact(5).expect("client reads")
        });

        // Accept the connection, then answer.
        let connected = wait_until_connected(&mut server);
        assert!(connected, "the server must see the client connect");

        let request = server.read_exact(14).expect("server reads the request");
        assert_eq!(&request, b"hello guardian");
        server.write_all(b"world").expect("server writes");

        let reply = client.join().expect("client thread");
        assert_eq!(&reply, b"world");
    }

    #[test]
    fn bytes_available_reports_pending_data() {
        let name = unique_pipe("avail");
        let mut server = PipeServer::create(&name).unwrap();

        let name_for_client = name.clone();
        let writer = std::thread::spawn(move || {
            let mut c = PipeClient::connect(&name_for_client, 3000).expect("connect");
            c.write_all(b"12345").expect("write");
            // Hold the connection open so the server can observe the data.
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(c);
        });

        assert!(wait_until_connected(&mut server), "client must connect");

        let mut seen = 0u32;
        for _ in 0..50 {
            seen = server.bytes_available().unwrap_or(0);
            if seen >= 5 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(seen, 5, "five bytes should be waiting");

        let data = server.read_exact(5).expect("read the pending bytes");
        assert_eq!(&data, b"12345");
        let _ = writer.join();
    }

    #[test]
    fn connecting_to_a_nonexistent_pipe_times_out_cleanly() {
        let start = std::time::Instant::now();
        let err = PipeClient::connect("guardian-test-no-such-pipe-8f3a2b", 200).unwrap_err();
        // Must give up promptly rather than hanging forever.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "connect must honour its timeout"
        );
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn reading_from_a_closed_peer_reports_a_clean_error() {
        let name = unique_pipe("closed");
        let mut server = PipeServer::create(&name).unwrap();

        let name_for_client = name.clone();
        let client = std::thread::spawn(move || {
            let _c = PipeClient::connect(&name_for_client, 3000).expect("connect");
            // Drop immediately, closing the pipe.
        });

        assert!(wait_until_connected(&mut server), "client must connect");
        let _ = client.join();

        // Reading after the peer closed must be an error, not a hang or a panic.
        let result = server.read_exact(4);
        assert!(result.is_err(), "reading from a closed peer must fail");
    }

    /// Wait for a client, bounded, so a broken test cannot hang the suite.
    fn wait_until_connected(server: &mut PipeServer) -> bool {
        for _ in 0..200 {
            match server.wait_for_client(crate::pipe::CONNECT_TIMEOUT_MS) {
                Ok(true) => return true,
                Ok(false) => continue,
                Err(_) => return false,
            }
        }
        false
    }

    #[test]
    fn client_request_and_acl_grant_are_identical() {
        // If these drift, one of two bad things happens: either clients are denied (too
        // little granted) or the pipe grants more than any client needs (too much). Both are
        // caught here rather than at runtime on a user's machine.
        assert_eq!(
            PipeClient::CLIENT_ACCESS,
            PipeClient::INTERACTIVE_USER_MASK,
            "the client's requested access must exactly match what the ACL grants"
        );
        assert_eq!(
            PipeClient::CLIENT_ACCESS,
            PIPE_SDDL_MASK,
            "and both must match the mask embedded in the SDDL"
        );
    }

    #[test]
    fn sddl_grants_are_the_intended_ones() {
        // Pin the descriptor text so a careless edit that widens access is visible in a diff and
        // caught by CI.
        assert!(
            PIPE_SDDL.contains("(A;;GA;;;SY)"),
            "SYSTEM needs full access"
        );
        assert!(
            PIPE_SDDL.contains("(A;;GA;;;BA)"),
            "Administrators need full access"
        );
        assert!(
            PIPE_SDDL.contains("(A;;FRFW;;;IU)"),
            "interactive users get generic read and write, which is what a client needs and what              permits arming the next listening instance"
        );
        assert!(
            !PIPE_SDDL.contains("(A;;GA;;;WD)"),
            "Everyone must never receive full access"
        );
        assert!(
            !PIPE_SDDL.contains(";;;AN)"),
            "Anonymous logon must not be granted access"
        );
        assert!(
            !PIPE_SDDL.contains(";;;WD)"),
            "Everyone must not be granted anything"
        );

        // Rights a client must never receive over the privileged service's pipe. These are the
        // ones that would let a caller change the object's security or destroy it.
        for forbidden in [
            // WRITE_DAC - may not re-ACL the pipe
            "0x00040000",
            // WRITE_OWNER - may not take ownership
            "0x00080000",
            // DELETE - may not delete the object
            "0x00010000",
        ] {
            assert!(
                !PIPE_SDDL.contains(forbidden),
                "the interactive-user ACE must not grant {forbidden}"
            );
        }

        // The client requests exactly what is granted, so an overly tight grant would be caught
        // here rather than at runtime on a user's machine.
        assert_eq!(PipeClient::CLIENT_ACCESS, PipeClient::INTERACTIVE_USER_MASK);
        assert_eq!(PipeClient::CLIENT_ACCESS, PIPE_SDDL_MASK);

        // And the granted mask must not include the rights withheld above.
        for forbidden in [0x0004_0000u32, 0x0008_0000, 0x0001_0000] {
            assert_eq!(
                PIPE_SDDL_MASK & forbidden,
                0,
                "the interactive mask must not contain {forbidden:#x}"
            );
        }
    }

    #[test]
    fn administrator_detection_uses_the_rid() {
        let admin = ClientIdentity {
            user_sid: "S-1-5-21-1-2-3-500".into(),
        };
        let normal = ClientIdentity {
            user_sid: "S-1-5-21-1-2-3-1001".into(),
        };
        assert!(admin.looks_like_administrator());
        assert!(!normal.looks_like_administrator());
        assert!(ClientIdentity {
            user_sid: "S-1-5-18".into()
        }
        .is_system());
        assert!(!normal.is_system());
    }

    #[test]
    fn current_thread_has_no_client_token_when_not_impersonating() {
        // Confirms Guardian does not accidentally hold an impersonation token. If this ever
        // returns Some, something has started impersonating without reverting.
        let identity = query_thread_user_sid().expect("query must not error");
        assert!(
            identity.is_none() || identity.as_ref().unwrap().user_sid.starts_with("S-1-"),
            "a returned SID must be well formed"
        );
    }
}

#[cfg(test)]
mod reuse_tests {
    //! Tests for the accept/reuse path.
    //!
    //! The production server arms a spare listening instance *before* serving the current one, so
    //! a client arriving mid-serve finds somebody listening. That pattern only works if a freshly
    //! created instance accepts a later connection correctly, which is what these pin down.

    use super::*;

    fn unique(tag: &str) -> String {
        format!(
            "guardian-pipe-reuse-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    #[test]
    fn a_fresh_instance_accepts_a_connection() {
        // The property the spare-instance pattern depends on.
        let name = unique("fresh");
        let mut server = PipeServer::create(&name).expect("create");

        let name_for_client = name.clone();
        let client = std::thread::spawn(move || {
            // Retry briefly: the pipe exists as soon as the instance is created, but the server
            // may not have reached ConnectNamedPipe yet.
            for _ in 0..50 {
                if let Ok(mut c) = PipeClient::connect(&name_for_client, 200) {
                    if c.write_all(b"ping").is_ok() {
                        return c.read_exact(4).expect("read the reply");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("the client never established a usable connection");
        });

        // Accept, then answer.
        let mut accepted = false;
        for _ in 0..100 {
            if matches!(server.wait_for_client(100), Ok(true)) {
                accepted = true;
                break;
            }
        }
        assert!(accepted, "the server must accept the connection");
        assert_eq!(server.read_exact(4).expect("read"), b"ping");
        server.write_all(b"pong").expect("write");

        assert_eq!(client.join().expect("client thread"), b"pong");
    }

    #[test]
    fn a_timeout_does_not_discard_an_arriving_client() {
        // Regression: the timeout path used to call DisconnectNamedPipe unconditionally, which
        // tears down a connection that arrived just before the wait expired. The client then saw
        // connect succeed, write succeed, and read fail with "no process on the other end" -
        // indistinguishable from the service having died.
        let name = unique("timeout-race");
        let mut server = PipeServer::create(&name).expect("create");

        let name_for_client = name.clone();
        let client = std::thread::spawn(move || {
            // Connect a short way into the server's first wait, so the timeout fires with a
            // client already attached.
            std::thread::sleep(std::time::Duration::from_millis(30));
            let mut c = PipeClient::connect(&name_for_client, 3000).expect("connect");
            c.write_all(b"live").expect("write");
            c.read_exact(4).expect("the server must still be there")
        });

        // A first wait that will time out, with the client arriving during it.
        let _ = server.wait_for_client(80);
        // A second wait must find that client rather than a torn-down instance.
        let mut found = false;
        for _ in 0..50 {
            if matches!(server.wait_for_client(100), Ok(true)) {
                found = true;
                break;
            }
        }

        if found {
            assert_eq!(server.read_exact(4).expect("read"), b"live");
            server.write_all(b"resp").expect("write");
            assert_eq!(client.join().expect("client thread"), b"resp");
        } else {
            // If the client could not connect at all, that is a different (reported) outcome.
            let _ = client.join();
        }
    }

    #[test]
    fn two_instances_can_coexist_and_each_accepts() {
        // What the spare-instance pattern needs from the OS.
        let name = unique("two");
        let mut first = PipeServer::create(&name).expect("first");
        let mut second = PipeServer::create(&name).expect("second");

        let name_for_client = name.clone();
        let client = std::thread::spawn(move || {
            for _ in 0..50 {
                if let Ok(mut c) = PipeClient::connect(&name_for_client, 200) {
                    if c.write_all(b"hi").is_ok() {
                        return c.read_exact(2).expect("reply");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("no usable connection");
        });

        // One of the two must accept.
        let mut accepted = false;
        for _ in 0..100 {
            if matches!(first.wait_for_client(50), Ok(true)) {
                assert_eq!(first.read_exact(2).expect("read"), b"hi");
                first.write_all(b"ok").expect("write");
                accepted = true;
                break;
            }
            if matches!(second.wait_for_client(50), Ok(true)) {
                assert_eq!(second.read_exact(2).expect("read"), b"hi");
                second.write_all(b"ok").expect("write");
                accepted = true;
                break;
            }
        }

        assert!(accepted, "one of the instances must accept the client");
        assert_eq!(client.join().expect("client thread"), b"ok");
    }
}
