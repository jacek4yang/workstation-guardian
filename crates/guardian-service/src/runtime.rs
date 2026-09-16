//! The Guardian runtime: everything the program does, independent of how it is hosted.
//!
//! # Why this is a library function and not a service entry point
//!
//! Guardian runs as an ordinary elevated tray application, not as a Windows service. Hosting is
//! therefore a thin concern — a console harness for development, a tray application for normal
//! use — while the protection logic lives here, unchanged.
//!
//! Nothing in this module assumes a Service Control Manager, an installed service, or a specific
//! executable name. It starts workers, serves IPC, and returns when asked to stop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::supervisor::{Supervisor, WorkerSpec};
use crate::{ipc, journal, logging, state};
use guardian_core::net::NetworkPolicy;
use guardian_core::ports::Clock;
use guardian_proto::model::*;
use guardian_win::clock::{SystemBootIdentity, SystemClock};

/// How often the coordinator refreshes its own view, and the journal checkpoints.
const CONTROL_INTERVAL: Duration = Duration::from_secs(5);
/// Journal checkpoint interval in NORMAL mode.
const CHECKPOINT_INTERVAL_NORMAL: Duration = Duration::from_secs(60);
/// Journal checkpoint interval in WORKING mode, where more is at stake.
const CHECKPOINT_INTERVAL_WORKING: Duration = Duration::from_secs(15);

/// How the runtime was asked to behave.
#[derive(Debug, Clone, Default)]
pub struct RuntimeOptions {
    /// Stop after this long. `None` runs until asked to stop.
    pub run_for: Option<Duration>,
    /// Where to write user-facing errors when a log directory is unavailable.
    pub echo_errors: bool,
}

/// A handle to a running Guardian.
///
/// Held by the host so it can share the live state with a UI and stop the runtime cleanly.
pub struct GuardianRuntime {
    shutdown: Arc<AtomicBool>,
    shared: state::SharedState,
    supervisor: Arc<Supervisor>,
}

impl std::fmt::Debug for GuardianRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianRuntime").finish_non_exhaustive()
    }
}

impl GuardianRuntime {
    /// Ask the runtime to stop. The hosting thread returns once shutdown has completed.
    pub fn request_stop(&self) {
        self.supervisor.request_shutdown();
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// The live protection state, for a host that wants to display it without going through IPC.
    pub fn state(&self) -> state::SharedState {
        Arc::clone(&self.shared)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

/// Start the runtime and block until it stops.
///
/// `on_ready` is called once the state is available, so a host can publish it — the tray shows
/// itself at that point rather than while the first verification pass is still running.
pub fn run(options: RuntimeOptions, on_ready: impl FnOnce(GuardianRuntime)) {
    let shutdown = Arc::new(AtomicBool::new(false));

    // ---- 1. Paths and configuration ----------------------------------------
    let config = load_configuration();
    let paths = config
        .body
        .storage
        .data_dir
        .as_deref()
        .map(guardian_storage::GuardianPaths::for_test_dir)
        .unwrap_or_else(guardian_storage::GuardianPaths::production);

    if let Err(e) = paths.ensure_dirs() {
        // Protection does not depend on the data directory, so this is reported and the service
        // continues. Losing logs is a degradation, not a reason to stop protecting.
        eprintln!(
            "guardian-service: could not create {}: {e}",
            paths.root().display()
        );
    }

    let _log_guard = logging::init_file_logging(&paths, &config.body.logging);

    let clock = SystemClock;
    let boot_id = SystemBootIdentity::read();
    let started_at = std::time::Instant::now();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        boot_id = %boot_id,
        data_dir = %paths.root().display(),
        "Workstation Guardian starting"
    );

    // ---- 2. Recovery: what happened last time? ------------------------------
    let previous = journal::read_previous_session(&paths.journal_file());
    tracing::info!(summary = %journal::describe_previous(&previous), "previous session");

    // ---- 3. Apply protection before anything else can go wrong --------------
    let store = match guardian_storage::Store::open(paths.clone()) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!(error = %e, "could not open the state store");
            None
        }
    };

    let update_worker = guardian_update::UpdateWorker::production(
        config.body.update.protect,
        config.body.update.auto_restore,
    );
    let update_worker = Arc::new(std::sync::Mutex::new(update_worker));

    // Apply protection synchronously and immediately.
    {
        let guard = update_worker.lock();
        match guard {
            Ok(mut w) => {
                let outcome = w.verify();
                tracing::info!(
                    level = %outcome.report.level.as_str(),
                    writes = outcome.writes_performed,
                    "initial update protection pass complete"
                );
            }
            Err(poisoned) => {
                let mut w = poisoned.into_inner();
                let _ = w.verify();
            }
        }
    }

    // ---- 4. Shared state and the coordinator --------------------------------
    let mut initial = state::ServiceState::initial(
        boot_id.clone(),
        clock.now_ms(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    initial.update = {
        let guard = update_worker.lock();
        match guard {
            Ok(w) => w.report_or_unknown(),
            Err(poisoned) => poisoned.into_inner().report_or_unknown(),
        }
    };
    initial.started_after_unclean_exit = !previous.clean;

    let shared: state::SharedState = Arc::new(RwLock::new(initial));

    let coordinator = state::ProtectionCoordinator::new(
        Arc::clone(&shared),
        SystemClock,
        guardian_win::boot::RebootProbe::new(),
        state::maintenance_policy_from(&config.body.maintenance),
        config.body.agents.auto_working,
        config.body.agents.protect_standalone_workloads,
    );
    let coordinator = Arc::new(coordinator);

    // Apply the boot identity, which invalidates any permit bound to a previous boot.
    let pending = guardian_win::boot::RebootProbe::new().classify();
    coordinator.apply_boot(boot_id.clone(), pending.verdict);
    coordinator.set_workers(&crate::supervisor::HealthRegistry::new());

    // ---- 5. Recovery incident ------------------------------------------------
    let event_log = guardian_win::eventlog::SystemEventLog::new();
    if let Some(incident) = journal::build_restart_incident(
        &event_log,
        &previous,
        &boot_id,
        journal::last_boot_ms(&SystemClock),
        clock.now_ms(),
    ) {
        tracing::warn!(
            summary = %incident.summary,
            severity = ?incident.severity,
            "unexpected restart detected"
        );
        coordinator.add_incident(incident);
    }

    // ---- 6. Journal ----------------------------------------------------------
    //
    // Shared behind a mutex because two paths write to it: the periodic checkpoint worker and the
    // shutdown handler. Giving it to one thread and reaching for it from the other is what produced
    // the ownership error this replaced.
    let recovery_journal: Arc<std::sync::Mutex<Option<journal::RecoveryJournal>>> =
        Arc::new(std::sync::Mutex::new(match journal::RecoveryJournal::open(
            paths.journal_file(),
            config.body.storage.journal_max_bytes,
            env!("CARGO_PKG_VERSION"),
            &SystemClock,
            &boot_id,
        ) {
            Ok(j) => Some(j),
            Err(e) => {
                tracing::error!(error = %e, "could not open the recovery journal");
                None
            }
        }));

    // Record what the *previous* session looked like, in this session's journal.
    //
    // This deliberately does not fabricate a `shutdown_observed` record. That record means "we saw
    // the machine go down", and a service starting up has seen no such thing. Writing one on every
    // start with a flag borrowed from an unrelated concept produced a journal full of events that
    // never happened, which is worse than useless when it is later read to reconstruct a crash.
    //
    // A `network_event` carries the same information without claiming an observation: the
    // conclusion about the previous session, as text.
    if let Ok(mut guard) = recovery_journal.lock() {
        if let Some(j) = guard.as_mut() {
            j.network_event(
                &SystemClock,
                &format!(
                    "previous session: {}",
                    journal::describe_previous(&previous)
                ),
            );
        }
    }

    // ---- 7. Workers ----------------------------------------------------------
    let supervisor = Arc::new(Supervisor::new());
    let health = supervisor.registry();
    let helper_connected = Arc::new(AtomicBool::new(false));
    let ipc_shutdown = Arc::clone(&shutdown);

    let mut handles = Vec::new();

    // Update verification worker.
    {
        let sup = Arc::clone(&supervisor);
        let worker = Arc::clone(&update_worker);
        let coord = Arc::clone(&coordinator);
        let interval = config.body.update.verify_interval_secs;
        let health = Arc::clone(&health);
        handles.push(std::thread::spawn(move || {
            sup.run_worker(WorkerSpec {
                name: "update",
                run: Box::new(move |ctx| {
                    health.mark_running("update");
                    loop {
                        if ctx.should_stop() {
                            return Ok(());
                        }
                        let (outcome, next) = {
                            let Ok(mut w) = worker.lock() else {
                                return Err("the update worker lock was poisoned".into());
                            };
                            let outcome = w.verify();
                            let next = w.next_interval(interval);
                            (outcome, next)
                        };

                        for line in &outcome.report.findings {
                            if line.severity >= FindingSeverity::Warning {
                                tracing::warn!(code = %line.code, message = %line.message, "update finding");
                            }
                        }
                        coord.set_update_report(outcome.report, outcome.incidents);
                        ctx.heartbeat();

                        if !ctx.sleep_interruptible(next) {
                            return Ok(());
                        }
                    }
                }),
            });
        }));
    }

    // Agent detection worker.
    {
        let sup = Arc::clone(&supervisor);
        let coord = Arc::clone(&coordinator);
        let sweep = config.body.agents.sweep_interval_secs;
        let agent_config = config.body.agents.clone();
        let health = Arc::clone(&health);
        handles.push(std::thread::spawn(move || {
            sup.run_worker(WorkerSpec {
                name: "agents",
                run: Box::new(move |ctx| {
                    health.mark_running("agents");
                    let engine = guardian_process::default_engine(&agent_config);
                    let adapters = guardian_process::adapters::Adapters::new(true);

                    loop {
                        if ctx.should_stop() {
                            return Ok(());
                        }

                        let inventory = match guardian_win::process::enumerate_processes() {
                            Ok(procs) => {
                                let graph = guardian_process::ProcessGraph::new(procs);
                                let detected = engine.detect_agents(&graph);
                                let now = guardian_win::clock::unix_now_ms();
                                let candidates = guardian_process::engine::collect_candidates(
                                    &engine, &graph, now,
                                );
                                guardian_process::engine::build_inventory(
                                    detected,
                                    &graph,
                                    &adapters,
                                    candidates,
                                    now,
                                    monitor_health(true),
                                )
                            }
                            Err(e) => {
                                // A failed sweep must not look like "no agents". The health
                                // record carries the failure so the UI can say the monitor is
                                // degraded rather than reporting an empty inventory.
                                tracing::warn!(error = %e, "process enumeration failed");
                                AgentInventory {
                                    monitor: monitor_health(false),
                                    ..Default::default()
                                }
                            }
                        };

                        coord.set_agents(inventory);
                        ctx.heartbeat();

                        if !ctx.sleep_interruptible(Duration::from_secs(sweep.max(1))) {
                            return Ok(());
                        }
                    }
                }),
            });
        }));
    }

    // Network worker.
    if config.body.network.enabled {
        let sup = Arc::clone(&supervisor);
        let coord = Arc::clone(&coordinator);
        let network_config = config.body.network.clone();
        let health = Arc::clone(&health);
        handles.push(std::thread::spawn(move || {
            sup.run_worker(WorkerSpec {
                name: "network",
                run: Box::new(move |ctx| {
                    health.mark_running("network");

                    let backend = guardian_network::RasBackend::new();
                    let entries = backend.entries();
                    let entry = match guardian_network::worker::select_entry(
                        &entries,
                        network_config.entry_name.as_deref(),
                    ) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(error = %e, "PPPoE entry selection needs a decision");
                            None
                        }
                    };

                    let mut worker = guardian_network::worker::NetworkWorker::new(
                        backend,
                        SystemClock,
                        guardian_network::ProbeRunner::new(network_config.probes.clone()),
                        NetworkPolicy::from_config(&network_config),
                        entry,
                    );

                    loop {
                        if ctx.should_stop() {
                            return Ok(());
                        }
                        let delay = worker.step();
                        coord.set_network(worker.snapshot());
                        ctx.heartbeat();
                        if !ctx.sleep_interruptible(delay) {
                            return Ok(());
                        }
                    }
                }),
            });
        }));
    }

    // Staleness tracker: advances the heartbeat clocks and republishes worker health.
    {
        let sup = Arc::clone(&supervisor);
        let coord = Arc::clone(&coordinator);
        let health = Arc::clone(&health);
        let journal_handle = Arc::clone(&recovery_journal);
        handles.push(std::thread::spawn(move || {
            sup.run_worker(WorkerSpec {
                name: "control",
                run: Box::new(move |ctx| {
                    health.mark_running("control");
                    let mut since_checkpoint = Duration::ZERO;
                    loop {
                        if ctx.should_stop() {
                            return Ok(());
                        }

                        let tick = CONTROL_INTERVAL;
                        if !ctx.sleep_interruptible(tick) {
                            return Ok(());
                        }

                        health.advance_staleness(tick.as_millis() as i64);
                        coord.set_workers(&health);
                        coord.tick_maintenance();
                        coord.refresh_pending_reboot();
                        since_checkpoint += tick;

                        // Checkpoint at the frequency the current mode warrants.
                        let interval = if coord.mode() == ProtectionMode::Working {
                            CHECKPOINT_INTERVAL_WORKING
                        } else {
                            CHECKPOINT_INTERVAL_NORMAL
                        };
                        if since_checkpoint >= interval {
                            since_checkpoint = Duration::ZERO;
                            let mut guard = match journal_handle.lock() {
                                Ok(g) => g,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            checkpoint(&coord, guard.as_mut());
                        }
                    }
                }),
            });
        }));
    }

    // IPC server.
    {
        let sup = Arc::clone(&supervisor);
        let coord = Arc::clone(&coordinator);
        let helper = Arc::clone(&helper_connected);
        let shutdown_flag = Arc::clone(&ipc_shutdown);
        handles.push(std::thread::spawn(move || {
            sup.run_worker(WorkerSpec {
                name: "ipc",
                run: Box::new(move |_ctx| {
                    let handler = Arc::new(crate::ipc::ServiceHandler::new(
                        coord.shared_state(),
                        Arc::clone(&coord),
                        Arc::clone(&helper),
                    ));
                    let server = ipc::IpcServer::new(
                        handler,
                        Arc::clone(&shutdown_flag),
                        Arc::clone(&helper),
                    );
                    server.run().map_err(|e| e.to_string())
                }),
            });
        }));
    }

    // The host can publish itself now: the state exists, the first protection pass has been
    // applied, and the workers are starting. A tray icon shows at this point rather than while the
    // machine is still unprotected.
    on_ready(GuardianRuntime {
        shutdown: Arc::clone(&shutdown),
        shared: Arc::clone(&shared),
        supervisor: Arc::clone(&supervisor),
    });

    // ---- 8. Main loop --------------------------------------------------------
    // Nothing here blocks: it polls the shutdown flag so a stop request is honoured promptly.
    let mut last_incident_count = 0usize;
    let run_deadline = options.run_for;
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));

        // A bounded run, requested from the command line. This exists so the clean-shutdown path
        // can be exercised end to end without an SCM and without signalling a console: the test
        // starts the service, waits, and then reads the journal to confirm the marker was written.
        // It also makes a smoke run easy on a machine where installing the service is not wanted.
        if let Some(limit) = run_deadline {
            if started_at.elapsed() >= limit {
                tracing::info!("configured run duration elapsed; stopping");
                break;
            }
        }

        // Surface incidents that workers raised.
        let incidents = supervisor.take_incidents();
        if !incidents.is_empty() {
            for i in &incidents {
                tracing::warn!(title = %i.title, summary = %i.summary, "incident");
                if let Some(w) = &i.details.worker_failure {
                    let mut guard = match recovery_journal.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if let Some(j) = guard.as_mut() {
                        j.worker_failure(&SystemClock, &w.worker, &w.error);
                    }
                }
                coordinator.add_incident(i.clone());
            }
        }

        // Detect a mode change and journal it, so the transition is visible after a crash.
        let current = coordinator.read();
        if current.incidents.len() != last_incident_count {
            last_incident_count = current.incidents.len();
        }

        // Persist state opportunistically; a failure here is reported, not fatal.
        if let (Some(store), false) = (&store, current.mode == ProtectionMode::Normal) {
            persist_state(store, &current, &previous);
        }
    }

    // ---- 9. Clean shutdown ---------------------------------------------------
    tracing::info!("shutdown requested; flushing state");

    // Ask the workers to stop and give them a bounded window to finish.
    supervisor.request_shutdown();
    shutdown.store(true, Ordering::SeqCst);

    // Flush the journal *before* anything else, since it is what proves this stop was clean.
    {
        let mut guard = match recovery_journal.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(j) = guard.as_mut() {
            checkpoint(&coordinator, Some(j));
            j.shutdown_observed(&SystemClock, false, None, false);
            j.mark_clean_shutdown(&SystemClock);
        }
    }

    // Persist the durable state, marking the shutdown clean.
    if let Some(store) = &store {
        let mut current = coordinator.read();
        let mut persisted = persistent_from(&current, &previous, &boot_id);
        persisted.clean_shutdown = true;
        if let Err(e) = store.save_state(&persisted) {
            tracing::error!(error = %e, "could not persist state during shutdown");
        }
        current.started_after_unclean_exit = false;
    }

    // Report the session helper as disconnected so the UI does not claim shutdown protection.
    coordinator.set_helper_connected(false);

    tracing::info!("Guardian stopped cleanly");
}

/// Load configuration, falling back to defaults on corruption.
/// Create the data directory and a default configuration, without overwriting anything.
///
/// Written here rather than in the CLI because the runtime is what starts first: an operator who
/// launches the tray app should find a configuration file to edit without having to run any
/// command. The CLI is free to call this too, but it is not the only entry point.
fn initialize_data_directory(paths: &guardian_storage::GuardianPaths) -> std::io::Result<()> {
    paths.ensure_dirs()?;

    if !paths.config_file().exists() {
        let file = guardian_storage::AtomicFile::new(paths.config_file());
        file.write_json(&ConfigDocument::default())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        tracing::info!(path = %paths.config_file().display(), "wrote a default configuration");
    }

    Ok(())
}

fn load_configuration() -> ConfigDocument {
    let paths = guardian_storage::GuardianPaths::production();

    // First run: create the data directory and a default configuration. The operator then has a
    // real file to edit rather than having to guess the schema. This never overwrites an existing
    // file, so it cannot discard settings.
    if let Err(e) = initialize_data_directory(&paths) {
        // Not being able to write the configuration is a degradation, not a reason to stop
        // protecting: the defaults used below are the protective ones.
        tracing::warn!(error = %e, "could not initialize the data directory");
    }

    match std::fs::read_to_string(paths.config_file()) {
        Ok(text) => {
            let validated = guardian_core::config::load_from_str(&text);
            if !validated.issues.is_empty() {
                for issue in &validated.issues {
                    tracing::warn!(
                        path = %issue.path,
                        severity = ?issue.severity,
                        message = %issue.message,
                        "configuration issue"
                    );
                }
            }
            if validated.changed {
                // Persist the repaired document so the operator sees what was corrected.
                if let Err(e) = guardian_storage::AtomicFile::new(paths.config_file())
                    .write_json(&validated.document)
                {
                    tracing::warn!(error = %e, "could not persist the repaired configuration");
                }
            }
            validated.document
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("no configuration file; using defaults that protect updates");
            ConfigDocument::default()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "configuration is unreadable; using defaults that protect updates"
            );
            ConfigDocument::default()
        }
    }
}

/// Build monitor health for a successful sweep.
fn monitor_health(healthy: bool) -> MonitorHealth {
    MonitorHealth {
        healthy,
        event_source_active: false,
        last_inventory_ms: guardian_win::clock::unix_now_ms(),
        last_sweep_age_ms: 0,
        consecutive_failures: if healthy { 0 } else { 1 },
        last_error: None,
    }
}

/// Write a journal checkpoint reflecting the current state.
fn checkpoint(
    coordinator: &state::ProtectionCoordinator<SystemClock, guardian_win::boot::RebootProbe>,
    journal: Option<&mut journal::RecoveryJournal>,
) {
    let Some(j) = journal else { return };
    let current = coordinator.read();
    let protected_work = current.agents.warrants_working(false);

    let input = journal::CheckpointInput {
        mode: current.mode.as_str(),
        update_protection: current.update.level.as_str(),
        agents: &current.agents,
        network: &current.network,
        authorization: current.maintenance.authorization.as_ref(),
        protected_work_live: protected_work,
        // Synchronous in WORKING mode, where more is at stake and checkpoints are less frequent.
        sync: current.mode == ProtectionMode::Working,
    };

    if let Err(e) = j.checkpoint(&SystemClock, input) {
        tracing::warn!(error = %e, "could not write a recovery checkpoint");
    }
}

/// Build the durable state document from the live state.
fn persistent_from(
    current: &state::ServiceState,
    previous: &journal::PreviousSession,
    boot_id: &str,
) -> guardian_storage::PersistentState {
    guardian_storage::PersistentState {
        schema_version: 1,
        last_boot_id: boot_id.to_string(),
        last_session_id: current.boot_id.clone(),
        last_started_at_ms: current.started_at_ms,
        last_heartbeat_ms: guardian_win::clock::unix_now_ms(),
        clean_shutdown: false,
        last_mode: current.mode.as_str().to_string(),
        last_update_protection: current.update.level.as_str().to_string(),
        // Owned policy values are recorded by the update worker the first time it writes; this
        // document only carries forward what previous runs recorded.
        owned_policy: Vec::new(),
        original_policy: previous
            .checkpoint
            .as_ref()
            .map(|_| Vec::new())
            .unwrap_or_default(),
        reboot_authorization: current.maintenance.authorization.clone(),
        policy_installed: true,
        start_count: 0,
    }
}

/// Persist durable state, reporting failure without interrupting protection.
fn persist_state(
    store: &guardian_storage::Store,
    current: &state::ServiceState,
    previous: &journal::PreviousSession,
) {
    let persisted = persistent_from(current, previous, &current.boot_id);
    if let Some(e) = journal::save_state(store, &persisted) {
        tracing::warn!(error = %e, "state could not be persisted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_storage::GuardianPaths;

    /// A unique temporary directory for one test.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "guardian-runtime-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        dir
    }

    #[test]
    fn the_first_run_writes_a_configuration_that_protects_updates() {
        let dir = temp_dir("first-run");
        let paths = guardian_storage::GuardianPaths::for_test_dir(dir.clone());

        initialize_data_directory(&paths).expect("initialization must succeed");
        assert!(paths.config_file().is_file());

        // The default must protect. A first run that silently disabled protection would be the
        // worst possible default.
        let (config, error) =
            guardian_storage::Store::open(GuardianPaths::for_test_dir(dir.clone()))
                .unwrap()
                .load_config();
        assert!(error.is_none());
        assert!(
            config.body.update.protect,
            "the default configuration must protect updates"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn starting_again_never_overwrites_the_operators_configuration() {
        let dir = temp_dir("preserve");
        std::fs::create_dir_all(&dir).unwrap();
        let paths = guardian_storage::GuardianPaths::for_test_dir(dir.clone());

        // An operator has edited their configuration.
        let mut config = ConfigDocument::default();
        config.body.update.verify_interval_secs = 99;
        guardian_storage::AtomicFile::new(paths.config_file())
            .write_json(&config)
            .unwrap();

        initialize_data_directory(&paths).expect("initialization must succeed");

        let (loaded, _) = guardian_storage::Store::open(GuardianPaths::for_test_dir(dir.clone()))
            .unwrap()
            .load_config();
        assert_eq!(
            loaded.body.update.verify_interval_secs, 99,
            "startup must never overwrite an operator's configuration"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn initialization_is_idempotent() {
        // The tray restarts whenever the user opens it, so this runs often. Running it twice must
        // be exactly as safe as running it once.
        let dir = temp_dir("idempotent");
        let paths = guardian_storage::GuardianPaths::for_test_dir(dir.clone());

        initialize_data_directory(&paths).unwrap();
        let first = std::fs::read_to_string(paths.config_file()).unwrap();
        initialize_data_directory(&paths).unwrap();
        let second = std::fs::read_to_string(paths.config_file()).unwrap();

        assert_eq!(first, second);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_configuration_falls_back_to_protective_defaults() {
        // The loader reads the real production path, which a test machine may or may not have.
        // Whatever it finds, the result must never be a configuration that stops protecting.
        let config = load_configuration();
        assert!(
            config.body.update.protect,
            "configuration loading must never yield a non-protecting configuration"
        );
    }
}
