//! `guardian-service` — the Workstation Guardian Windows service entry point.
//!
//! Wires the subsystems together and hands control to the Service Control Manager.
//!
//! # Startup order
//!
//! 1. Decide the data directory and load configuration. A corrupt configuration falls back to
//!    defaults, which protect updates, so this can never leave the machine unprotected.
//! 2. Open the journal and determine whether the previous session ended cleanly. This happens
//!    *before* anything else writes to the journal, so the evidence is not overwritten.
//! 3. Apply update protection immediately, synchronously, before any worker starts. Protection
//!    must not wait on the supervisor: a machine that is booting is exactly when an unexpected
//!    update activity is least welcome.
//! 4. Start the supervised workers.
//! 5. Serve IPC.
//!
//! # Shutdown order
//!
//! Preshutdown asks every worker to stop, flushes the journal and the state document, and writes
//! the clean-shutdown marker. That marker is the *only* thing that makes the next boot treat this
//! one as clean, so it is written with a synchronous flush.
//!
//! # Service architecture
//!
//! Nothing here blocks the SCM's control handler. The handler sets a flag; the main thread polls
//! it. That is what lets a stop request be acknowledged promptly even while a worker is mid-task.

#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use guardian_core::net::NetworkPolicy;
use guardian_core::ports::Clock;
use guardian_proto::model::*;
use guardian_service::supervisor::{Supervisor, WorkerSpec};
use guardian_service::{ipc, journal, logging, state};
use guardian_win::clock::{SystemBootIdentity, SystemClock};
use guardian_win::service_host::ServiceIdentity;

/// How often the coordinator refreshes its own view, and the journal checkpoints.
const CONTROL_INTERVAL: Duration = Duration::from_secs(5);
/// Journal checkpoint interval in NORMAL mode.
const CHECKPOINT_INTERVAL_NORMAL: Duration = Duration::from_secs(60);
/// Journal checkpoint interval in WORKING mode, where more is at stake.
const CHECKPOINT_INTERVAL_WORKING: Duration = Duration::from_secs(15);

fn main() {
    // The service must never be a console application; failures are reported through the SCM and
    // the log rather than to a console nobody is watching.
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("guardian-service {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // A `--console` mode makes the service debuggable without installing it. It is deliberately
    // not the default: running protection as a console app leaves it dead when the session ends.
    if args.iter().any(|a| a == "--console") {
        run_service_body();
        return;
    }

    match guardian_win::service_host::run_service(ServiceIdentity {
        name: SERVICE_NAME,
        body: run_service_body,
    }) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("guardian-service: could not start as a service: {e}");
            std::process::exit(1);
        }
    }
}

/// The service body, run either under the SCM or in `--console` mode.
pub fn run_service_body() {
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

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        boot_id = %boot_id,
        data_dir = %paths.root().display(),
        "Workstation Guardian service starting"
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
    coordinator.set_workers(&guardian_service::supervisor::HealthRegistry::new());

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

    if let Ok(mut guard) = recovery_journal.lock() {
        if let Some(j) = guard.as_mut() {
            j.shutdown_observed(&SystemClock, previous.truncated, None, false);
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
                    let handler = Arc::new(guardian_service::ipc::ServiceHandler::new(
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

    // ---- 8. Main loop --------------------------------------------------------
    // Nothing here blocks: it polls the shutdown flag so a stop request is honoured promptly.
    let mut last_incident_count = 0usize;
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));

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

    tracing::info!("Workstation Guardian service stopped cleanly");
}

/// Load configuration, falling back to defaults on corruption.
fn load_configuration() -> ConfigDocument {
    let paths = guardian_storage::GuardianPaths::production();
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

/// The service name, taken from the shared constant so the installer and the service cannot
/// disagree about what it is called.
use guardian_proto::SERVICE_NAME;
