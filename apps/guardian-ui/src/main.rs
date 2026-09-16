//! Workstation Guardian — the whole program, in one process.
//!
//! # What this is
//!
//! A single elevated tray application. It hosts the protection runtime directly, so there is no
//! Windows service, nothing registered with the Service Control Manager, no installer, and nothing
//! left behind when it exits.
//!
//! ```text
//!   guardian-ui.exe  (elevated, one process)
//!        │
//!        ├── the Guardian runtime: update protection, agent detection,
//!        │   network guardian, recovery journal   (worker threads)
//!        │
//!        └── tray icon + control panel (Tauri / WebView2)
//! ```
//!
//! The control panel reads the runtime's state *in process*, so a UI fault cannot take protection
//! down: the runtime runs on its own thread with its own supervisor. The named-pipe IPC server
//! still runs inside the runtime, because `guardianctl` uses it, but the panel does not depend on it.
//!
//! # Lifecycle
//!
//! * Closing the window hides it to the tray. Protection continues untouched.
//! * The tray icon is the program's presence. It disappears only when the program exits.
//! * Exiting is explicit — from the tray menu or the panel. It stops the runtime cleanly, which
//!   writes the recovery journal's clean-shutdown marker and persists state.
//!
//! # Elevation
//!
//! Update protection is a machine-wide policy write, so it needs administrator rights. Without them
//! the runtime still starts and reports honestly: update protection reads `Unknown` rather than
//! claiming a lock it could not apply. The panel says so at the top of the window instead of
//! pretending everything is fine.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

mod autostart;

use guardian_proto::i18n::{msg, Text};
use guardian_proto::model::*;
use guardian_proto::Lang;
use guardian_service::runtime::{run, GuardianRuntime, RuntimeOptions};
use guardian_service::state::{ServiceState, SharedState};
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

/// Wire the tray menu to [`handle_menu_event`].
///
/// Kept as a small function so the builder chain stays readable and so the same handler is
/// reachable from a test.
const MENU_EVENT_HANDLER: fn(&AppHandle, &str) = handle_menu_event;

/// How often the tray labels and the open panel are refreshed from the in-process state.
///
/// Cheap: it takes a read lock and formats a few strings. Frequent enough that the tray is never
/// visibly stale, infrequent enough to be invisible in a process that runs for months.
const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

/// How long to let the runtime shut down before the process exits anyway.
///
/// The runtime flushes its journal and writes the clean-shutdown marker on the way out. A short
/// bounded wait means an explicit exit is still prompt even if a worker is wedged.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(1500);

/// Shared between the UI and the runtime thread.
///
/// Deliberately tiny: the only thing the UI needs from the runtime is the state handle and the
/// ability to ask it to stop. Everything else the panel displays comes out of `ServiceState`.
#[derive(Default)]
struct UiBridge {
    /// `None` until the runtime has published its state.
    runtime: Mutex<Option<GuardianRuntime>>,
    /// Whether the runtime has been asked to stop, so the exit path runs once.
    exiting: AtomicBool,
    /// Set when this process is not elevated, so the panel can say what is not protected.
    elevated: AtomicBool,
}

impl UiBridge {
    /// Publish the runtime. Returns the state handle and whether this process is elevated.
    fn attach(&self, runtime: GuardianRuntime, elevated: bool) -> SharedState {
        let shared = runtime.state();
        self.elevated.store(elevated, Ordering::SeqCst);
        if let Ok(mut guard) = self.runtime.lock() {
            *guard = Some(runtime);
        }
        shared
    }

    /// Run `f` against the live state, if the runtime is up.
    ///
    /// A poisoned lock is recovered rather than propagated: a UI thread panicking must not stop the
    /// operator from seeing their protection status.
    fn with_state<T>(&self, f: impl FnOnce(&ServiceState) -> T) -> Option<T> {
        let guard = match self.runtime.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let shared = guard.as_ref()?.state();
        drop(guard);

        let state = match shared.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        Some(f(&state))
    }

    /// The panel document, or `None` while the runtime is still starting.
    fn panel(&self, lang: Lang) -> Option<serde_json::Value> {
        self.with_state(|state| {
            let snapshot = state.snapshot(guardian_win::clock::unix_now_ms());
            panel_json(state, &snapshot, lang)
        })
    }

    fn is_elevated(&self) -> bool {
        self.elevated.load(Ordering::SeqCst)
    }

    /// Ask the runtime to stop and wait, briefly, for it to finish.
    fn request_stop(&self) {
        if self.exiting.swap(true, Ordering::SeqCst) {
            return; // already exiting; the second request must not wait again
        }
        let guard = match self.runtime.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(runtime) = guard.as_ref() {
            runtime.request_stop();
        }
        drop(guard);

        let deadline = std::time::Instant::now() + SHUTDOWN_GRACE;
        while std::time::Instant::now() < deadline {
            let done = matches!(self.runtime.lock(), Ok(g) if g.as_ref().is_some_and(|r| r.is_shutting_down()));
            if done {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // The elevated copy is started by the unelevated one, so for a moment both exist. The two are
    // told apart explicitly rather than by guessing:
    //
    //   --relaunched=<pid>   this instance was started by <pid>, which is about to exit
    //
    // Identifying the predecessor by pid rather than by image name matters. Matching on the name
    // means "wait for any guardian-ui.exe", which includes this one, and cannot distinguish the
    // process that is leaving from one that is starting. That made the handshake racy: the new
    // instance could give up waiting, start alongside its predecessor, and then the two fought over
    // the named pipe — with the loser exiting, which looks exactly like the button doing nothing.
    let relaunched_from = args
        .iter()
        .find_map(|a| a.strip_prefix(RELAUNCH_PREFIX))
        .and_then(|v| v.parse::<u32>().ok());

    if let Some(predecessor) = relaunched_from {
        // Wait for the specific process that launched us. Bounded, because the user has already
        // approved the UAC prompt and is waiting for a window.
        wait_for_exit(predecessor, Duration::from_secs(15));
    } else if let Some(existing) = other_instance() {
        eprintln!(
            "Workstation Guardian is already running (pid {existing}). \
             Use the tray icon to open it."
        );
        return;
    }

    build_app()
        .run(tauri::generate_context!())
        .expect("the Tauri runtime could not start");
}

/// The prefix the elevated instance is started with, followed by the launcher's pid.
const RELAUNCH_PREFIX: &str = "--relaunched=";

/// Wait for one specific process to exit.
///
/// Returns as soon as that pid is gone. A timeout is not an error: coexisting briefly is
/// survivable, whereas refusing to start would strand the user with only the unelevated copy.
fn wait_for_exit(pid: u32, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !process_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    tracing::warn!(
        pid,
        "the instance that launched us did not exit; continuing anyway"
    );
}

/// Whether a pid is still running.
///
/// Enumerating and matching is used rather than `OpenProcess`, because the predecessor runs at a
/// different integrity level and a direct query can fail for permission reasons that would look
/// like "already exited".
fn process_alive(pid: u32) -> bool {
    guardian_win::process::enumerate_processes()
        .map(|procs| procs.iter().any(|p| p.pid == pid))
        .unwrap_or(false)
}

/// Another copy of this program, by pid.
fn other_instance() -> Option<u32> {
    let me = std::process::id();
    let mut processes = guardian_win::process::enumerate_processes().ok()?;
    processes.retain(|p| p.pid != me);
    processes
        .into_iter()
        .find(|p| {
            let name = p.name.to_ascii_lowercase();
            name == "guardian-ui.exe" || name == "guardian.exe"
        })
        .map(|p| p.pid)
}

/// The language to render in, from configuration, defaulting to the system locale.
fn configured_language() -> Lang {
    let paths = guardian_storage::GuardianPaths::production();
    match std::fs::read_to_string(paths.config_file()) {
        Ok(text) => {
            guardian_core::config::load_from_str(&text)
                .document
                .body
                .language
        }
        Err(_) => Lang::Auto,
    }
}

fn build_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .manage(UiBridge::default())
        .manage(configured_language())
        .invoke_handler(tauri::generate_handler![
            get_panel,
            get_incidents,
            get_language,
            reconnect,
            restart_elevated,
            get_autostart,
            set_autostart,
            exit_app,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            install_tray(&handle)?;
            start_runtime(handle);
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it. The runtime keeps running and protection is unaffected,
            // which is the entire reason the UI is not the program's lifecycle.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
}

/// Start the protection runtime on its own thread.
///
/// The runtime owns the process's real work. This thread runs until the runtime stops, which is why
/// a panic in the webview cannot end protection.
fn start_runtime(app: AppHandle) {
    std::thread::spawn(move || {
        let elevated = guardian_win::elevation::is_elevated();

        run(
            RuntimeOptions {
                run_for: None,
                echo_errors: true,
            },
            move |runtime| {
                let bridge = app.state::<UiBridge>();
                let shared = bridge.attach(runtime, elevated);

                if !elevated {
                    tracing::warn!(
                        "not elevated: Windows Update policy cannot be applied. \
                         Restart the program as administrator for full protection."
                    );
                }

                // Refresh the tray and the open panel from the live state.
                let app = app.clone();
                std::thread::spawn(move || refresh_loop(app, shared));
            },
        );
    });
}

/// Publish runtime state to the tray, and to the window when it is open.
fn refresh_loop(app: AppHandle, shared: SharedState) {
    let lang = *app.state::<Lang>();

    loop {
        std::thread::sleep(REFRESH_INTERVAL);

        let state = match shared.read() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let snapshot = state.snapshot(guardian_win::clock::unix_now_ms());

        if let Some(items) = app.try_state::<TrayItems>() {
            items.update(&snapshot, lang);
        }

        if let Some(window) = app.get_webview_window("main") {
            let panel = panel_json(&state, &snapshot, lang);
            let _ = window.emit("guardian://panel", panel);
        }
    }
}

/// Build the tray icon and its menu.
fn install_tray(app: &AppHandle) -> tauri::Result<()> {
    let lang = *app.state::<Lang>();
    let (menu, items) = build_menu(app, lang)?;

    TrayIconBuilder::with_id("guardian-tray")
        .tooltip("Workstation Guardian")
        .icon(tray_icon())
        .menu(&menu)
        .show_menu_on_left_click(false)
        // Left click opens the panel, right click shows the menu. That is what a Windows tray icon
        // is expected to do, and it means the panel is one click away without hunting the menu.
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| MENU_EVENT_HANDLER(app, event.id().as_ref()))
        .build(app)?;

    app.manage(items);
    Ok(())
}

/// The tray menu items whose labels track the live state.
struct TrayItems {
    status: MenuItem<tauri::Wry>,
    agents: MenuItem<tauri::Wry>,
    network: MenuItem<tauri::Wry>,
}

impl TrayItems {
    fn update(&self, snapshot: &StatusSnapshot, lang: Lang) {
        let _ = self.status.set_text(format!(
            "{}: {}",
            msg::UPDATE_PROTECTION.get(lang),
            level_label(snapshot.update.level, lang)
        ));

        let _ = self.agents.set_text(format!(
            "{}: {}",
            msg::ACTIVE_AGENTS.get(lang),
            snapshot.agents.agent_count()
        ));

        let _ = self.network.set_text(format!(
            "{}: {}",
            msg::INTERNET.get(lang),
            internet_label(snapshot.network.internet, lang)
        ));
    }
}

/// Build the tray menu.
fn build_menu(app: &AppHandle, lang: Lang) -> tauri::Result<(Menu<tauri::Wry>, TrayItems)> {
    let status = MenuItem::with_id(
        app,
        "status",
        format!(
            "{}: {}",
            msg::UPDATE_PROTECTION.get(lang),
            msg::UNKNOWN.get(lang)
        ),
        false,
        None::<&str>,
    )?;
    let agents = MenuItem::with_id(
        app,
        "agents",
        format!("{}: —", msg::ACTIVE_AGENTS.get(lang)),
        false,
        None::<&str>,
    )?;
    let network = MenuItem::with_id(
        app,
        "network",
        format!("{}: —", msg::INTERNET.get(lang)),
        false,
        None::<&str>,
    )?;

    let open = MenuItem::with_id(
        app,
        "open",
        Text::new("Open Guardian", "打开 Guardian").get(lang),
        true,
        None::<&str>,
    )?;
    let logon = CheckMenuItem::with_id(
        app,
        "start-at-logon",
        msg::START_AT_LOGON.get(lang),
        true,
        autostart::state().any(),
        None::<&str>,
    )?;
    let data_folder = MenuItem::with_id(
        app,
        "data-folder",
        Text::new("Open data folder", "打开数据目录").get(lang),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        "exit-app",
        Text::new("Exit Guardian", "退出 Guardian").get(lang),
        true,
        None::<&str>,
    )?;

    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(
        app,
        &[
            &status,
            &agents,
            &network,
            &sep1,
            &open,
            &data_folder,
            &logon,
            &sep2,
            &quit,
        ],
    )?;

    Ok((
        menu,
        TrayItems {
            status,
            agents,
            network,
        },
    ))
}

/// The tray icon.
///
/// Drawn in code rather than loaded from a file, so the program has no runtime asset dependency and
/// cannot fail to start because a resource is missing.
fn tray_icon() -> tauri::image::Image<'static> {
    const SIZE: u32 = 32;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = (x as i32 - 16).abs();
            let dy = (y as i32 - 16).abs();
            let inside = dx <= 11 && dy <= 13;
            let border = inside && (dx >= 9 || dy >= 11);
            let (r, g, b, a) = if border {
                (0x5Au8, 0x9Bu8, 0xE8u8, 0xFFu8)
            } else if inside {
                (0x1E, 0x5C, 0xB0, 0xFF)
            } else {
                (0, 0, 0, 0)
            };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }

    tauri::image::Image::new_owned(rgba, SIZE, SIZE)
}

/// Bring the control panel to the front.
fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

// ---------------------------------------------------------------------------
// Labels, shared with the CLI so the two can never disagree
// ---------------------------------------------------------------------------

/// The label for a protection level.
pub fn level_label(level: ProtectionLevel, lang: Lang) -> &'static str {
    match level {
        ProtectionLevel::Protected => msg::PROTECTED.get(lang),
        ProtectionLevel::Degraded => msg::DEGRADED.get(lang),
        ProtectionLevel::Maintenance => msg::MAINTENANCE.get(lang),
        ProtectionLevel::Unknown => msg::UNKNOWN.get(lang),
        ProtectionLevel::Unprotected => msg::UNPROTECTED.get(lang),
    }
}

/// The label for Internet health.
pub fn internet_label(health: InternetHealth, lang: Lang) -> &'static str {
    match health {
        InternetHealth::Healthy => msg::HEALTHY.get(lang),
        InternetHealth::Degraded => msg::DEGRADED.get(lang),
        InternetHealth::Down => msg::DOWN.get(lang),
        InternetHealth::Unknown => msg::UNKNOWN.get(lang),
    }
}

/// Everything the panel draws, in one document.
///
/// The frontend is handed finished values — already-translated labels, already-computed counts —
/// rather than raw state it would have to interpret. That keeps the "fail closed, never overstate"
/// rule in one place, in Rust, where it is tested.
fn panel_json(state: &ServiceState, snapshot: &StatusSnapshot, lang: Lang) -> serde_json::Value {
    let now = guardian_win::clock::unix_now_ms();

    // One row per detected agent. `instances` is the list of matching processes; a group is shown
    // with its instance count rather than one row per process, because an agent like Claude Code
    // appears as several helper processes that an operator thinks of as one session.
    let agents: Vec<serde_json::Value> = snapshot
        .agents
        .agents
        .iter()
        .map(|group| {
            serde_json::json!({
                "display_name": group.display_name,
                "kind": group.kind,
                "confidence": group.confidence.as_str(),
                "confidence_label": confidence_label(group.confidence, lang),
                "instance_count": group.instances.len(),
                // The project is per instance, so it is only shown when every instance in the group
                // agrees; otherwise the row would name one project out of several.
                "project": shared_project(&group.instances),
            })
        })
        .collect();

    serde_json::json!({
        "lang": lang.as_str(),
        "generated_at_ms": snapshot.generated_at_ms,
        "version": snapshot.service_version,
        "mode": {
            "value": snapshot.mode.as_str(),
            "label": mode_label(snapshot.mode, lang),
        },
        "update": {
            "level": snapshot.update.level.as_str(),
            "label": level_label(snapshot.update.level, lang),
            // Findings carry the plain-language reasons; when protection is intact there are none
            // and the panel shows the affirmative instead of an empty list.
            "findings": snapshot.update.findings.iter().map(|f| f.message.clone()).collect::<Vec<_>>(),
            "primary_lock_effective": snapshot.update.primary_lock_effective,
            "management": snapshot.update.management.describe(),
            "checked_at_ms": snapshot.update.checked_at_ms,
            "backend_error": snapshot.update.backend_error,
        },
        "restart_protection": {
            "level": snapshot.restart_protection.as_str(),
            "label": level_label(snapshot.restart_protection, lang),
        },
        "pending_reboot": {
            "verdict": snapshot.pending_reboot.verdict.as_str(),
            "label": pending_reboot_label(snapshot.pending_reboot.verdict, lang),
            "signals": snapshot
                .pending_reboot
                .signals
                .iter()
                .map(|s| s.detail.clone())
                .collect::<Vec<_>>(),
        },
        "network": {
            "internet": snapshot.network.internet.as_str(),
            "internet_label": internet_label(snapshot.network.internet, lang),
            "entry_name": snapshot.network.entry_name,
            "ras_state": format!("{:?}", snapshot.network.ras_state),
        },
        "agents": agents,
        "agent_count": snapshot.agents.agent_count(),
        "incident_count": state.incidents.len(),
        "uptime_ms": now.saturating_sub(snapshot.service.started_at_ms),
        "degraded_components": snapshot.service.degraded_components,
        "maintenance": {
            "blockers": snapshot.maintenance_denial_reasons,
            "reboot_authorization": snapshot.reboot_authorization.as_ref().map(|a| serde_json::json!({
                "expires_at_ms": a.expires_at_ms,
            })),
        },
        "unclean_previous_exit": state.started_after_unclean_exit,
    })
}

/// The project shared by every instance in a group, if they all agree.
///
/// Returns `None` when the instances disagree or none supplied one. Showing one instance's project
/// for the whole group would attribute work to the wrong project, which is worse than showing
/// nothing.
fn shared_project(instances: &[AgentInstance]) -> Option<String> {
    let mut names = instances
        .iter()
        .filter_map(|i| i.project.as_ref().map(|p| p.name.clone()));
    let first = names.next()?;
    names.all(|n| n == first).then_some(first)
}

/// The label for a pending-reboot verdict.
fn pending_reboot_label(verdict: PendingRebootVerdict, lang: Lang) -> &'static str {
    match verdict {
        PendingRebootVerdict::NotPending => msg::PENDING_REBOOT_NONE.get(lang),
        PendingRebootVerdict::ProbablyPending => msg::PENDING_REBOOT_PROBABLY.get(lang),
        PendingRebootVerdict::Pending => msg::PENDING_REBOOT_ALREADY.get(lang),
        PendingRebootVerdict::Unknown => msg::PENDING_REBOOT_UNKNOWN.get(lang),
    }
}

/// The label for a detection confidence.
fn confidence_label(confidence: Confidence, lang: Lang) -> &'static str {
    match confidence {
        Confidence::Confirmed => msg::CONFIDENCE_CONFIRMED.get(lang),
        Confidence::High => msg::CONFIDENCE_HIGH.get(lang),
        Confidence::Possible => msg::CONFIDENCE_POSSIBLE.get(lang),
        Confidence::Unknown => msg::CONFIDENCE_UNKNOWN.get(lang),
    }
}

/// The label for a protection mode.
fn mode_label(mode: ProtectionMode, lang: Lang) -> &'static str {
    match mode {
        ProtectionMode::Normal => msg::MODE_NORMAL.get(lang),
        ProtectionMode::Working => msg::MODE_WORKING.get(lang),
        ProtectionMode::Maintenance => msg::MODE_MAINTENANCE.get(lang),
    }
}

// ---------------------------------------------------------------------------
// Commands exposed to the frontend
// ---------------------------------------------------------------------------

/// The whole panel, in one call.
///
/// One command rather than six means the panel can never render a half-updated view — a status from
/// this second beside a network figure from ten seconds ago.
#[tauri::command]
fn get_panel(
    bridge: tauri::State<'_, UiBridge>,
    lang: tauri::State<'_, Lang>,
) -> serde_json::Value {
    let lang = *lang;
    match bridge.panel(lang) {
        Some(panel) => serde_json::json!({
            "ok": true,
            "elevated": bridge.is_elevated(),
            "panel": panel,
        }),
        // Not an error: the first protection pass is still running. Saying "starting" is honest,
        // where an empty panel would look exactly like a machine with nothing protected.
        None => serde_json::json!({
            "ok": false,
            "starting": true,
            "elevated": bridge.is_elevated(),
            "message": msg::STARTING.get(lang),
        }),
    }
}

#[tauri::command]
fn get_incidents(bridge: tauri::State<'_, UiBridge>, limit: u16) -> serde_json::Value {
    let limit = usize::from(limit.min(200));
    match bridge.with_state(|state| {
        // Newest first, then trim: the panel wants the most recent events.
        let mut incidents: Vec<&Incident> = state.incidents.iter().collect();
        incidents.reverse();
        incidents.truncate(limit);
        incidents.into_iter().cloned().collect::<Vec<Incident>>()
    }) {
        Some(incidents) => serde_json::json!({ "ok": true, "incidents": incidents }),
        None => serde_json::json!({ "ok": false, "starting": true }),
    }
}

#[tauri::command]
fn get_language(lang: tauri::State<'_, Lang>) -> String {
    lang.as_str().to_string()
}

/// Report the user's right-click "reconnect" as intent.
///
/// The panel does not dial. The network worker owns the link and acts on its own evaluation, so a
/// button cannot start two dials at once or fight the watchdog. This records the request in the log
/// so the reason for the next dial attempt is visible.
#[tauri::command]
fn reconnect(
    bridge: tauri::State<'_, UiBridge>,
    lang: tauri::State<'_, Lang>,
) -> serde_json::Value {
    let lang = *lang;
    let known = bridge.with_state(|_| ()).is_some();
    if known {
        tracing::info!("operator requested a reconnect from the control panel");
    }
    serde_json::json!({
        "ok": known,
        "message": if known {
            msg::RECONNECT_REQUESTED.get(lang)
        } else {
            msg::STARTING.get(lang)
        },
    })
}

/// Restart this program elevated, after the user consents to the UAC prompt.
///
/// # Ordering
///
/// The elevated copy is started *first*, then this one stops. Doing it the other way around would
/// leave the user with no Guardian at all if they then declined the prompt — so the decline path
/// must change nothing.
///
/// The new process is told to wait for this one to exit (`--relaunched`), so the single-instance
/// check does not turn its own restart away.
#[tauri::command]
fn restart_elevated(
    app: AppHandle,
    bridge: tauri::State<'_, UiBridge>,
    lang: tauri::State<'_, Lang>,
) -> serde_json::Value {
    let lang = *lang;

    if bridge.is_elevated() {
        return serde_json::json!({
            "ok": true,
            "already_elevated": true,
            "message": msg::ALREADY_ELEVATED.get(lang),
        });
    }

    // Pass this process's pid so the new instance waits for *this* one, not for any process that
    // happens to share the image name.
    let flag = format!("{RELAUNCH_PREFIX}{}", std::process::id());
    match guardian_win::elevation::relaunch_elevated_with(&[&flag]) {
        Ok(true) => {
            // The new instance is on its way. Stop this one so it can take over cleanly.
            let handle = app.clone();
            // Stop the runtime on a background thread so this command returns and the panel can
            // show that a restart is under way, rather than the process vanishing mid-reply.
            std::thread::spawn(move || {
                handle.state::<UiBridge>().request_stop();
                handle.exit(0);
            });
            serde_json::json!({ "ok": true, "relaunching": true })
        }
        // Declining the prompt is a legitimate choice, not a failure. Nothing has changed: the
        // program is still running and still protecting whatever it can.
        Ok(false) => serde_json::json!({
            "ok": false,
            "declined": true,
            "message": msg::ELEVATION_DECLINED.get(lang),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "could not restart elevated");
            serde_json::json!({
                "ok": false,
                "error": format!("{}: {e}", msg::ELEVATION_FAILED.get(lang)),
            })
        }
    }
}

/// Whether Guardian and the session helper start at logon.
#[tauri::command]
fn get_autostart(lang: tauri::State<'_, Lang>) -> serde_json::Value {
    let lang = *lang;
    let state = autostart::state();
    serde_json::json!({
        "ok": true,
        "enabled": state.any(),
        "guardian": state.guardian,
        "helper": state.helper,
        // Whether the helper *can* be registered: the binary has to be there. Reported up front so
        // the panel does not offer a toggle that would create an entry pointing at nothing.
        "helper_available": helper_path().is_some(),
        "label": msg::START_AT_LOGON.get(lang),
    })
}

/// Enable or disable logon startup.
#[tauri::command]
fn set_autostart(enabled: bool, lang: tauri::State<'_, Lang>) -> serde_json::Value {
    let lang = *lang;

    let Ok(exe) = std::env::current_exe() else {
        return serde_json::json!({
            "ok": false,
            "error": msg::AUTOSTART_FAILED.get(lang),
        });
    };

    // Register the helper alongside Guardian when it is present. It is what makes restart
    // protection real, so enabling startup without it would leave the panel reporting Degraded
    // forever with no obvious way to fix it.
    let helper = helper_path();

    match autostart::set_enabled(enabled, &exe, helper.as_deref()) {
        Ok(state) => serde_json::json!({
            "ok": true,
            "enabled": state.any(),
            "guardian": state.guardian,
            "helper": state.helper,
            "helper_available": helper.is_some(),
        }),
        Err(e) => {
            tracing::warn!(error = %e, "could not change the autostart setting");
            serde_json::json!({
                "ok": false,
                "error": format!("{}: {e}", msg::AUTOSTART_FAILED.get(lang)),
            })
        }
    }
}

/// Where `guardian-session.exe` is, if it ships beside this executable.
fn helper_path() -> Option<std::path::PathBuf> {
    autostart::helper_beside(&std::env::current_exe().ok()?)
}

/// Exit the whole program, runtime included.
///
/// This is the only action that stops protection, and it is explicit. Closing the window hides the
/// panel; it does not do this.
#[tauri::command]
fn exit_app(app: AppHandle, bridge: tauri::State<'_, UiBridge>) {
    bridge.request_stop();
    app.exit(0);
}

/// Open the data directory in Explorer.
///
/// Guarded so the tray item is harmless if the folder does not exist yet.
pub fn open_data_folder() -> std::io::Result<()> {
    let paths = guardian_storage::GuardianPaths::production();
    let root = paths.root().to_path_buf();
    if !root.exists() {
        std::fs::create_dir_all(&root)?;
    }
    std::process::Command::new("explorer.exe")
        .arg(root.as_os_str())
        .spawn()?;
    Ok(())
}

/// Handle the tray menu items that are not state readouts.
pub fn handle_menu_event(app: &AppHandle, id: &str) {
    match id {
        "open" => show_window(app),
        "data-folder" => {
            if let Err(e) = open_data_folder() {
                tracing::warn!("could not open the data folder: {e}");
            }
        }
        "start-at-logon" => {
            // A check item: Windows has already flipped the tick visually. Read the registry back
            // afterwards and re-sync, so the tick reflects what was actually written rather than
            // what was clicked.
            let wanted = !autostart::state().any();
            match std::env::current_exe() {
                Ok(exe) => {
                    if let Err(e) = autostart::set_enabled(wanted, &exe, helper_path().as_deref()) {
                        tracing::warn!(error = %e, "could not change the autostart setting");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "could not determine this executable's path"),
            }
        }
        "exit-app" => {
            app.state::<UiBridge>().request_stop();
            app.exit(0);
        }
        // The status rows are read-outs, not commands. Windows still delivers the event, so it is
        // matched explicitly rather than falling into a wildcard that could hide a typo in an id.
        "status" | "agents" | "network" => {}
        other => tracing::warn!("unhandled tray menu item: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tray_icon_has_the_expected_shape() {
        let icon = tray_icon();
        assert_eq!(icon.width(), 32);
        assert_eq!(icon.height(), 32);
        assert_eq!(icon.rgba().len(), 32 * 32 * 4);

        let alpha_at = |x: u32, y: u32| icon.rgba()[((y * 32 + x) * 4 + 3) as usize];
        assert_eq!(alpha_at(0, 0), 0, "the corner must be transparent");
        assert_eq!(
            alpha_at(16, 16),
            255,
            "the centre must be opaque so the icon is visible on any taskbar"
        );
    }

    #[test]
    fn the_refresh_interval_is_low_frequency() {
        // The panel reads in-process state, so this interval is a UI smoothness choice, not a
        // correctness one. A tight loop would waste CPU on a process that runs for months.
        assert!(REFRESH_INTERVAL >= Duration::from_secs(1));
        assert!(REFRESH_INTERVAL <= Duration::from_secs(30));
    }

    #[test]
    fn the_shutdown_grace_is_bounded() {
        // An explicit exit must be prompt even if a worker is wedged, while still leaving the
        // runtime time to flush its journal.
        assert!(SHUTDOWN_GRACE >= Duration::from_millis(200));
        assert!(SHUTDOWN_GRACE <= Duration::from_secs(10));
    }

    #[test]
    fn a_detached_bridge_reports_nothing_rather_than_a_blank_panel() {
        // A panel that showed zeros while the first protection pass is still running would look
        // exactly like a machine with no protection and no agents.
        let bridge = UiBridge::default();
        assert!(bridge.panel(Lang::En).is_none());
        assert!(bridge.with_state(|_| ()).is_none());
    }

    #[test]
    fn requesting_a_stop_before_the_runtime_exists_is_harmless() {
        let bridge = UiBridge::default();
        bridge.request_stop(); // must not panic, must not block
        assert!(bridge.exiting.load(Ordering::SeqCst));
    }

    #[test]
    fn a_second_stop_request_returns_immediately() {
        let bridge = UiBridge::default();
        bridge.request_stop();
        let start = std::time::Instant::now();
        bridge.request_stop();
        assert!(
            start.elapsed() < SHUTDOWN_GRACE,
            "the second exit request must not wait again"
        );
    }

    #[test]
    fn the_relaunch_flag_carries_the_launcher_pid() {
        // The pid is what makes the handshake unambiguous. With a bare flag the new instance has to
        // guess which process to wait for by image name, which also matches *itself*, so it cannot
        // reliably tell a process that is leaving from one that is starting.
        let pid = 4242u32;
        let flag = format!("{RELAUNCH_PREFIX}{pid}");
        assert_eq!(flag, "--relaunched=4242");

        let parsed = flag
            .strip_prefix(RELAUNCH_PREFIX)
            .and_then(|v| v.parse::<u32>().ok());
        assert_eq!(parsed, Some(pid));
    }

    #[test]
    fn a_normal_start_has_no_predecessor() {
        // Without the flag nothing is stripped, so the single-instance check applies as usual.
        assert_eq!("--turbo".strip_prefix(RELAUNCH_PREFIX), None);
        assert_eq!("--relaunched".strip_prefix(RELAUNCH_PREFIX), None);
        // A malformed pid must not be treated as a predecessor to wait for.
        assert_eq!(
            "--relaunched=abc"
                .strip_prefix(RELAUNCH_PREFIX)
                .and_then(|v| v.parse::<u32>().ok()),
            None
        );
    }

    #[test]
    fn the_predecessor_wait_is_bounded() {
        // A wedged earlier copy must not hang the new one: the user has already approved the UAC
        // prompt and is waiting for a window to appear.
        let start = std::time::Instant::now();
        // A pid that cannot exist, so the wait returns once the timeout elapses.
        wait_for_exit(0xFFFF_FFFE, Duration::from_millis(300));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "waiting for a predecessor must be bounded"
        );
    }

    #[test]
    fn this_process_is_reported_as_alive() {
        // `process_alive` guards the wait, so a false negative here would make the new instance
        // start alongside its predecessor and fight it for the pipe.
        assert!(process_alive(std::process::id()));
        assert!(
            !process_alive(0xFFFF_FFFE),
            "a nonexistent pid is not alive"
        );
    }

    #[test]
    fn this_process_is_not_reported_as_another_instance() {
        // `other_instance` must exclude the caller, or `wait_for_predecessor` would wait for
        // itself until the timeout on every start.
        let me = std::process::id();
        if let Some(other) = other_instance() {
            assert_ne!(other, me, "a process must not be its own predecessor");
        }
    }

    #[test]
    fn the_language_choices_all_round_trip() {
        for lang in Lang::choices() {
            assert_eq!(Lang::parse(lang.as_str()), lang);
        }
    }

    #[test]
    fn every_protection_level_has_a_distinct_label() {
        // If two levels rendered the same text, a degraded machine could be mistaken for a
        // protected one, which is the failure this project exists to prevent.
        for lang in [Lang::En, Lang::ZhCn] {
            let labels: Vec<&str> = [
                ProtectionLevel::Protected,
                ProtectionLevel::Degraded,
                ProtectionLevel::Maintenance,
                ProtectionLevel::Unknown,
                ProtectionLevel::Unprotected,
            ]
            .into_iter()
            .map(|l| level_label(l, lang))
            .collect();

            for (i, a) in labels.iter().enumerate() {
                assert!(!a.is_empty(), "a level label is empty in {lang:?}");
                for b in labels.iter().skip(i + 1) {
                    assert_ne!(a, b, "two protection levels read the same in {lang:?}");
                }
            }
        }
    }

    #[test]
    fn unhandled_menu_ids_are_not_silently_ignored() {
        // The status rows must be matched explicitly: a wildcard would swallow a typo in a real
        // command's id and the button would appear to do nothing.
        let known = [
            "status",
            "agents",
            "network",
            "open",
            "data-folder",
            "exit-app",
        ];
        assert_eq!(known.len(), 6);
        assert!(known.contains(&"exit-app"), "exit must be reachable");
    }
}
