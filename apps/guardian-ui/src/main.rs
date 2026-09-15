//! `guardian-ui` — the tray icon and control panel.
//!
//! # What this process is, and is not
//!
//! It is a *view*. Every fact it displays comes from `guardian-service` over the named pipe, and
//! every action it offers is a request to that service. It holds no protection authority of its
//! own, which is why closing it - or crashing it, or killing WebView2 - has no effect on
//! protection whatsoever.
//!
//! Consequences that are load-bearing:
//!
//! * Closing the window hides it to the tray rather than exiting, so the tray icon stays available
//!   without a window being open.
//! * "Exit UI" stops this process and nothing else. There is deliberately no way to stop the
//!   service from here; that requires an explicit administrative action (`guardianctl stop`).
//! * Every privileged action goes through the service, which re-checks the calling principal.
//!   The UI being unable to do something is a convenience, not a security boundary.
//!
//! # Why the state is polled on a timer
//!
//! The service pushes state to subscribers, but the tray needs an icon that reflects reality even
//! when nothing has changed for hours. A single low-frequency poll (a few seconds) that updates
//! both the window and the tray is simpler than maintaining a push connection in the UI, and at
//! this interval its cost is negligible.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use std::time::Duration;

use guardian_proto::model::*;
use guardian_proto::{Request, Response};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

/// How often the UI refreshes from the service.
///
/// Long enough to be free, short enough that the tray icon is never stale for long.
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// The most recent snapshot, shared with the poller.
#[derive(Default)]
struct UiState {
    last: Option<StatusSnapshot>,
    /// Set when the service is unreachable, so the UI can say so rather than showing stale data
    /// as though it were current.
    last_error: Option<String>,
}

fn main() {
    build_tauri_app()
        .run(tauri::generate_context!())
        .expect("the Tauri runtime could not start");
}

fn build_tauri_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .manage(Mutex::new(UiState::default()))
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_agents,
            get_incidents,
            get_network,
            enter_maintenance,
            exit_maintenance,
            arm_reboot,
            disarm_reboot,
            reconnect,
            exit_ui,
        ])
        .setup(|app| {
            install_tray(app.handle())?;
            start_refresh_loop(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it. The tray icon remains, and protection is unaffected -
            // the service never depended on this process.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
}

/// Build the tray icon and its menu.
fn install_tray(app: &AppHandle) -> tauri::Result<()> {
    // Menu items are rebuilt on each refresh so their labels track the live state; the menu itself
    // is created once and its items replaced.
    let (menu, items) = build_menu(app, None)?;

    TrayIconBuilder::with_id("guardian-tray")
        .tooltip("Workstation Guardian")
        .icon(tray_icon())
        .menu(&menu)
        .show_menu_on_left_click(false)
        // Left click opens the panel; right click shows the menu. That is what a Windows tray icon
        // is expected to do.
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
        .build(app)?;

    // Keep the item handles so the refresh loop can relabel them.
    app.manage(items);
    Ok(())
}

/// The tray menu items whose labels change.
struct TrayItems {
    status: MenuItem<tauri::Wry>,
    agents: MenuItem<tauri::Wry>,
    network: MenuItem<tauri::Wry>,
}

impl TrayItems {
    fn update(&self, snapshot: Option<&StatusSnapshot>, error: Option<&str>) {
        match (snapshot, error) {
            (_, Some(_)) => {
                let _ = self.status.set_text("Service unreachable");
                let _ = self.agents.set_text("Agents: unknown");
                let _ = self.network.set_text("Internet: unknown");
            }
            (Some(s), None) => {
                let _ = self
                    .status
                    .set_text(format!("Update protection: {}", s.update.level.as_str()));
                let _ = self
                    .agents
                    .set_text(format!("Active agents: {}", s.agents.agent_count()));
                let _ = self
                    .network
                    .set_text(format!("Internet: {}", internet_label(s.network.internet)));
            }
            (None, None) => {}
        }
    }
}

/// Build the tray menu.
///
/// Returns `tauri::Result` directly: every failure here is a Tauri menu error, and converting to a
/// string only to convert back would lose the original error's type.
fn build_menu(
    app: &AppHandle,
    snapshot: Option<&StatusSnapshot>,
) -> tauri::Result<(Menu<tauri::Wry>, TrayItems)> {
    let status = MenuItem::with_id(
        app,
        "status",
        snapshot
            .map(|s| format!("Update protection: {}", s.update.level.as_str()))
            .unwrap_or_else(|| "Update protection: unknown".into()),
        false,
        None::<&str>,
    )?;

    let agents = MenuItem::with_id(
        app,
        "agents",
        snapshot
            .map(|s| format!("Active agents: {}", s.agents.agent_count()))
            .unwrap_or_else(|| "Active agents: unknown".into()),
        false,
        None::<&str>,
    )?;

    let network = MenuItem::with_id(
        app,
        "network",
        snapshot
            .map(|s| format!("Internet: {}", internet_label(s.network.internet)))
            .unwrap_or_else(|| "Internet: unknown".into()),
        false,
        None::<&str>,
    )?;

    let open = MenuItem::with_id(app, "open", "Open Guardian", true, None::<&str>)?;
    let reconnect = MenuItem::with_id(app, "reconnect", "Reconnect Internet", true, None::<&str>)?;
    let maintenance =
        MenuItem::with_id(app, "maintenance", "Maintenance Mode…", true, None::<&str>)?;
    let diagnostics = MenuItem::with_id(app, "diagnostics", "Diagnostics", true, None::<&str>)?;
    let quit = MenuItem::with_id(
        app,
        "exit-ui",
        "Exit UI (service keeps running)",
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
            &reconnect,
            &maintenance,
            &diagnostics,
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
/// Generated in code rather than loaded from a file so the UI has no binary asset dependency and
/// cannot fail to start because a resource is missing.
fn tray_icon() -> tauri::image::Image<'static> {
    const SIZE: u32 = 32;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);

    for y in 0..SIZE {
        for x in 0..SIZE {
            // A simple shield shape: a rounded square with a lighter border, in the same blue the
            // panel uses for "protected".
            let dx = (x as i32 - 16).abs();
            let dy = (y as i32 - 16).abs();
            let inside = dx <= 11 && dy <= 13;
            let border = inside && (dx >= 9 || dy >= 11);
            let (r, g, b, a) = if border {
                (0x37u8, 0x66u8, 0xC4u8, 0xFFu8)
            } else if inside {
                (0x2B, 0x53, 0x9E, 0xFF)
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

/// Poll the service and push the result to the window.
fn start_refresh_loop(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(REFRESH_INTERVAL);

            let snapshot = fetch_status();
            let (state, error) = match &snapshot {
                Ok(s) => (Some(s.clone()), None),
                Err(e) => (None, Some(e.clone())),
            };

            // Update the shared state so an `invoke` from the window sees fresh data.
            if let Some(shared) = app.try_state::<Mutex<UiState>>() {
                if let Ok(mut guard) = shared.lock() {
                    if state.is_some() {
                        guard.last = state.clone();
                    }
                    guard.last_error = error.clone();
                }
            }

            // Relabel the tray items.
            if let Some(items) = app.try_state::<TrayItems>() {
                items.update(state.as_ref(), error.as_deref());
            }

            // Tell the window, if it is open. A closed window costs nothing here.
            if let Some(window) = app.get_webview_window("main") {
                let payload = match &snapshot {
                    Ok(s) => serde_json::json!({ "ok": true, "status": s }),
                    Err(e) => serde_json::json!({ "ok": false, "error": e }),
                };
                let _ = window.emit("guardian://status", payload);
            }
        }
    });
}

/// Fetch the current status from the service.
fn fetch_status() -> Result<StatusSnapshot, String> {
    match call(&Request::GetStatus)? {
        Response::Status { snapshot } => Ok(*snapshot),
        Response::Error { error } => Err(error.to_string()),
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

/// Send one request to the service over the pipe.
///
/// A fresh connection per call: the operations are infrequent and a short-lived connection keeps
/// the client's state trivial.
fn call(request: &Request) -> Result<Response, String> {
    let mut client = guardian_service::ipc::IpcClient::connect(3_000)?;
    client.call_expect(request)
}

fn internet_label(health: InternetHealth) -> &'static str {
    match health {
        InternetHealth::Healthy => "Healthy",
        InternetHealth::Degraded => "Degraded",
        InternetHealth::Down => "Down",
        InternetHealth::Unknown => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Commands exposed to the frontend
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_status(state: tauri::State<'_, Mutex<UiState>>) -> Result<serde_json::Value, String> {
    let guard = state
        .lock()
        .map_err(|_| "UI state is unavailable".to_string())?;
    match (&guard.last, &guard.last_error) {
        (_, Some(e)) => Ok(serde_json::json!({ "ok": false, "error": e })),
        (Some(s), None) => Ok(serde_json::json!({ "ok": true, "status": s })),
        (None, None) => {
            // First poll has not completed yet; report that rather than an empty snapshot, which
            // would look like a machine with no agents and no protection.
            Ok(serde_json::json!({ "ok": false, "error": "connecting to the service…" }))
        }
    }
}

#[tauri::command]
fn get_agents() -> Result<serde_json::Value, String> {
    match call(&Request::GetAgents)? {
        Response::Agents { inventory } => {
            Ok(serde_json::json!({ "ok": true, "agents": inventory }))
        }
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn get_incidents(limit: u16) -> Result<serde_json::Value, String> {
    match call(&Request::GetIncidents { limit })? {
        Response::Incidents { incidents } => {
            Ok(serde_json::json!({ "ok": true, "incidents": incidents }))
        }
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn get_network() -> Result<serde_json::Value, String> {
    match call(&Request::GetNetwork)? {
        Response::Network { snapshot } => {
            Ok(serde_json::json!({ "ok": true, "network": snapshot }))
        }
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn enter_maintenance(
    override_protected_work: bool,
    confirmation: String,
) -> Result<serde_json::Value, String> {
    match call(&Request::EnterMaintenance {
        override_protected_work,
        confirmation,
    })? {
        Response::Ok { message } => Ok(serde_json::json!({ "ok": true, "message": message })),
        // A refusal is an expected outcome, not a transport failure, so it comes back as data the
        // UI can show rather than as an error.
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn exit_maintenance() -> Result<serde_json::Value, String> {
    match call(&Request::ExitMaintenance)? {
        Response::Ok { message } => Ok(serde_json::json!({ "ok": true, "message": message })),
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn arm_reboot(ttl_secs: u32) -> Result<serde_json::Value, String> {
    match call(&Request::ArmSingleReboot { ttl_secs })? {
        Response::Ok { message } => Ok(serde_json::json!({ "ok": true, "message": message })),
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn disarm_reboot() -> Result<serde_json::Value, String> {
    match call(&Request::DisarmReboot)? {
        Response::Ok { message } => Ok(serde_json::json!({ "ok": true, "message": message })),
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

#[tauri::command]
fn reconnect(reason: String) -> Result<serde_json::Value, String> {
    match call(&Request::Reconnect { reason })? {
        Response::Ok { message } => Ok(serde_json::json!({ "ok": true, "message": message })),
        Response::Error { error } => {
            Ok(serde_json::json!({ "ok": false, "error": error.to_string() }))
        }
        other => Err(format!("unexpected reply: {other:?}")),
    }
}

/// Close the panel, leaving the service running.
///
/// Named `exit_ui` rather than `exit` to make the scope unmistakable at every call site: this
/// process ends, protection does not.
#[tauri::command]
fn exit_ui(app: AppHandle) {
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tray_icon_has_the_expected_dimensions() {
        let icon = tray_icon();
        assert_eq!(icon.width(), 32);
        assert_eq!(icon.height(), 32);
        assert_eq!(icon.rgba().len(), 32 * 32 * 4);
    }

    #[test]
    fn the_tray_icon_has_transparent_corners_and_a_solid_centre() {
        let icon = tray_icon();
        let rgba = icon.rgba();
        let alpha_at = |x: u32, y: u32| rgba[((y * 32 + x) * 4 + 3) as usize];

        assert_eq!(alpha_at(0, 0), 0, "the corner must be transparent");
        assert_eq!(
            alpha_at(16, 16),
            255,
            "the centre must be opaque so the icon is visible on any taskbar"
        );
    }

    #[test]
    fn internet_labels_cover_every_health_value() {
        for health in [
            InternetHealth::Healthy,
            InternetHealth::Degraded,
            InternetHealth::Down,
            InternetHealth::Unknown,
        ] {
            assert!(!internet_label(health).is_empty());
        }
    }

    /// Build a status snapshot with the given protection level.
    fn snapshot_with(level: ProtectionLevel, health: InternetHealth) -> StatusSnapshot {
        StatusSnapshot {
            mode: ProtectionMode::Working,
            update: UpdateProtectionReport {
                level,
                primary_lock_effective: level.is_protected(),
                values: vec![],
                neutralized_deadlines: vec![],
                management: ManagementState::Unmanaged,
                findings: vec![],
                checked_at_ms: 0,
                backend_error: None,
            },
            restart_protection: ProtectionLevel::Protected,
            pending_reboot: PendingRebootReport::unknown("test", 0),
            service: ServiceHealth {
                running: true,
                started_at_ms: 0,
                uptime_ms: 0,
                version: "0.1.0".into(),
                degraded_components: vec![],
                started_after_unclean_exit: false,
            },
            agents: Box::new(AgentInventory::default()),
            network: Box::new(NetworkSnapshot {
                internet: health,
                ..Default::default()
            }),
            reboot_authorization: None,
            maintenance_denial_reasons: vec![],
            generated_at_ms: 0,
            service_version: "0.1.0".into(),
            boot_id: "boot".into(),
            session_id_helper: SessionHelperState::NotRunning,
        }
    }

    #[test]
    fn the_tray_labels_name_the_live_protection_level() {
        // The tray is what an operator sees without opening anything, so its wording must be the
        // honest one from the snapshot rather than a fixed string.
        let snapshot = snapshot_with(ProtectionLevel::Degraded, InternetHealth::Down);
        assert_eq!(snapshot.update.level.as_str(), "Degraded");
        assert!(!snapshot.update.level.is_protected());
        assert_eq!(internet_label(snapshot.network.internet), "Down");
    }

    #[test]
    fn a_protected_snapshot_is_the_only_one_that_reads_as_protected() {
        // Mirrors the invariant the whole project rests on, asserted at the boundary the UI reads.
        assert_eq!(
            snapshot_with(ProtectionLevel::Protected, InternetHealth::Healthy)
                .update
                .level
                .as_str(),
            "Protected"
        );
        for level in [
            ProtectionLevel::Degraded,
            ProtectionLevel::Maintenance,
            ProtectionLevel::Unknown,
            ProtectionLevel::Unprotected,
        ] {
            let snapshot = snapshot_with(level, InternetHealth::Healthy);
            assert_ne!(
                snapshot.update.level.as_str(),
                "Protected",
                "{level:?} must not reach the UI as Protected"
            );
            assert!(!snapshot.update.level.is_protected());
        }
    }

    #[test]
    fn the_refresh_interval_is_low_frequency() {
        // A UI that polled continuously would defeat the point of the event-driven service.
        assert!(REFRESH_INTERVAL >= Duration::from_secs(2));
        assert!(REFRESH_INTERVAL <= Duration::from_secs(30));
    }
}
