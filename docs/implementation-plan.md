# Workstation Guardian — Implementation Plan

Status: living document. Updated as implementation proceeds.

## Core invariant

The machine may fail, but it must never silently lose work.

## Repository survey (2026-09-15)

The repository contained only a placeholder `Cargo.toml` + `src/main.rs` (`Hello, world!`),
no commits, no remote. Everything below is greenfield.

Environment probed on the target machine (Windows 11 Pro 10.0.26200, x64, MSVC 1.98.1):

| Fact | Finding |
|---|---|
| Host target | `x86_64-pc-windows-msvc`; `windows` crate 0.62 builds and links (Windows SDK 10.0.26100) |
| WebView2 | installed (`EdgeWebView/Application/153.x`) |
| Tauri | `@tauri-apps/cli` 2.11.4 (npm, global); `tauri` crate 2.11.5 is current stable; 3.0 is alpha → pin v2 |
| RAS | `rasapi32.dll` present; `RasMan` running; phonebook `%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk` (2805 bytes) |
| WU policy | `HKLM\SOFTWARE\Policies\...\WindowsUpdate\AU` already holds `NoAutoUpdate=1`, `NoAutoRebootWithLoggedOnUsers=1`, `AlwaysAutoRebootAtScheduledTime=0` |
| WU deadline | `SetAutoRestartDeadline` / `SetAutoRestartNotificationConfig` **absent** (no deadline being enforced) |
| Pending reboot | all classic signals absent → `NotPending` |
| Management | not domain joined, no MDM enterprise enrollment (only `EnrollmentType=1` = MDM *service* declarations); `PolicyManager\current\device` holds only Education/knobs/Start |
| Services | `wuauserv` Manual/Stopped, `UsoSvc` Automatic/**Running**, `WaaSMedicSvc` Manual/Stopped |
| Agents present | `claude.exe` (2.1.270, `~/.local/bin`), `codex-cli` 0.154.0 (node wrapper, also `@openai/codex` npm), `grok.exe` (1.0.30, native, `~/.grok/bin`) |

### Real evidence gathered for the detector

Live process trees show the shapes the detector must handle:

```
grok.exe --resume <uuid>          (native, C:\Users\...\.grok\bin\grok.exe)
└─ python.exe .../ida_pro_mcp/server.py   (MCP child — NOT an agent)

claude.exe                        (native, C:\Users\...\.local\bin\claude.exe)
└─ python.exe .../ida_pro_mcp/server.py   (MCP child — NOT an agent)
```

Agent-owned local state that adapters may read (read-only, no secrets copied):

* Claude Code — `~/.claude/sessions/<pid>.json` carries `{pid, sessionId, cwd, startedAt,
  procStart, version, kind, entrypoint, status}`. `procStart` is a Windows FILETIME that can be
  matched against the live process creation time to defeat PID reuse. `.key` files hold a
  `peerToken` and must **never** be read.
* Grok — `~/.grok/active_sessions.json` = list of `{session_id, pid, cwd, opened_at}`.
* Codex — `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`, first line `session_meta` carries
  `cwd`, `cli_version`, `originator`, `source`.

Notable false-positive traps confirmed on this machine: `python.exe .../ida_pro_mcp/server.py`
spawned as an MCP child of an agent, and `Scoop`/`codex` **sh** wrapper scripts (not the real
binary) on PATH.

## Component map

```
crates/
  guardian-proto    versioned request/response, shared types, no Win32
  guardian-core     state machines (pure), confidence scoring, policy model, config schema
  guardian-storage  atomic journal + crash-safe state
  guardian-win      ALL unsafe Win32 in one crate behind safe wrappers
  guardian-process  process inventory/graph + generic agent detection engine
  guardian-network  RAS/PPPoE + connectivity quorum state machine
  guardian-update   Windows Update policy backend + tamper detection + pending reboot
  guardian-service  service supervisor, IPC server, workers
apps/
  guardian-session  tiny per-user shutdown blocker
  guardian-ui       Tauri v2 tray + control panel
  guardianctl       CLI diagnostics
```

## Order of work

1. crates + state models + persistence
2. Windows Service lifecycle + SCM recovery
3. secure IPC (named pipe + ACL)
4. update policy backend
5. maintenance / single-reboot state machine
6. process monitor + generic agent detector
7. session helper + shutdown blocker
8. preshutdown / recovery journal
9. Windows Event Log reboot analysis
10. RAS/PPPoE backend
11. network state machine
12. Tauri tray/UI
13. guardianctl
14. installer/uninstaller
15. integration tests
16. documentation
17. real-machine validation
