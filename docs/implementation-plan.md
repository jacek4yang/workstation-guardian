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
| Tauri | `@tauri-apps/cli` 2.11.4 (npm, global); `tauri` crate 2.11.5 is current stable; 3.0 is alpha -> pin v2 |
| RAS | `rasapi32.dll` present; `RasMan` running; phonebook `%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk` |
| WU policy | `HKLM\SOFTWARE\Policies\...\WindowsUpdate\AU` already holds `NoAutoUpdate=1`, `NoAutoRebootWithLoggedOnUsers=1`, `AlwaysAutoRebootAtScheduledTime=0` |
| WU deadline | `SetAutoRestartDeadline` / `SetAutoRestartNotificationConfig` **absent** (no deadline being enforced) |
| Pending reboot | all classic signals absent -> `NotPending` |
| Management | not domain joined, no MDM enterprise enrollment; `PolicyManager\current\device` holds only Education/knobs/Start |
| Agents present | `claude.exe` 2.1.270, `codex-cli` 0.154.0 (npm), `grok.exe` 1.0.30 (native) |

## Progress

Completed subsystems, each committed with its tests green:

1. **Workspace, protocol, storage** — closed versioned IPC protocol; atomic document
   replacement and a checksummed append-only journal that discards a torn tail.
2. **guardian-core** — pure, dependency-inverted state machines: update policy verification,
   maintenance and the single-use reboot capability, pending-reboot and unexpected-restart
   classification, the broadband/Wi-Fi network policy, and configuration validation.
   `#![forbid(unsafe_code)]`.
3. **guardian-win** — the only crate with `unsafe`, `#![deny(unsafe_op_in_unsafe_fn)]`:
   registry, clocks, boot identity, pending-reboot probes, process enumeration, the Windows
   Update policy backend with management detection, RAS, named-pipe IPC with a tested ACL,
   session enumeration and shutdown blocking, and Native Wi-Fi.
4. **guardian-process** — generic, data-driven agent detection. Validated against this
   machine's live process table: reports exactly the five running agents with no false
   positives and no double-counting of their helper processes.
5. **guardian-network** — connectivity probes by quorum, the RAS/Wi-Fi backend, and the worker
   loop that implements "broadband primary, Wi-Fi continuity, repair in parallel".

6. **guardian-update** — verification loop, tamper detection, incident recording.
7. **guardian-service** — supervisor with per-worker restart, state coordinator, IPC server,
   recovery journal, preshutdown handling, bounded structured logging.
8. **guardian-session** — the per-user shutdown blocker.
9. **guardianctl** — diagnostics, SCM control, installation and uninstallation.
10. **guardian-ui** — Tauri v2 tray and control panel.
11. **Documentation** — README plus seven documents under `docs/`.
12. **CI and packaging** — GitHub Actions on Windows, and a redistributable archive.

## Status: shipped

Released as [v0.1.0](https://github.com/jacek4yang/workstation-guardian/releases/tag/v0.1.0).

Verified on this workstation (Windows 11 Pro 10.0.26200): update protection reads `Protected`
with zero registry writes on a conformant machine; the detector reports exactly the five running
agents Windows reports, with their real project names and no false positives; the PPPoE entry
`宽带连接` is enumerated and auto-selected; connectivity is judged by quorum across four probes on
a network that filters direct connections to public resolver IPs.

595 tests pass with no clippy warnings.

## Findings worth remembering

Real behaviour discovered by running tests against the OS rather than reasoning on paper:

* The named-pipe `IU` ACE needs `FILE_READ_ATTRIBUTES` and `SYNCHRONIZE` as well as the data
  rights; without them every client open is denied, so a "tight" ACL is merely unusable.
* `ConnectNamedPipe` on a blocking pipe ignores timeouts entirely, so the accept loop needs
  overlapped I/O or it can hang a service stop.
* `REG_MULTI_SZ` decoding must not stop at the first NUL.
* RAS error text is localized by the OS, so tests must not assert English words from that path.
* An npm-launched agent appears as two matching processes; a launcher that has an
  at-least-as-strong matched descendant must be suppressed or every such agent counts twice.

## Defects found by running against the real machine

Recorded because they justify the insistence on real-machine validation. None of these were
visible by reading the code, and several would have shipped.

| Defect | How it surfaced |
|---|---|
| The pipe ACL was unusable rather than tight — every client open was denied | An actual client connecting |
| `ConnectNamedPipe` ignores timeouts on a blocking pipe, so a stop could hang | A test that hung |
| `REG_MULTI_SZ` decoding truncated at the first element | Registry round-trip |
| MDM reported a managed machine that was not managed | `guardianctl update` on this workstation |
| Absent deadline policies were flagged *and* written every pass | The same run |
| `Response` could not serialize `Incidents` at all | A real IPC round trip |
| The accept timeout destroyed arriving connections | A sequential-request test |
| A second pipe instance could not be created without elevation | Bisecting an access-denied failure |
| `OpenEventLogW` silently opens a *different* log for a bogus channel | A channel-existence test |
| "Has a console" is not a valid service check | A test run with no console |
| A freshly dialled link was torn down and re-dialled forever on a filtered network | Running against this campus network |
| Backoff reset on every attempt, producing a dial loop | The same run |
| Log pruning could delete the live log | A bounds test |
