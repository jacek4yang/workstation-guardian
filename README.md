# Workstation Guardian

A Windows 11 workstation guardian that protects long-running development work from
unexpected Windows Update restarts, and keeps the network link available.

> **The machine may fail, but it must never silently lose work.**

---

## What Guardian protects

* **Automatic Windows Update reboots.** While Guardian is in `NORMAL` or `WORKING` mode,
  automatic update activity and automatic restarts are prevented through supported local
  policy (`NoAutoUpdate=1` and its supporting values). This is the primary protection.
* **Interactive shutdown.** While protected work is running, Guardian asks Windows to hold a
  normal shutdown or restart and shows the reason in the shutdown UI.
* **Your network link.** PPPoE/broadband is monitored and reconnected automatically, using
  the credentials Windows already has saved. Guardian never sees your password.
* **Recovery information.** If the machine does stop, Guardian records what was running so
  you know what was lost and can resume it.

## What Guardian cannot protect against

Stated plainly, because a protection tool that overstates itself is worse than none:

* **A forced shutdown** (`shutdown /f`), an administrative power action, or a policy-driven
  restart from an external authority.
* **A kernel fault, bugcheck, power loss, or hardware failure.**
* **Group Policy or MDM.** If your machine is domain-joined or MDM-enrolled, an organisation
  can override local policy. Guardian detects this, does not fight it, and reports update
  protection as **Degraded** rather than claiming a guarantee it cannot keep.
* **A sufficiently privileged attacker** with administrator rights on the machine.

Guardian's guarantee is narrower and more honest: *automatic Windows Update activity is
locked under Guardian-controlled local policy, and normal shutdown receives additional
protection while important work exists.* Where prevention is impossible, Guardian's recovery
metadata reduces the loss.

---

## Installation

### Requirements

* Windows 11 x64.
* Administrator rights to install (the service runs as `LocalSystem`).
* WebView2, which ships with Windows 11.

### Install

```powershell
# From an elevated prompt, in the directory containing the binaries:
.\guardianctl.exe install
```

This registers the service as an automatic-start service, configures SCM recovery so it
restarts itself if it fails (never a reboot action), writes a default configuration that
protects updates, starts the service, and verifies the result.

Then verify:

```powershell
.\guardianctl.exe doctor
```

### Optional: logon helper

`guardian-session.exe` must run in your interactive session to hold a shutdown block. Place a
shortcut to it in your Startup folder (`shell:startup`), or register it under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

If the helper is not running, Guardian reports **Restart Protection: Degraded** and continues
protecting updates exactly as before.

---

## Normal operation

Guardian has three states.

| State | Meaning |
|---|---|
| `NORMAL` | Updates locked, restart blocked, guardians active. |
| `WORKING` | As `NORMAL`, plus active development work detected, so shutdown protection is engaged and the journal checkpoints more often. |
| `MAINTENANCE` | Entered only by an explicit administrator action. Updates may be installed manually; an automatic restart is still never silently authorized. |

`WORKING` is *derived* from what is actually running. It is not a setting you have to
remember to turn on, and it cannot drift out of step with reality.

### Checking state

```powershell
guardianctl status          # human-readable
guardianctl status --json   # machine-readable
```

The tray icon shows the same information without opening anything. **Closing the control
panel hides it to the tray**; protection continues. **Exit UI** stops the panel only — the
service is unaffected, by design.

---

## Maintenance and updates

Windows Update stays locked until you unlock it deliberately.

1. Open the control panel and choose **Enter Maintenance Mode…**
2. If protected work is running, Guardian refuses. To proceed anyway you must type an exact
   confirmation phrase; the refusal lists every agent and build it found, with project names.
3. In maintenance, Windows Update may install.
4. To reboot, choose **Allow One Reboot**. This issues a single-use authorization with a
   nonce, an expiry (30 minutes by default), and a binding to the current boot.
5. One restart is allowed. The authorization is then **consumed** and cannot authorize a
   second restart, cannot survive into another boot, and expires on its own if unused.
6. After any boot, protection returns to `LOCKED` before steady state resumes.

**An ordinary reboot never unlocks updates.** If you restart for any unrelated reason,
Guardian comes back locked.

---

## PPPoE configuration

Guardian uses the RAS API directly and dials the phonebook entry **using the credentials
Windows already has stored**. It never asks for, holds, or logs your broadband password.

* If exactly one suitable broadband entry exists, it is selected automatically.
* If several exist, Guardian asks you to choose once and remembers it.
* On startup, if the link is down, Guardian dials automatically.
* If the link drops while you are working, Guardian reconnects with exponential backoff
  (immediate, 1s, 2s, 4s, 8s, 15s, 30s, 60s) with jitter.

### Broadband is always preferred; Wi-Fi is only a backup

When broadband is healthy it is the preferred route. If broadband drops, Guardian brings up
the configured Wi-Fi **first** so you stay online, and repairs PPPoE **in parallel** — it
never takes down your only working connection to retry the dial.

A successful dial is *not* recovery. Before traffic moves back to broadband, Guardian
requires the link to stay healthy through a stabilization window (DNS healthy, several
independent probes passing, stable for 10–30 seconds). If broadband keeps failing right after
being promoted, that window widens automatically. A link that flaps is not trusted.

A DNS-only failure never destroys a working PPPoE session.

### Checking the network

```powershell
guardianctl network
```

---

## Agent detection

Guardian detects AI coding agents generically, using layered evidence rather than a list of
executable names. It reports a confidence with each detection:

| Confidence | Meaning | Triggers shutdown protection? |
|---|---|---|
| `Confirmed` | Specific, corroborated evidence. | Yes |
| `High` | Strong specific evidence. | Yes |
| `Possible` | Ambiguous evidence (an editor that *might* host an agent). | **No** |
| `Unknown` | Weak signal, reported in diagnostics only. | No |

Deliberately, **`Possible` never blocks a shutdown.** A detector that blocks your shutdown
because you have an editor open is worse than useless.

Built-in signatures cover Claude Code (native and npm), Codex (native and npm), Grok Build,
Gemini CLI, GitHub Copilot CLI, Aider (module and pipx script), OpenCode, Goose, Amp, Qwen
Code, Cline CLI and Cursor Agent.

### False positives this is designed to avoid

Verified against a real machine with agents running:

* an agent's own **MCP helper** processes are not counted as agents;
* unrelated `node.exe` and `python.exe` are not agents;
* VS Code and Cursor with no agent running are not agents;
* `cargo`, `rustc`, `cmake`, `ninja` and `msbuild` are protected *workloads*, not agents;
* an npm-launched agent counts once, not twice (the launcher and the agent it spawns).

### Adding an agent without recompiling

The signature database is data. A signature has regex rules over the process name, image path,
command line, parent, children, and package paths, each contributing a weight, plus optional
veto rules and a confidence cap. Add one to `agents.user_signatures` in the configuration, or
promote a candidate that Guardian reports as `Possible`.

To see why something was or was not detected:

```powershell
guardianctl agents
guardianctl doctor
```

### What Guardian never does

It never reads your prompts, never reads API keys, never copies conversation content into
logs, and never uploads anything. It reads only the small session records agents write about
themselves, and only the fields it needs.

---

## Recovery after an unexpected reboot

On every start, Guardian determines whether the previous session ended cleanly. If it did not:

* it inspects the Windows Event Log around the failure;
* it classifies the cause where the evidence supports it, and says **Unknown** where it does
  not — it never invents a cause;
* it reports which agents and protected builds were running, with project names;
* where an agent records resume information, it offers it.

```powershell
guardianctl incidents
```

**Resume is always an explicit action you take.** Guardian never launches an agent for you.

---

## Diagnostics

```powershell
guardianctl status          # overall state
guardianctl agents          # detected agents and protected workloads
guardianctl network         # PPPoE and Wi-Fi state, outage history
guardianctl update          # Windows Update policy detail
guardianctl incidents       # recorded incidents, newest first
guardianctl doctor          # full sweep of every subsystem
guardianctl doctor --json   # the same, machine-readable
```

None of these require PowerShell, `reg.exe`, or `sc.exe`.

`guardianctl doctor` works **without the service running**, which is exactly when you need it.
It checks service installation and reachability, session helper, IPC, Windows Update policy,
conflicting external policy, pending reboot, RAS entries, entry selection, connectivity probes,
process monitor, storage and journal health, log health, elevation, and current mode.

---

## Uninstallation

```powershell
# From an elevated prompt:
.\guardianctl.exe uninstall
```

This stops and removes the service, then restores **only the policy values Guardian itself
recorded setting**. Values belonging to Group Policy or MDM are never touched, because
Guardian never recorded owning them.

* Uninstall **never reboots** the machine.
* `--keep-policy` leaves update policy in place if you want it to stay locked.
* State and logs remain under `%ProgramData%\WorkstationGuardian` for inspection; delete that
  directory to remove them.

---

## Command-line reference

```text
guardianctl <command> [--json] [options]

  status        Overall protection, network and agent state
  agents        Detected AI coding agents and protected workloads
  network       PPPoE and Wi-Fi state, including outage history
  update        Windows Update protection state and policy detail
  incidents     Recorded incidents, newest first
  doctor        Full diagnostic sweep of every subsystem
  install       Install the service and supporting components
  uninstall     Remove the service and report policy restoration
  start         Start the service
  stop          Stop the service

  --json        Machine-readable output
  --limit <n>   Maximum incidents to show (default 50)
  --force       Reinstall even if already installed
  --keep-policy Leave update policy in place when uninstalling
```

Stopping the service requires an explicit administrative action. Nothing in the UI can stop it,
and **Exit UI** affects only the panel.

---

## Where things live

```text
%ProgramData%\WorkstationGuardian\
  config.json        validated, versioned configuration
  state.json         durable state (atomic replacement)
  journal.log        append-only recovery journal (checksummed, rotating)
  incidents.json     incident history
  logs\guardian.log  structured logs, bounded on disk
```

Logs are redacted and bounded. They never contain credentials, tokens, prompts, or full
process environments.

---

## Further reading

* [`docs/architecture.md`](docs/architecture.md) — how the components fit together
* [`docs/security.md`](docs/security.md) — the threat model and the IPC design
* [`docs/update-protection.md`](docs/update-protection.md) — exactly which policy is set, and why
* [`docs/agent-detection.md`](docs/agent-detection.md) — how detection and confidence work
* [`docs/network-recovery.md`](docs/network-recovery.md) — the failover and reconnect policy
* [`docs/recovery.md`](docs/recovery.md) — the journal and unexpected-restart analysis
* [`docs/testing.md`](docs/testing.md) — what is tested, and how to run it
