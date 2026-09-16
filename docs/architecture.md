# Architecture

Workstation Guardian is a single elevated tray application that hosts the protection runtime in
its own process. There is no Windows service, nothing registered with the Service Control
Manager, and nothing left behind when it exits.

The runtime is deliberately *not* part of the UI's lifecycle. It runs on its own thread with its
own supervisor, so a crash in the webview, a hung panel, or an operator closing the window cannot
stop protection. That property is what the process layout has to preserve:

```text
guardian-ui.exe             elevated, one process — the program
        │
        ├── runtime thread  ── update protection, agent detection, network guardian,
        │   │                   recovery journal   (worker threads + supervisor)
        │   │
        │   └── named pipe, closed protocol, per-operation authorization
        │            │
        │            └── guardianctl.exe        diagnostics (any process, on demand)
        │
        └── window thread   ── tray icon + control panel (Tauri v2 / WebView2)
              reads the runtime's state in-process; does not depend on the pipe
```

`guardian-session.exe` runs separately in each interactive session. It must: a shutdown block is
per-session by nature, and a process in the runtime's elevated context cannot hold one for a user's
logon session.

## Crates

```text
crates/
  guardian-proto    versioned wire protocol, shared data model, bilingual text
  guardian-core     pure state machines; no I/O, no Win32, no globals
  guardian-storage  atomic documents and a checksummed append-only journal
  guardian-win      the only crate containing unsafe; safe Win32 wrappers
  guardian-process  process graph, agent detection engine, signature database
  guardian-network  connectivity probes, RAS/Wi-Fi backend, the network worker
  guardian-update   Windows Update verification loop and tamper detection
  guardian-service  the runtime: supervisor, state coordinator, IPC server, journal, logging
apps/
  guardian-ui       Tauri tray + control panel, and the host of the runtime
  guardian-session  per-user shutdown blocker
  guardianctl       diagnostics
```

### The dependency direction

```text
   guardian-proto  ◀── everything
   guardian-core   ◀── guardian-process, guardian-network, guardian-update
   guardian-win    ◀── guardian-process, guardian-network, guardian-update,
                      guardian-service, guardian-session, guardianctl
   guardian-service ◀── guardian-ui, guardian-session, guardianctl
```

`guardian-core` never depends on `guardian-win`. That is what makes the safety-critical logic
testable without a computer that can be rebooted, and it is enforced by the crate graph rather
than by convention.

### Why the runtime lives in a library, not in a binary

`guardian-service` exposes `runtime::run()`, which starts the workers and blocks until asked to
stop. Both hosts use it: the tray application for normal use, and the `guardian-service` console
binary for development and for observing the runtime without a GUI.

Keeping the runtime out of a `main()` is what makes the no-service design affordable. Hosting is a
thin concern — a Tauri builder, or a few lines of argument parsing — while the protection logic is
unchanged and still testable on its own.

## Why the state machines are pure

Every decision that matters is a pure function of `(state, observation, policy, time)`:

```rust
pub fn evaluate(
    state: &NetworkState,
    obs: &NetworkObservation,
    policy: &NetworkPolicy,
    now_ms: i64,
) -> NetworkTransition
```

Effects are expressed as data (`NetworkAction`) and performed by a thin adapter. The
consequences are concrete:

* the anti-flap behaviour of the network state machine is verified by tests that advance a fake
  clock, not by waiting on a real adapter that CI does not have;
* the maintenance machine's single-use reboot capability is tested across simulated reboots,
  clock changes, and crashes;
* agent confidence scoring is tested against fixtures built from real process trees.

`guardian-core` is `#![forbid(unsafe_code)]`. `guardian-win` is the only crate with `unsafe`, and
it is `#![deny(unsafe_op_in_unsafe_fn)]` with every unsafe operation individually justified.

## Runtime lifecycle

### Startup

1. Load configuration. Corruption falls back to defaults, which **protect updates**, so a bad
   config cannot leave the machine unprotected. On first run this also writes a default
   configuration and creates the data directory, so the operator has a real file to edit.
2. Open the journal and determine whether the previous session ended cleanly — *before* anything
   writes to the journal, so the evidence is not overwritten.
3. **Apply update protection synchronously**, before any worker starts. A machine that is booting
   is exactly when an unexpected update restart is least welcome, so protection must not wait on
   the supervisor.
4. Start the supervised workers.
5. Serve IPC, and hand the state handle to the host so the panel can read it in-process.

### Shutdown

Shutdown is requested from the tray menu or the panel, or by the console harness ending. Either
way it sets a flag that the runtime's control loop polls. That is what lets a stop be acknowledged
promptly even while a worker is mid-task, and what keeps the wait bounded: the host waits
`SHUTDOWN_GRACE` and then exits regardless, so an explicit exit is never hostage to a wedged
worker.

On stop, the journal is flushed and the clean-shutdown marker written with a synchronous
`FlushFileBuffers`. That marker is the only thing that makes the next start treat this one as
clean.

There is no `SERVICE_ACCEPT_PRESHUTDOWN` any more, and that is a real trade. A service could ask
Windows for an early warning before a shutdown; an ordinary process cannot. Guardian handles this
two ways instead: the journal is checkpointed on a timer (every 15 s in `WORKING`, every 60 s in
`NORMAL`), and `guardian-session.exe` holds the shutdown off in the interactive session. The
worst case is therefore losing up to one checkpoint interval of metadata — never the work itself,
which Guardian does not own.

### Worker supervision

Each subsystem runs as its own supervised task:

* a panic is caught at the task boundary, recorded as an incident, and the worker restarted with
  bounded exponential backoff;
* a worker that **returns normally** is treated as a failure, because returning means a subsystem
  stopped protecting;
* after a budget of restarts the worker is marked `Failed` and reported as a degraded component,
  so the status surface never claims everything is fine;
* the supervisor itself never panics on a worker failure.

Panics are not globally swallowed. A panic is a bug; the supervisor's job is to keep the *runtime*
alive and make the bug loud.

Supervision matters more in this design than it did with a service, not less. There is no SCM to
notice that Guardian died and restart it, so the supervisor is the only thing standing between a
bug in one worker and an unprotected machine. That is also why the panel does not share a thread
with the runtime.

## State and mode

`ServiceState` is the single shared snapshot. `ProtectionCoordinator` owns it and is the only
thing that mutates it.

The mode is **derived, never set by hand**:

```text
MAINTENANCE   when the maintenance machine is not LOCKED   (an explicit user decision)
WORKING       when protected work is live                  (from the agent inventory)
NORMAL        otherwise
```

Because it is derived, it cannot drift out of step with what is actually running. A user who
enters maintenance while agents run gets `MAINTENANCE`, and on exit the mode is re-derived from
the live inventory rather than defaulting to `NORMAL`.

### The one rule

`Protected` is reported only when every required check genuinely passed. Every other path —
a worker down, a policy read failure, external management, a configuration that disables
protection — resolves to `Degraded`, `Unknown` or `Unprotected`.

This is why restart protection reads `Degraded` when no session helper is connected: shutdown
blocking is a session-helper capability, and claiming `Protected` for a subsystem that cannot act
would be a lie.

## Persistence

```text
%ProgramData%\WorkstationGuardian\
  config.json        versioned, validated, unknown fields preserved
  state.json         durable state (atomic replacement)
  journal.log        append-only recovery journal (checksummed, rotating)
  incidents.json     incident history
  logs\guardian.log  structured logs, bounded on disk
```

### Why not SQLite

The needs are a handful of small documents, a bounded append-only record, and incident history.
There is no relational query, no concurrency beyond a single writer, and no transactions spanning
tables. An atomic file plus an append-only journal satisfies this with far less code, no C
dependency, and a recovery story readable in one sitting.

### Durability

* **Documents** — written to a sibling temp file, flushed, `sync_all`, then renamed over the
  target. On Windows that rename is atomic with respect to readers, so a crash leaves the old or
  the new document, never a mixture.
* **Journal** — records carry a length and a CRC-32. A torn tail, which is what power loss
  actually produces, fails the length or checksum check and is discarded rather than parsed as
  data.

Routine checkpoints do not `fsync`. The data is visible to any reader, which fully covers a
process crash, and avoiding an fsync every few seconds matters over a machine's lifetime. The
transitions an investigation depends on — mode changes, tamper, shutdown, clean-shutdown — are
written synchronously.

## IPC

A named pipe with a strict ACL and a **closed** protocol. See
[`security.md`](security.md) for the threat model.

Two design points worth stating here:

* **The client retries nothing the server should have got right.** An earlier revision had the
  client retry transport failures, which masked a server-side race that discarded arriving
  connections. The race is fixed at the source, and the client reports a genuine failure
  promptly.
* **The server keeps a spare listening instance armed** before serving the current one, and never
  disconnects a connection that has just arrived. A named pipe only accepts a connection while an
  instance is listening, so without this a second client arriving mid-serve is closed with "no
  process on the other end" — indistinguishable from Guardian having died.

The tray panel does not use this pipe. It reads the shared state directly, which means a panel
that is open, closed, hung, or crashed has no effect on whether `guardianctl` can diagnose the
machine.

## Idle cost

Guardian is designed to run for months.

* No polling of processes at 100 ms; sweeps are every few seconds and event-driven where possible.
* No registry writes when policy already matches — a conformant machine gets **zero** writes per
  verification pass.
* No constant WMI full snapshots; the process inventory uses a toolhelp snapshot.
* No fsync without a changed state.
* The panel is pushed to every 3 seconds while it is open, and does nothing at all while it is
  hidden. There is no polling timer in the frontend.
* Logs are bounded on disk; journals rotate.
