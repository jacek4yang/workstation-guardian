# Architecture

Workstation Guardian is a Windows service that owns protection, plus thin clients that observe
and request. The split is deliberate: protection must not depend on anything with a UI, a user
session, or a lifecycle shorter than the machine's.

```text
guardian-service.exe        Windows Service, LocalSystem — the authority
        │
        │  named pipe, closed protocol, per-operation authorization
        │
        ├── guardian-ui.exe       tray + control panel (Tauri v2)
        ├── guardian-session.exe  per-user shutdown blocker (tiny, native)
        └── guardianctl.exe       diagnostics and installation
```

## Crates

```text
crates/
  guardian-proto    versioned wire protocol and the shared data model
  guardian-core     pure state machines; no I/O, no Win32, no globals
  guardian-storage  atomic documents and a checksummed append-only journal
  guardian-win      the only crate containing unsafe; safe Win32 wrappers
  guardian-process  process graph, agent detection engine, signature database
  guardian-network  connectivity probes, RAS/Wi-Fi backend, the network worker
  guardian-update   Windows Update verification loop and tamper detection
  guardian-service  supervisor, state coordinator, IPC server, journal, logging
apps/
  guardian-session  shutdown blocker
  guardian-ui       Tauri tray and control panel
  guardianctl       diagnostics and installation
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

## Service lifecycle

### Startup

1. Load configuration. Corruption falls back to defaults, which **protect updates**, so a bad
   config cannot leave the machine unprotected.
2. Open the journal and determine whether the previous session ended cleanly — *before* anything
   writes to the journal, so the evidence is not overwritten.
3. **Apply update protection synchronously**, before any worker starts. A machine that is booting
   is exactly when an unexpected update restart is least welcome, so protection must not wait on
   the supervisor.
4. Start the supervised workers.
5. Serve IPC.

### Shutdown

The SCM control handler only sets flags; the main thread polls them. That is what lets a stop be
acknowledged promptly even while a worker is mid-task.

`SERVICE_ACCEPT_PRESHUTDOWN` is requested so Windows gives the service an early chance to flush
state. Preshutdown is treated as a *warning*, not a stop: the service keeps protecting until the
actual stop arrives, because ending protection several seconds early is exactly the window an
update could use.

On stop, the journal is flushed and the clean-shutdown marker written with a synchronous
`FlushFileBuffers`. That marker is the only thing that makes the next boot treat this one as
clean.

### Worker supervision

Each subsystem runs as its own supervised task:

* a panic is caught at the task boundary, recorded as an incident, and the worker restarted with
  bounded exponential backoff;
* a worker that **returns normally** is treated as a failure, because returning means a subsystem
  stopped protecting;
* after a budget of restarts the worker is marked `Failed` and reported as a degraded component,
  so the status surface never claims everything is fine;
* the supervisor itself never panics on a worker failure.

Panics are not globally swallowed. A panic is a bug; the supervisor's job is to keep the *service*
alive and make the bug loud.

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
  process on the other end" — indistinguishable from the service having died.

## Idle cost

Guardian is designed to run for months.

* No polling of processes at 100 ms; sweeps are every few seconds and event-driven where possible.
* No registry writes when policy already matches — a conformant machine gets **zero** writes per
  verification pass.
* No constant WMI full snapshots; the process inventory uses a toolhelp snapshot.
* No fsync without a changed state.
* The UI polls at 5 seconds and does nothing when its window is closed.
* Logs are bounded on disk; journals rotate.
