# Testing

## Running

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

Ordinary `cargo test` never reboots the machine, touches persistent update policy, disconnects a
real network link, installs anything, or stops a Windows service. That is a hard rule, not a
convention: a test suite that mutates the developer's machine is one that stops being run.

### Network-dependent tests

Five probe tests reach the real network and are `#[ignore]`d so `cargo test` stays fast and
deterministic. Run them explicitly when connectivity matters:

```bash
cargo test --workspace -- --ignored
```

### Destructive tests

Tests that would be destructive are marked `#[ignore]` **and** require an explicit opt-in
environment flag. None exist yet; the mechanism is in place for when they do.

## How the design makes testing possible

The safety-critical logic lives in `guardian-core`, which has no Win32, no I/O, and no ambient
globals. Effects are traits in `guardian-core::ports`, injected:

```
UpdatePolicyBackend   RasBackend (trait)   ProcessSource   ShutdownBackend
Clock                 Storage             EventLogSource   BootIdentity
```

So the state machines are tested by driving a fake clock and a scripted observation stream, which
means:

* the anti-flap behaviour of network failover is verified by advancing time, not by waiting on a
  real adapter that CI does not have;
* the single-use reboot capability is tested across simulated reboots, clock changes and crashes;
* agent confidence scoring runs against fixtures built from real process trees.

`guardian-win` is where the real APIs are exercised. Its tests run against the actual OS, which is
where several genuine defects were found (see below).

## Coverage by area

| Area | What is covered |
|---|---|
| Update protection | conformant host reports `Protected` with **zero writes**; unreadable policy is `Unknown` never `Protected`; a changed value is tamper-detected and restored; a failed write downgrades to `Unknown`; externally managed is `Degraded`; repeated read failures back off |
| Maintenance | entry refused with protected work; override requires the exact phrase; full `LOCKED→MAINTENANCE→UPDATE_PENDING→REBOOT_ARMED→BOOT→LOCKED` cycle; ordinary reboot never unlocks; expired permit rejected and disarmed; consumed permit cannot be reused; permit bound to a previous boot is invalidated; exit reapplies protection immediately |
| Reboot classification | clean vs unclean; `User32 1074` attributed to Windows Update only when the message says so; `Kernel-Power 41` does not invent a cause; no evidence yields `Unknown` |
| Network | a fresh dial is not torn down because probes fail; an established link that stops passing probes *is* demoted; backoff accumulates across repeated aborts; DNS-only failure never destroys a session; auth failure stops retrying; preference is derived; only one dial per evaluation; jitter is bounded |
| Agent detection | every required agent form; MCP helpers, unrelated `node`/`python`, editors and build tools are not agents; npm wrapper counted once; pipx console scripts detected; user signatures override built-ins; candidates never drive protection; PID reuse; missing command line |
| IPC | per-operation authorization; malformed frames answered not dropped; oversized frames rejected before allocation; a second request over one connection succeeds; a fresh instance accepts |
| Storage | atomic replacement; torn journal tail discarded; bit-flipped payload caught by checksum; rotation preserves the session identity; corrupt documents fall back to defaults |
| Config | bad config cannot disable protection; pathological regex rejected; unknown future fields preserved; validation is idempotent |
| Supervision | panicking worker restarted and recorded; a worker that returns is a failure; backoff bounded; a stale worker is reported degraded |

## Real-machine validation

`guardian-process/tests/real_machine.rs` enumerates the live process table and asserts *properties*
rather than counts, so it holds on a machine with no agents and on one running six. It never starts,
stops or signals a process — terminating a real agent session with hours of work in it is exactly
what this project exists to prevent.

Verified on the development machine: the detector reports exactly the agents Windows reports, with
their real project names, and no false positives.

## Defects found by testing

Recorded because they justify the approach — none of these were visible by reading the code.

| Defect | Found by |
|---|---|
| The pipe ACL was unusable, not merely tight: every client open was denied | Running an actual client against the server |
| `ConnectNamedPipe` ignores timeouts on a blocking pipe, so the accept loop could hang a shutdown | A test that hung |
| `REG_MULTI_SZ` decoding stopped at the first NUL, silently truncating multi-strings | Registry round-trip test |
| MDM detection reported a managed machine that was not managed | Running `guardianctl update` on a real workstation |
| Absent deadline policies were reported as hazards *and* written as zeros on every pass | The same run |
| `Response` could not serialize `Incidents` at all — serde cannot internally-tag a newtype variant holding a sequence | A real IPC round trip |
| The accept timeout destroyed arriving connections, which looked like Guardian dying | A sequential-request test |
| A second pipe instance could not be created by a non-elevated user | Bisecting an access-denied failure on the OS |
| `OpenEventLogW` silently opens a *different* log for a nonexistent channel | A channel-existence test |
| "Does the process have a console" is not a valid way to detect a service | A test run with no console |
| A freshly dialled link was torn down and re-dialled forever on a filtered network | Running against a real campus network |
| Backoff reset on every dial attempt, producing a dial loop at the initial interval | The same run |
| Log pruning could delete the live log file | A bounds test |

## What is deliberately not tested

* Anything requiring a real reboot, a real BSOD, or real power loss. The state machines model those
  transitions and are tested; causing them is not.
* Real Windows Update installation.
* Real Wi-Fi association changes.
