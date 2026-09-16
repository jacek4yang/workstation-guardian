# Recovery

## What this subsystem is for

On every start, determine whether the **previous** session ended cleanly. If it did not,
work may have been lost, and the operator deserves to know what was running and why it stopped.

That is the difference between "the machine rebooted overnight" and "your four agents were killed
at 03:14 by a Windows Update restart".

## The journal

An append-only file of length- and CRC-prefixed records:

```text
magic:u32 | length:u32 | crc32:u32 | payload
```

A torn tail — which is what power loss actually produces — fails the length or checksum check and
is **discarded**, not parsed as data. A corrupt journal degrades recovery information; it never
prevents the runtime from starting.

Record kinds: session start, checkpoint, mode change, policy tamper, shutdown observed, clean
shutdown, worker failure, network event.

### What a checkpoint contains

Boot id, session id, protection mode, update protection level, the agent inventory, the network
snapshot, and any live reboot authorization. Plus `protected_work_live`, which is what decides
whether the next boot's incident says any work was at risk.

### Durability

Routine checkpoints do not `fsync`: the data is visible to any reader, which fully covers a process
crash, and avoiding an fsync every few seconds matters over a machine's lifetime. Checkpoints are
written every 60s in `NORMAL` and every 15s in `WORKING`, where more is at stake.

The transitions an investigation depends on — mode changes, tamper, shutdown observed, clean
shutdown — are written **synchronously**.

### The clean-shutdown marker

Its presence is the only thing that makes the next boot treat this session as clean. It is written
from the runtime's stop path, with a synchronous flush.

An earlier revision had a subtle bug here worth recording, because it is the kind of thing that
would quietly destroy trust in the whole recovery report: journal rotation moved the session-start
record into the rotated file, so a later clean shutdown could no longer be paired with its session
and was misreported as a crash — after *every* rotation. The session identity is now carried into
the fresh file, with a regression test.

## Unexpected restart analysis

If the previous session wrote no clean marker, Guardian inspects the Windows Event Log around the
failure.

### Records and what they actually mean

| Record | What it proves |
|---|---|
| `User32` 1074 | A process *initiated* a shutdown. Names the process and, for restarts, the reason. The most informative record available. |
| `Kernel-Power` 41 | The system stopped without a clean shutdown. Proves *abruptness*, says nothing about *why*. |
| `EventLog` 6008 | The previous shutdown was unexpected. |
| `EventLog` 6006 | The event log service stopped cleanly. Absent means the stop was abrupt. |
| `EventLog` 6005 | The event log service started; marks the current boot. |
| `Kernel-General` 12/13 | OS start/stop. |
| `WindowsUpdateClient` | An update-related operation occurred. |

### Confidence ladder

```text
shutdown_initiated              → Confirmed     (someone requested it, and we know who)
abrupt                          → Likely        (we know how, not why)
event log service stopped cleanly → Likely      (the OS stopped orderly, our process did not)
nothing decisive                → Unknown       (we know it was not clean; that is all)
```

**Ambiguity is reported as ambiguity.** A `Kernel-Power 41` record is not evidence that Windows
Update did anything, and the report never says it was. When there is no usable evidence the
confidence is `Unknown` and the incident is still raised, because losing the fact that something
went wrong would be worse than reporting it vaguely.

## The incident

```text
Unexpected restart detected

time
previous boot id
likely initiator
reason
confidence
Windows Update related: yes/no/unknown
agents lost
protected jobs lost
last heartbeat
last network state
```

`agents lost` carries the project name and resume availability for each agent that was running, so
the recovery page can offer a resume.

**Resume is always an explicit user action.** Guardian never launches an agent for you.

```powershell
guardianctl incidents
```

## Failure classification and the event log

An event log query is bounded by a time window *and* a record cap. A machine that has been up for
months has hundreds of thousands of records; walking them would turn a boot-time diagnostic into a
multi-second stall.

If the log cannot be read at all, the incident is still raised with `Unknown` confidence. Partial
evidence with a stated gap is more useful than nothing.

## Event log channel existence

`OpenEventLogW` does **not** fail for a nonexistent channel on Windows 11. It silently returns a
handle to some other log — measured, a bogus name yielded 30317 records while `System` held 31662.

Reading without an existence check could therefore classify restart evidence drawn from an unrelated
log, which is worse than reporting nothing. Channel existence is established through
`EvtOpenChannelConfig`, which fails cleanly, and the read then uses the legacy API.

## Boot identity and authorization

The boot id is derived from `now − uptime`, rounded to the second. It changes on every boot, which
is what binds a single-use reboot authorization to exactly one boot: after a restart the id differs,
so a capability issued for the previous boot can never match.

A permit is invalidated on boot if its `issued_boot_id` differs from the current one, if it has been
consumed, or if it has expired. Invalidation is recorded as an incident rather than silently
dropped, so a permit that never got used is visible after the fact.

## Crash-loop visibility

Persistent state carries a `start_count`. A rising count with no intervening clean shutdown is
itself evidence of a crash loop, and worker failures are recorded with their restart count so a
component that keeps failing is visible rather than merely noisy.

## Corrupted state

| File | Corrupt behaviour |
|---|---|
| `config.json` | Quarantined, defaults used. Defaults **protect updates**. |
| `state.json` | Quarantined, defaults used, protection re-applied. |
| `journal.log` | Torn tail discarded; earlier records kept. |
| `incidents.json` | Quarantined; history is lost, protection is not. |

In every case the machine ends up protected. Losing diagnostics is a degradation; losing protection
is not acceptable.

Quarantined files are bounded to three, so a crash loop cannot fill the disk.
