# Security

Guardian's runtime runs as an **elevated user process**, not as `LocalSystem`. That is a
meaningful reduction in privilege, and the security story is simpler for it. The design question
is still how to keep the elevated runtime from becoming a way for an unprivileged local process to
act with administrator rights.

## Threat model

**In scope.** A non-administrator local process attempting to:
* make the runtime perform a privileged action;
* read information it should not;
* prevent protection from starting or continuing;
* cause the runtime to execute attacker-controlled code or paths.

**Out of scope.** An attacker who already has administrator rights. Guardian is not a defence
against a privileged adversary, and does not pretend to be. Nor is it a defence against a kernel
exploit, physical access, or a compromised signing chain.

## Why this is not running as LocalSystem

An earlier revision installed a Windows service running as `LocalSystem`. It was removed, for two
reasons:

* **It was not needed.** Update protection is a write to
  `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`. Administrators can write that key.
  `LocalSystem` was privilege the design did not require.
* **A permanent, self-restarting, fully privileged process is a liability.** It is the most
  attractive target on the machine and it runs whether or not anyone is using the computer.

What was given up is honest to state: there is no longer an SCM to restart Guardian after a crash,
and no preshutdown notification. The first is handled by the supervisor (see
[`architecture.md`](architecture.md)); the second is discussed there too, including what it costs.

## The IPC boundary

Three independent barriers, in the sense that defeating one does not defeat the others.

### 1. The pipe ACL

The named pipe is created with this security descriptor:

```text
D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;FRFW;;;IU)
```

* `SY` (LocalSystem) and `BA` (Administrators) get full access.
* `IU` (Interactive Users) get generic read and generic write.

The mask was determined **empirically**, not from reasoning about the bit names. Starting from a
minimal-looking mask, the first pipe instance could be created but the *second* failed with
`ERROR_ACCESS_DENIED`, and no individual added right fixed it — only generic read and write, which
is what a client needs anyway. This matters because a pipe server that cannot arm its next
listening instance serves exactly one client and then stops accepting.

What interactive users are **not** granted: `WRITE_DAC`, `WRITE_OWNER`, `DELETE`. A client cannot
re-ACL the pipe, take ownership of it, or delete it. Remote clients are rejected outright.

Note that the server process is elevated, but the *pipe* is not restricted to administrators: a
standard user can connect and read status. That is intentional — an operator diagnosing a machine
should not need elevation to ask what is happening. What they cannot do is send a request that
changes protection, because of the next barrier.

### 2. Derived principal

The runtime derives the caller's principal from the **connecting token**, never from anything on
the wire. A request that claims to be an administrator is an administrator only if its token says
so.

`ImpersonateNamedPipeClient` is deliberately **not** used. Impersonation changes the server
thread's security context, and a bug in the reversion path leaks a client's identity into
unrelated runtime work. Reading the token without impersonating gives the same information with
none of that risk.

Every request declares the minimum principal required to issue it, and the server re-checks that
on each call:

| Principal | May do |
|---|---|
| `InteractiveUser` | read status, agents, network, incidents, health; request a reconnect |
| `Administrator` | everything above, plus maintenance mode, arming a reboot, configuration |

A reconnect is available without elevation on purpose: reconnecting a dropped dial-up link has no
privilege impact, and it is the operation a user most often needs to be fast.

### 3. A closed protocol

There is no `RunCommand`, no `WriteRegistry`, no `LaunchAsSystem`, no path parameter that reaches
a filesystem operation. The runtime is a protection authority, not a remote-control facility.

This is the barrier that matters most in practice. Even a complete ACL failure would leave an
attacker with a set of named operations, none of which can execute anything or write anything
outside Guardian's own state.

## Path handling

Nowhere does the runtime accept a filesystem path from a client and act on it. The only paths the
runtime uses come from its own configuration file, which is written under `ProgramData` with
administrative access.

Configuration values that are paths are validated on load:
* must be absolute (drive-letter or UNC with both server and share);
* `..` is rejected;
* a relative path is rejected, because it would resolve against the runtime's working directory.

There is no service binary path to validate, because nothing hands a path to the SCM any more.
That removes a genuine privilege-escalation vector rather than defending against it.

## What is never stored or logged

* **The broadband password.** `RasDialW` is called with the entry name only; Windows supplies the
  stored credentials. Guardian never holds the secret, so it cannot leak it.
* **Wi-Fi keys.** Connecting uses the key Windows already has for the saved profile.
* **Agent API keys, tokens, prompts, transcripts.** Adapters read a whitelist of fields — a
  project path, a session handle — and a test asserts that a record containing secrets cannot
  produce output containing them.
* **Full process environments.**
* **Terminal output.**

Credentials that appear in log-bound strings are redacted by a narrow filter, and command lines
are truncated to a bounded prefix before being logged.

## Audit notes

Checked deliberately rather than assumed:

| Area | Finding |
|---|---|
| Pipe ACL | `WRITE_DAC`/`WRITE_OWNER`/`DELETE` withheld from interactive users; asserted by test |
| Pipe creation | Remote clients rejected |
| Client impersonation | Not used |
| Client identity | Derived from the token, not the request |
| Frame handling | Length validated *before* allocation, so a hostile client cannot make the runtime allocate an arbitrary amount |
| Malformed input | Produces an error response, never a panic |
| Command construction | No shell invocation anywhere in the workspace |
| Process launch | The runtime launches no processes, except `explorer.exe` for the tray's "open data folder" item, with a fixed argument and no shell |
| Persistence | Nothing is registered for autostart; the program is running or it is not |
| Config paths | Validated absolute, no `..` |
| Rollback metadata | Stored under `ProgramData`; used by `restore-policy` to restore exactly the values Guardian owned |

## Fail-closed behaviour

Protection never depends on any of the above succeeding:

* if the IPC server cannot start, update protection still applies;
* if a worker panics, it is restarted and reported; protection is unaffected;
* if the UI is closed, crashes, or never runs, nothing changes;
* if the configuration is corrupt, defaults are used, and the defaults protect updates;
* if the update policy cannot be read, protection is reported `Unknown` **and re-applied**.

The failure mode Guardian deliberately does not have is "something went wrong, so protection
silently stopped".
