# Security

The service runs as `LocalSystem`. Everything here follows from that: it is the most privileged
process Guardian installs, and the design question is how to keep it from becoming a way for an
unprivileged local process to become `LocalSystem`.

## Threat model

**In scope.** A non-administrator local process attempting to:
* make the service perform a privileged action;
* read information it should not;
* prevent protection from starting or continuing;
* cause the service to execute attacker-controlled code or paths.

**Out of scope.** An attacker who already has administrator rights. Guardian is not a defence
against a privileged adversary, and does not pretend to be. Nor is it a defence against a kernel
exploit, physical access, or a compromised signing chain.

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

### 2. Derived principal

The service derives the caller's principal from the **connecting token**, never from anything on
the wire. A request that claims to be an administrator is an administrator only if its token says
so.

`ImpersonateNamedPipeClient` is deliberately **not** used. Impersonation changes the server
thread's security context, and a bug in the reversion path leaks a client's identity into
unrelated service work. Reading the token without impersonating gives the same information with
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
a filesystem operation. The service is a protection authority, not a remote-control facility.

This is the barrier that matters most in practice. Even a complete ACL failure would leave an
attacker with a set of named operations, none of which can execute anything or write anything
outside Guardian's own state.

## Path handling

Nowhere does the service accept a filesystem path from a client and act on it. The only paths the
service uses come from its own configuration file, which is written under `ProgramData` with
administrative access.

Configuration values that are paths are validated on load:
* must be absolute (drive-letter or UNC with both server and share);
* `..` is rejected;
* a relative path is rejected, because it would resolve against the service's working directory.

The service binary path, which the installer passes to the SCM to be executed as `LocalSystem`,
is validated before it is handed over: absolute, `.exe`, no shell metacharacters, and quoted if it
contains spaces. That is a genuine privilege-escalation vector otherwise.

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
| Frame handling | Length validated *before* allocation, so a hostile client cannot make the service allocate an arbitrary amount |
| Malformed input | Produces an error response, never a panic |
| Command construction | No shell invocation anywhere in the workspace |
| Process launch | The service launches no processes |
| Recovery actions | Service recovery is set to restart only; a reboot action is never configured, and a test asserts the constant |
| Service binary path | Validated before reaching the SCM |
| Config paths | Validated absolute, no `..` |
| Rollback metadata | Stored under `ProgramData`; used by uninstall to restore exactly the values Guardian owned |

## Fail-closed behaviour

Protection never depends on any of the above succeeding:

* if the IPC server cannot start, update protection still applies;
* if a worker panics, it is restarted and reported; protection is unaffected;
* if the UI is closed, crashes, or never runs, nothing changes;
* if the configuration is corrupt, defaults are used, and the defaults protect updates;
* if the update policy cannot be read, protection is reported `Unknown` **and re-applied**.

The failure mode Guardian deliberately does not have is "something went wrong, so protection
silently stopped".
