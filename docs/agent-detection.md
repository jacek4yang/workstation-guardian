# Agent detection

## The problem

There is no Windows flag meaning "this process is an AI coding agent". Agents ship as native
binaries, as Node packages, as Python packages, as Rust binaries, and as shell wrappers around all
of those. A detector that matches one executable name breaks the moment a different agent is
installed; one that calls every `node.exe` an agent is worse, because it blocks shutdown forever.

## The approach

Layered evidence with explicit confidence, driven by a **data** database rather than code.

```text
  process snapshot ──▶ weighted rule matching ──▶ score ──▶ confidence
         │                      │                              │
         │                veto rules                          │
         │                      │                              ▼
         └──▶ process graph ────┴──▶ session grouping ──▶ AgentInstance
```

A signature is regex rules over fields of a process snapshot — process name, image path, command
line, parent, children, package paths — each contributing a weight, plus optional veto rules and a
declared confidence cap.

Because the database is data, adding an agent or correcting a false positive is a configuration
edit, not a release.

## Confidence

| Level | Meaning | Triggers WORKING? |
|---|---|---|
| `Confirmed` | Specific, corroborated evidence | Yes |
| `High` | Strong specific evidence | Yes |
| `Possible` | Ambiguous evidence | **No** |
| `Unknown` | Weak signal; diagnostics only | No |

**`Possible` never blocks a shutdown.** This is the single most important rule in the detector: a
tool that holds your shutdown because you have an editor open is one you will uninstall.

A signature's declared confidence caps its result. A signature that ships as `Possible` — because
its evidence is inherently ambiguous, such as an editor that may be hosting an agent — can never
reach `Confirmed` no matter how much it matches.

## Session grouping

An agent and its descendants are one session:

```text
WindowsTerminal
└─ pwsh
   └─ node
      └─ Claude Code
         ├─ git
         ├─ cargo
         └─ rustc
```

Those children are **not** separate agents. They are protected *workloads* owned by the session,
which is what lets "cargo is running because Claude Code asked it to" be distinguished from "some
unrelated cargo is running".

### Wrapper resolution

An npm-launched agent appears as *two* matching processes: the interpreter whose command line names
the package, and the binary it spawns. Both legitimately match, so counting both would double every
such agent.

A matched process that has an at-least-as-strong matched **descendant** is suppressed as a launcher.
The rule is agent-agnostic: it knows nothing about which agent is which, only that a launcher and
the thing it launched are one agent.

## Built-in coverage

Claude Code (native and npm), Codex (native and npm), Grok Build (including its bundled launcher),
Gemini CLI, GitHub Copilot CLI, Aider (module and pipx console script), OpenCode, Goose, Amp, Qwen
Code, Cline CLI, and Cursor Agent.

Cline and Cursor Agent are capped at `Possible`: Cline usually runs inside an editor where there is
no separate process, and `Cursor.exe` is the editor and must never count as an agent.

## False positives this is designed to avoid

Verified against a real machine with agents running:

| Case | Result |
|---|---|
| Agent's own MCP helper (`python.exe .../ida_pro_mcp/server.py`) | Not an agent |
| Unrelated `node.exe` / `python.exe` | Not an agent |
| VS Code with no agent | Not an agent |
| Cursor editor with no agent | Not an agent |
| `cargo`, `rustc`, `cmake`, `ninja`, `msbuild` on their own | Not agents (workloads) |
| npm-launched agent | Counted once, not twice |
| Agent with ten children | One agent |

The veto rules that prevent the first two are applied to every interpreter-keyed signature, so no
individual entry can forget them.

## Adapters

Adapters read each agent's *own* session state for project and resume metadata.

**Another process's working directory is not read from its PEB.** That is undocumented and
version-fragile; project directories come from what each agent already records about itself.

| Agent | Source | Provides |
|---|---|---|
| Claude Code | `~/.claude/sessions/<pid>.json` | project, session id, resume hint |
| Grok | `~/.grok/active_sessions.json` | project, session id, resume hint |
| Codex | `~/.codex/sessions/.../rollout-*.jsonl` | project |

Claude Code's `procStart` field is a FILETIME matched against the live process creation time, which
defeats PID reuse: it is the difference between resuming the right session and resuming an unrelated
one.

Codex resume is reported unavailable, deliberately: the rollout file is not keyed by pid, so
Guardian cannot know that transcript belongs to the process it detected. Offering a resume it cannot
honour would be worse than offering none.

### Hard rules

An adapter may only read. It never modifies agent state, never reads credentials — Claude Code's
`.key` files hold a peer token and are never opened — never copies prompts or transcripts into logs
or persisted state, and never uploads anything.

Tests assert that a record containing a prompt, a transcript, an API key and a token cannot produce
adapter output containing any of them.

## Adding an agent

Two ways, neither requiring a release:

1. **Add a signature** to `agents.user_signatures` in the configuration. A user signature with the
   same id as a built-in *replaces* it, which is how a built-in is corrected.
2. **Promote a candidate.** Processes that matched some evidence but scored below the reporting bar
   appear in `guardianctl agents` and the UI as candidates, with the reason they looked agent-like.
   They never block shutdown.

Patterns are validated on load: length is capped, excessive nesting is rejected, and huge counted
repetition is rejected. A bad pattern is dropped with a warning rather than disabling detection.

## Protected workloads

Long-running development work is protected even without an agent, under configurable rules:

* `cargo`, `rustc`, `cmake`, `ninja`, `msbuild`, `dotnet build`, `make`, `gradle`, `webpack`.

A workload owned by an agent session is protected immediately, because the agent is waiting on it. A
**standalone** build must exceed a runtime threshold, and only some rules qualify standalone by
default.

Interpreters are deliberately not standalone workloads. A rule that matched every `node.exe` would
make every machine with a background process believe work is in progress, which blocks shutdown for
no reason and trains the operator to ignore the warning.

## Diagnostics

```powershell
guardianctl agents     # what was detected, with evidence
guardianctl doctor     # monitor health, rejected rules, near misses
```

A rejected rule is reported explicitly, so a broken pattern is visible rather than silently making
an agent undetectable.
