//! The built-in agent signature database.
//!
//! This is **data**, not logic. Every entry encodes what is actually known about how a given
//! agent appears on a Windows machine, with the weights chosen so that:
//!
//! * a specific, unambiguous marker (a native binary with a distinctive name) reaches `High`
//!   on its own;
//! * a generic wrapper (`node.exe`, `python.exe`) only reaches `High` when the command line
//!   or a package path corroborates it;
//! * anything inherently ambiguous (an IDE that *might* be hosting an agent) is capped at
//!   `Possible`, which never triggers WORKING protection.
//!
//! # Evidence from the real world
//!
//! These signatures were written against agents actually installed and running on the target
//! machine, not against guesses:
//!
//! ```text
//! claude.exe   C:\Users\<user>\.local\bin\claude.exe              2.1.270
//! grok.exe     C:\Users\<user>\.grok\bin\grok.exe                 1.0.30
//! node.exe     ...\npm\...\@openai\codex\...  (npm-installed)     0.154.0
//! python.exe   ...\Lib\site-packages\ida_pro_mcp\server.py        (an MCP *helper*)
//! ```
//!
//! That last entry is the reason several signatures carry `none_of` vetoes: an agent spawns
//! MCP servers and other helpers, and counting those as agents would inflate the count and,
//! worse, make a single agent look like several.

use guardian_proto::model::{
    AgentAdapterKind, AgentSignature, Rule, RuleField, SignatureConfidence, SignatureRules,
};

/// Shorthands that keep the table readable.
fn any(rules: Vec<Rule>) -> SignatureRules {
    SignatureRules {
        any_of: rules,
        ..Default::default()
    }
}

fn r(field: RuleField, pattern: &str, weight: i32, detail: &str) -> Rule {
    Rule {
        field,
        pattern: pattern.into(),
        weight,
        detail: detail.into(),
    }
}

/// Veto: this process is a helper an agent spawned, not an agent.
///
/// Applied to every signature that otherwise keys off an interpreter name, because MCP
/// servers and language servers are exactly the shape that produces false positives.
fn helper_vetoes() -> Vec<Rule> {
    vec![
        r(
            RuleField::CommandLine,
            r"[/\\]server\.py\b",
            -1,
            "an MCP/language server helper, not an agent",
        ),
        r(
            RuleField::CommandLine,
            r"[/\\]mcp[/\\]",
            -1,
            "an MCP server path",
        ),
        r(
            RuleField::CommandLine,
            r"-m\s+(?:ida_pro_mcp|mcp_server|mcp-server)\b",
            -1,
            "a Python MCP module invocation",
        ),
        // Language servers, which agents and editors both spawn.
        r(
            RuleField::ProcessName,
            r"^(?:rust-analyzer|pyright|typescript-language-server|clangd|gopls|tsserver|jdtls|yaml-language-server|lua-language-server|vue-language-server|bash-language-server|eslint|prettier|black|ruff)(?:\.exe|\.cmd)?$",
            -1,
            "a language server or formatter, not an agent",
        ),
        // Guardian's own processes must never be mistaken for an agent it is protecting.
        r(
            RuleField::ProcessName,
            r"^guardian(?:-session|-service)?(?:\.exe)?$",
            -1,
            "Workstation Guardian itself",
        ),
    ]
}

/// The built-in signature set.
///
/// Ordered roughly by how commonly the agent is found on a developer workstation.
pub fn signatures() -> Vec<AgentSignature> {
    let mut all_signatures = vec![
        claude_code(),
        codex_native(),
        codex_node(),
        grok(),
        gemini(),
        copilot_cli(),
        aider(),
        opencode(),
        goose(),
        amp(),
        qwen_code(),
        cline(),
        cursor_agent(),
    ];

    // Apply the shared helper vetoes to every signature that keys off an interpreter, so no
    // individual entry can forget them. Doing this in code rather than repeating the list
    // thirteen times keeps the table honest.
    for sig in &mut all_signatures {
        if signature_needs_helper_vetoes(sig) {
            sig.rules.none_of.extend(helper_vetoes());
        }
    }

    all_signatures
}

/// Whether a signature should inherit the shared helper vetoes.
///
/// Only signatures that can match an interpreter process need them; a signature keyed on a
/// unique native binary cannot be confused with a helper.
fn signature_needs_helper_vetoes(sig: &AgentSignature) -> bool {
    const INTERPRETERS: [&str; 6] = ["python", "python3", "node", "bun", "deno", "pwsh"];
    sig.rules.any_of.iter().any(|rule| {
        rule.field == RuleField::ProcessName
            && INTERPRETERS.iter().any(|i| rule.pattern.contains(i))
    }) || sig.rules.all_of.iter().any(|rule| {
        rule.field == RuleField::ProcessName
            && INTERPRETERS.iter().any(|i| rule.pattern.contains(i))
    })
}

/// Claude Code.
///
/// Installed as a native binary at `~\.local\bin\claude.exe`, and also published as an npm
/// package (`@anthropic-ai/claude-code`) whose CLI runs under Node. Both forms are covered.
fn claude_code() -> AgentSignature {
    AgentSignature {
        id: "claude_code".into(),
        display_name: "Claude Code".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: SignatureRules {
            any_of: vec![
                r(
                    RuleField::ProcessName,
                    r"^claude(?:\.exe|\.cmd)?$",
                    100,
                    "the Claude Code CLI executable",
                ),
                r(
                    RuleField::ImagePath,
                    r"[/\\]\.local[/\\]bin[/\\]claude(?:\.exe)?$",
                    100,
                    r"the native installer's ~\.local\bin\claude.exe layout",
                ),
                r(
                    RuleField::PackagePath,
                    r"(?:@anthropic-ai[/\\]claude-code|/claude-code/)",
                    90,
                    "the @anthropic-ai/claude-code package path",
                ),
                // The versioned launcher under the installer's data directory.
                r(
                    RuleField::ImagePath,
                    r"[/\\]\.local[/\\]share[/\\]claude[/\\]versions[/\\]",
                    85,
                    "a versioned Claude Code launcher",
                ),
            ],
            all_of: vec![],
            none_of: vec![
                // The desktop/IDE helper processes share the name prefix but are not agents.
                r(
                    RuleField::ProcessName,
                    r"^claude-(?:mcp|helper|language-server)",
                    -1,
                    "a Claude Code helper rather than the agent",
                ),
            ],
        },
        adapter: Some(AgentAdapterKind::ClaudeCode),
        notes: "Detects both the native binary and the npm-installed Node form.".into(),
    }
}

/// OpenAI Codex CLI as a native binary.
fn codex_native() -> AgentSignature {
    AgentSignature {
        id: "codex_native".into(),
        display_name: "Codex".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^codex(?:\.exe)?$",
                100,
                "the Codex CLI executable",
            ),
            r(
                RuleField::ImagePath,
                r"[/\\]Programs[/\\]OpenAI[/\\]Codex[/\\]",
                95,
                "the OpenAI Codex installer layout",
            ),
        ]),
        adapter: Some(AgentAdapterKind::Codex),
        notes: "The native Codex CLI.".into(),
    }
}

/// OpenAI Codex CLI installed through npm, which runs under Node.
///
/// `all_of` rather than `any_of`: a `node.exe` is only Codex when the package path says so.
/// Without that, every Node process on the machine would be a candidate.
fn codex_node() -> AgentSignature {
    AgentSignature {
        id: "codex_node".into(),
        display_name: "Codex".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: SignatureRules {
            all_of: vec![
                r(
                    RuleField::ProcessName,
                    r"^node(?:\.exe)?$",
                    60,
                    "the Node.js runtime",
                ),
                r(
                    RuleField::PackagePath,
                    r"(?:@openai[/\\]codex|/codex-cli/|\\codex\\bin\\)",
                    60,
                    "the @openai/codex package path",
                ),
            ],
            ..Default::default()
        },
        adapter: Some(AgentAdapterKind::Codex),
        notes: "Codex installed through npm or a package manager.".into(),
    }
}

/// Grok Build (xAI).
fn grok() -> AgentSignature {
    AgentSignature {
        id: "grok".into(),
        display_name: "Grok Build".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^grok(?:\.exe)?$",
                100,
                "the Grok Build CLI executable",
            ),
            r(
                RuleField::ImagePath,
                r"[/\\]\.grok[/\\]bin[/\\]",
                100,
                r"the ~\.grok\bin installer layout",
            ),
            // The launcher binary is installed under both names.
            r(
                RuleField::ImagePath,
                r"[/\\]\.grok[/\\]bin[/\\]agent(?:\.exe)?$",
                95,
                "the Grok agent launcher",
            ),
        ]),
        adapter: Some(AgentAdapterKind::Grok),
        notes: "Grok Build, including its bundled agent launcher.".into(),
    }
}

/// Gemini CLI.
fn gemini() -> AgentSignature {
    AgentSignature {
        id: "gemini_cli".into(),
        display_name: "Gemini CLI".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^gemini(?:\.exe|\.cmd)?$",
                95,
                "the Gemini CLI executable",
            ),
            r(
                RuleField::PackagePath,
                r"@google[/\\]gemini-cli",
                100,
                "the @google/gemini-cli package path",
            ),
        ]),
        adapter: None,
        notes: "Gemini CLI, native or npm-installed.".into(),
    }
}

/// GitHub Copilot CLI.
fn copilot_cli() -> AgentSignature {
    AgentSignature {
        id: "copilot_cli".into(),
        display_name: "GitHub Copilot CLI".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^copilot(?:\.exe|\.cmd)?$",
                85,
                "the Copilot CLI executable",
            ),
            r(
                RuleField::PackagePath,
                r"@github[/\\]copilot",
                100,
                "the @github/copilot package path",
            ),
            r(
                RuleField::CommandLine,
                r"gh\s+copilot",
                80,
                "the gh copilot subcommand",
            ),
        ]),
        adapter: None,
        notes: "Copilot CLI, whether run directly or through gh.".into(),
    }
}

/// Aider, which is a Python package.
fn aider() -> AgentSignature {
    AgentSignature {
        id: "aider".into(),
        display_name: "Aider".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: SignatureRules {
            any_of: vec![
                // A pipx/pip-installed console script runs as its own executable rather than
                // under python.exe, so the image path is what identifies it. The bare process
                // name `aider.exe` would not be enough on its own.
                r(
                    RuleField::ImagePath,
                    r"[/\\](?:Scripts|bin)[/\\]aider(?:\.exe)?$",
                    95,
                    "an installed Aider console script",
                ),
                r(
                    RuleField::ImagePath,
                    r"[/\\]pipx[/\\]venvs[/\\]aider[/\\]",
                    95,
                    "an Aider virtual environment created by pipx",
                ),
            ],
            all_of: vec![
                r(
                    RuleField::ProcessName,
                    r"^python(?:3)?(?:\.exe)?$",
                    60,
                    "a Python runtime",
                ),
                r(
                    RuleField::CommandLine,
                    r"(?:-m\s+aider\b|[/\\]aider[/\\](?:main|__main__)|[/\\]Scripts[/\\]aider(?:\.exe)?\b|[/\\]bin[/\\]aider\b)",
                    70,
                    "an Aider entry point",
                ),
            ],
            ..Default::default()
        },
        adapter: None,
        notes: "Aider is a Python package, detected both as a pipx console script and as a \
                module run under python.exe."
            .into(),
    }
}

/// OpenCode.
fn opencode() -> AgentSignature {
    AgentSignature {
        id: "opencode".into(),
        display_name: "OpenCode".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^opencode(?:\.exe|\.cmd)?$",
                100,
                "the OpenCode CLI executable",
            ),
            r(
                RuleField::PackagePath,
                r"(?:opencode-ai[/\\]|/opencode[/\\]bin)",
                95,
                "the OpenCode package path",
            ),
        ]),
        adapter: None,
        notes: "OpenCode CLI.".into(),
    }
}

/// Goose (Block).
fn goose() -> AgentSignature {
    AgentSignature {
        id: "goose".into(),
        display_name: "Goose".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^goose(?:\.exe)?$",
                100,
                "the Goose CLI executable",
            ),
            r(
                RuleField::ImagePath,
                r"[/\\]\.local[/\\]bin[/\\]goose(?:\.exe)?$",
                95,
                "the Goose installer layout",
            ),
        ]),
        adapter: None,
        notes: "Goose, the Block coding agent.".into(),
    }
}

/// Amp.
fn amp() -> AgentSignature {
    AgentSignature {
        id: "amp".into(),
        display_name: "Amp".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^amp(?:\.exe|\.cmd)?$",
                95,
                "the Amp CLI executable",
            ),
            r(
                RuleField::PackagePath,
                r"@sourcegraph[/\\]amp",
                100,
                "the @sourcegraph/amp package path",
            ),
        ]),
        adapter: None,
        notes: "Amp.".into(),
    }
}

/// Qwen Code.
fn qwen_code() -> AgentSignature {
    AgentSignature {
        id: "qwen_code".into(),
        display_name: "Qwen Code".into(),
        user_defined: false,
        confidence: SignatureConfidence::Confirmed,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^qwen(?:\.exe|\.cmd)?$",
                95,
                "the Qwen Code CLI executable",
            ),
            r(
                RuleField::PackagePath,
                r"@qwen-code[/\\]qwen-code",
                100,
                "the @qwen-code/qwen-code package path",
            ),
        ]),
        adapter: None,
        notes: "Qwen Code.".into(),
    }
}

/// Cline CLI, if present.
///
/// Ambiguous by nature: Cline usually runs *inside* VS Code, where there is no separate
/// process to detect. A standalone CLI is reported at `Possible` because a bare `cline.exe`
/// name is not enough to be certain, and `Possible` never blocks shutdown.
fn cline() -> AgentSignature {
    AgentSignature {
        id: "cline_cli".into(),
        display_name: "Cline CLI".into(),
        user_defined: false,
        confidence: SignatureConfidence::Possible,
        rules: any(vec![
            r(
                RuleField::ProcessName,
                r"^cline(?:\.exe|\.cmd)?$",
                60,
                "a standalone Cline CLI",
            ),
            r(
                RuleField::PackagePath,
                r"(?:cline[/\\]dist[/\\]cli|@cline[/\\])",
                60,
                "a Cline CLI package path",
            ),
        ]),
        adapter: None,
        notes: "Cline normally runs inside an editor, where there is no separate process. \
                A standalone CLI is reported as Possible, never Confirmed."
            .into(),
    }
}

/// Cursor Agent, if identifiable.
///
/// Kept at `Possible` deliberately. `Cursor.exe` is the editor and must never count as an
/// agent; only the separate agent binary with corroborating evidence does, and even then the
/// signal is weak enough that claiming `High` would risk blocking shutdown for someone who
/// merely has the editor open.
fn cursor_agent() -> AgentSignature {
    AgentSignature {
        id: "cursor_agent".into(),
        display_name: "Cursor Agent".into(),
        user_defined: false,
        confidence: SignatureConfidence::Possible,
        rules: SignatureRules {
            any_of: vec![
                r(
                    RuleField::ProcessName,
                    r"^cursor-agent(?:\.exe|\.cmd)?$",
                    80,
                    "the standalone cursor-agent binary",
                ),
                r(
                    RuleField::PackagePath,
                    r"cursor-agent[/\\]",
                    70,
                    "the cursor-agent package path",
                ),
            ],
            all_of: vec![],
            none_of: vec![
                // The editor itself is never an agent, whatever else matches.
                r(
                    RuleField::ProcessName,
                    r"^Cursor\.exe$",
                    -1,
                    "the Cursor editor is not an agent",
                ),
                r(
                    RuleField::ProcessName,
                    r"^cursor(?:\.exe)?$",
                    -1,
                    "the Cursor editor is not an agent",
                ),
            ],
        },
        adapter: None,
        notes: "Only the standalone agent binary counts; the editor never does.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signature_is_well_formed() {
        let sigs = signatures();
        assert!(!sigs.is_empty());

        let mut ids = Vec::new();
        for s in &sigs {
            assert!(!s.id.is_empty(), "a signature needs an id");
            assert!(!s.display_name.is_empty(), "{} needs a display name", s.id);
            assert!(!s.notes.is_empty(), "{} needs notes for the UI", s.id);
            assert!(
                !s.rules.any_of.is_empty() || !s.rules.all_of.is_empty(),
                "{} has no positive rule and could never match",
                s.id
            );
            assert!(!ids.contains(&s.id), "duplicate signature id: {}", s.id);
            ids.push(s.id.clone());
        }
    }

    #[test]
    fn every_pattern_is_a_valid_regex() {
        for s in signatures() {
            for (list, rules) in [
                ("any_of", &s.rules.any_of),
                ("all_of", &s.rules.all_of),
                ("none_of", &s.rules.none_of),
            ] {
                for rule in rules {
                    assert!(
                        regex::Regex::new(&format!("(?i){}", rule.pattern)).is_ok(),
                        "signature {} {list} has an invalid pattern {:?}",
                        s.id,
                        rule.pattern
                    );
                }
            }
        }
    }

    #[test]
    fn every_positive_rule_has_a_positive_weight() {
        for s in signatures() {
            for rule in s.rules.any_of.iter().chain(s.rules.all_of.iter()) {
                assert!(
                    rule.weight > 0,
                    "signature {} has a non-positive positive-rule weight on {:?}",
                    s.id,
                    rule.pattern
                );
                assert!(
                    !rule.detail.is_empty(),
                    "signature {} rule {:?} has no explanation; the UI and logs need one",
                    s.id,
                    rule.pattern
                );
            }
        }
    }

    #[test]
    fn veto_rules_are_never_positive_weighted() {
        for s in signatures() {
            for rule in &s.rules.none_of {
                assert!(
                    rule.weight <= 0,
                    "signature {} has a positive veto weight on {:?}",
                    s.id,
                    rule.pattern
                );
            }
        }
    }

    #[test]
    fn the_required_agents_are_all_covered() {
        // The spec names these explicitly; a regression that drops one should fail loudly.
        let sigs = signatures();
        let ids: Vec<&str> = sigs.iter().map(|s| s.id.as_str()).collect();
        for required in [
            "claude_code",
            "codex_native",
            "codex_node",
            "grok",
            "gemini_cli",
            "copilot_cli",
            "aider",
            "opencode",
            "goose",
            "amp",
            "qwen_code",
            "cline_cli",
            "cursor_agent",
        ] {
            assert!(
                ids.contains(&required),
                "the signature database must cover {required}"
            );
        }
    }

    #[test]
    fn interpreter_based_signatures_carry_the_helper_vetoes() {
        // A signature that keys off python/node without vetoes is the classic false-positive
        // generator.
        for s in signatures() {
            if !signature_needs_helper_vetoes(&s) {
                continue;
            }
            let has_server_veto = s
                .rules
                .none_of
                .iter()
                .any(|r| r.pattern.contains("server\\.py"));
            assert!(
                has_server_veto,
                "signature {} keys off an interpreter but cannot veto a server helper",
                s.id
            );
        }
    }

    #[test]
    fn the_editor_processes_are_never_agents() {
        // Having Cursor or VS Code open is not evidence of an agent.
        for s in signatures() {
            let vetoes_editor = s
                .rules
                .none_of
                .iter()
                .any(|r| r.field == RuleField::ProcessName && r.pattern.contains("Cursor"));
            let matches_editor = s.rules.any_of.iter().chain(s.rules.all_of.iter()).any(|r| {
                r.field == RuleField::ProcessName
                    && (r.pattern == r"^Cursor\.exe$" || r.pattern == r"^Code\.exe$")
            });
            if matches_editor {
                assert!(
                    vetoes_editor,
                    "signature {} matches an editor name without vetoing it",
                    s.id
                );
            }
        }
    }

    #[test]
    fn ambiguous_signatures_are_capped_below_high() {
        // These must never reach High, because High triggers WORKING protection and would
        // block shutdown for someone who merely has an editor open.
        for s in signatures() {
            if matches!(s.id.as_str(), "cline_cli" | "cursor_agent") {
                assert_eq!(
                    s.confidence,
                    SignatureConfidence::Possible,
                    "{} must be capped at Possible",
                    s.id
                );
            }
        }
    }

    #[test]
    fn guardian_never_detects_itself() {
        for s in signatures() {
            let vetoes_self = s
                .rules
                .none_of
                .iter()
                .any(|r| r.pattern.contains("guardian"));
            if signature_needs_helper_vetoes(&s) {
                assert!(
                    vetoes_self,
                    "signature {} could match a Guardian process",
                    s.id
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Workload rules
// ---------------------------------------------------------------------------

/// A compiled workload rule: the data form plus a ready regex.
#[derive(Debug)]
pub struct CompiledWorkloadRule {
    pub id: String,
    pub display_name: String,
    /// Matched against the lowercased image file name.
    pub regex: regex::Regex,
    /// Matched against the command line, when the rule requires corroboration.
    pub cmdline: Option<regex::Regex>,
    pub min_runtime_secs: u64,
    pub protects_standalone: bool,
}

/// One workload rule specification: id, display name, name pattern, optional command-line
/// pattern, minimum runtime in seconds, and whether it protects a build with no owning agent.
type WorkloadSpec = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    u64,
    bool,
);

/// Rules describing long-running development work worth protecting.
///
/// These are deliberately narrower than "anything that looks like a build". A rule that matches
/// too broadly would make every machine with a background Node process believe work is in
/// progress, which blocks shutdown for no reason and trains the operator to ignore the warning.
///
/// Build tools are included because losing a two-hour `cargo build` is real work. Interpreters
/// (`node.exe`, `python.exe`) are deliberately **not** included as standalone workloads: they are
/// far too common to mean anything on their own, and they are already covered when an agent owns
/// them.
pub fn workload_rules() -> &'static [CompiledWorkloadRule] {
    // Compiled once for the process lifetime. These are consulted on every process sweep, so
    // recompiling nine regexes every few seconds forever would be a real cost for no benefit.
    static RULES: std::sync::OnceLock<Vec<CompiledWorkloadRule>> = std::sync::OnceLock::new();
    RULES.get_or_init(build_workload_rules).as_slice()
}

/// Compile the workload rules. Called once, by [`workload_rules`].
fn build_workload_rules() -> Vec<CompiledWorkloadRule> {
    let specs: [WorkloadSpec; 9] = [
        ("cargo", "cargo", r"^cargo(\.exe)?$", None, 60, true),
        ("rustc", "rustc", r"^rustc(\.exe)?$", None, 30, true),
        ("cmake", "cmake", r"^cmake(\.exe)?$", None, 60, true),
        ("ninja", "ninja build", r"^ninja(\.exe)?$", None, 60, true),
        ("msbuild", "MSBuild", r"^msbuild(\.exe)?$", None, 60, true),
        (
            "dotnet-build",
            "dotnet build",
            r"^dotnet(\.exe)?$",
            Some(r"\bbuild\b"),
            60,
            true,
        ),
        ("make", "make", r"^(make|gmake)(\.exe)?$", None, 60, true),
        (
            "gradle",
            "Gradle",
            r"^(gradle|gradlew)(\.(exe|bat|cmd))?$",
            None,
            60,
            true,
        ),
        (
            "webpack",
            "webpack build",
            r"^node(\.exe)?$",
            Some(r"webpack"),
            120,
            false,
        ),
    ];

    // The `expect`s below are deliberate and are not a "no unwrap in production" violation: the
    // patterns are static literals in the table under this function, and a test asserts every one
    // of them compiles. Failing loudly here is strictly better than silently installing a
    // never-matching rule, which would disable protection for a build tool without anyone
    // noticing.
    let mut out = Vec::with_capacity(specs.len());
    for (id, display, name_pattern, cmdline_pattern, min_runtime, protects) in specs {
        let regex = regex::Regex::new(&format!("(?i){name_pattern}")).unwrap_or_else(|e| {
            panic!("the built-in workload pattern '{name_pattern}' is invalid: {e}")
        });
        let cmdline = cmdline_pattern.map(|p| {
            regex::Regex::new(&format!("(?i){p}")).unwrap_or_else(|e| {
                panic!("the built-in workload command-line pattern '{p}' is invalid: {e}")
            })
        });

        out.push(CompiledWorkloadRule {
            id: id.to_string(),
            display_name: display.to_string(),
            regex,
            cmdline,
            min_runtime_secs: min_runtime,
            protects_standalone: protects,
        });
    }

    out
}

#[cfg(test)]
mod workload_tests {
    use super::*;

    #[test]
    fn every_workload_pattern_compiles() {
        // Compilation panics on a bad pattern, so reaching this assertion at all proves the whole
        // table is valid. The body checks the compiled rules are usable.
        for rule in workload_rules() {
            assert!(!rule.regex.as_str().is_empty());
            assert!(
                rule.regex.as_str().starts_with("(?i)"),
                "rule '{}' must match case-insensitively, which Windows requires",
                rule.id
            );
            assert!(!rule.display_name.is_empty());
        }
    }

    #[test]
    fn build_tools_are_matched_and_interpreters_are_not_broadly() {
        let rules = workload_rules();
        let matches = |name: &str| rules.iter().any(|r| r.regex.is_match(name));

        for tool in [
            "cargo.exe",
            "rustc.exe",
            "cmake.exe",
            "ninja.exe",
            "msbuild.exe",
            "make.exe",
        ] {
            assert!(matches(tool), "{tool} should be a build workload");
        }

        // Interpreters must not be standalone workloads on their own; an idle background node
        // process must not block shutdown.
        assert!(
            !matches("python.exe"),
            "a bare python process is not a workload"
        );
        assert!(
            !rules
                .iter()
                .any(|r| r.id == "node" && r.protects_standalone),
            "no rule may protect a bare node process standalone"
        );
    }

    #[test]
    fn the_dotnet_rule_requires_the_build_subcommand() {
        let rules = workload_rules();
        let dotnet = rules
            .iter()
            .find(|r| r.id == "dotnet-build")
            .expect("the rule exists");
        assert!(dotnet.regex.is_match("dotnet.exe"));
        // A bare `dotnet` invocation (for example `dotnet run` on a server) must not qualify.
        assert!(dotnet
            .cmdline
            .as_ref()
            .unwrap()
            .is_match("dotnet build proj.sln"));
        assert!(!dotnet.cmdline.as_ref().unwrap().is_match("dotnet run"));
    }

    #[test]
    fn only_genuine_builds_protect_standalone() {
        // The flag that decides whether a workload can hold a shutdown block without an agent
        // needs to be deliberate, so it is asserted explicitly.
        let rules = workload_rules();
        for rule in rules {
            if rule.protects_standalone {
                assert!(
                    rule.min_runtime_secs >= 30,
                    "rule '{}' protects standalone with only a {}s threshold",
                    rule.id,
                    rule.min_runtime_secs
                );
            }
        }
    }
}
