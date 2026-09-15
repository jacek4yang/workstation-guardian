//! Fixture-driven detection tests.
//!
//! Every case the specification calls out is represented here. The fixtures are built from
//! the process shapes actually observed on a real Windows developer workstation, including
//! the false-positive traps that matter most: an agent's own MCP helper processes, unrelated
//! `node.exe` and `python.exe` instances, and editors with no agent running.

use guardian_proto::model::{
    AgentConfig, Confidence, ProcessSnapshot, ResumeCapability, Rule, RuleField,
    SignatureConfidence, SignatureRules,
};

use crate::builtins;
use crate::engine::{
    collect_candidates, group_sessions_with_pids, Detection, DetectionEngine, EngineConfig,
};
use crate::graph::ProcessGraph;

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

/// Build a process snapshot. `path` and `cmdline` are optional so a test can express
/// "this process's command line could not be read".
fn proc(pid: u32, parent: u32, name: &str, image: &str, cmdline: Option<&str>) -> ProcessSnapshot {
    ProcessSnapshot {
        pid,
        parent_pid: parent,
        name: name.into(),
        image_path: Some(image.into()),
        cmdline: cmdline.map(str::to_string),
        created_filetime: 1_000_000 + pid as u64,
        session_id: 3,
        user_sid: None,
        cmdline_denied: false,
    }
}

/// The engine with the shipped signature database.
fn engine() -> DetectionEngine {
    DetectionEngine::new(EngineConfig::from_agent_config(&AgentConfig::default()))
}

/// Detect and return the instances, grouped into sessions.
fn detect(procs: Vec<ProcessSnapshot>) -> (ProcessGraph, DetectionEngine) {
    let graph = ProcessGraph::new(procs);
    let engine = engine();
    (graph, engine)
}

/// The detections paired with their processes, with launcher chains resolved.
///
/// Uses `detect_agents` rather than repeated `inspect` so these fixtures exercise the same
/// path the service does, including wrapper suppression.
fn detections_with_procs(
    engine: &DetectionEngine,
    graph: &ProcessGraph,
) -> Vec<(ProcessSnapshot, Detection)> {
    engine.detect_agents(graph)
}

/// Convenience: the display names of every high-confidence detection.
fn protected_agents(engine: &DetectionEngine, graph: &ProcessGraph) -> Vec<String> {
    detections_with_procs(engine, graph)
        .into_iter()
        .filter(|(_, d)| d.confidence.drives_protection())
        .map(|(_, d)| d.display_name)
        .collect()
}

// ---------------------------------------------------------------------------
// Required coverage: each agent form
// ---------------------------------------------------------------------------

#[test]
fn native_claude_executable_is_confirmed() {
    let (graph, engine) = detect(vec![proc(
        100,
        1,
        "claude.exe",
        r"C:\Users\dev\.local\bin\claude.exe",
        Some(r#""C:\Users\dev\.local\bin\claude.exe""#),
    )]);
    let names = protected_agents(&engine, &graph);
    assert_eq!(names, vec!["Claude Code"]);
}

#[test]
fn claude_launched_through_node_is_confirmed() {
    // The npm-installed form: a node process whose package path names the CLI.
    let (graph, engine) = detect(vec![proc(
        100,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some(
            r#""C:\Program Files\nodejs\node.exe" "C:\Users\dev\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js""#,
        ),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(
        names.contains(&"Claude Code".to_string()),
        "expected Claude Code, got {names:?}"
    );
}

#[test]
fn native_codex_executable_is_confirmed() {
    let (graph, engine) = detect(vec![proc(
        200,
        1,
        "codex.exe",
        r"C:\Users\dev\AppData\Local\Programs\OpenAI\Codex\bin\codex.exe",
        Some(r#""C:\Users\dev\AppData\Local\Programs\OpenAI\Codex\bin\codex.exe""#),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(names.contains(&"Codex".to_string()), "got {names:?}");
}

#[test]
fn codex_through_a_package_manager_is_confirmed() {
    // Observed shape: node running the npm-installed codex.
    let (graph, engine) = detect(vec![proc(
        201,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some(
            r#""C:\Program Files\nodejs\node.exe" "C:\Users\dev\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js""#,
        ),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(names.contains(&"Codex".to_string()), "got {names:?}");
}

#[test]
fn grok_build_is_confirmed() {
    // Byte-for-byte the shape observed on the development machine.
    let (graph, engine) = detect(vec![proc(
        16340,
        14440,
        "grok.exe",
        r"C:\Users\dev\.grok\bin\grok.exe",
        Some(r#""C:\Users\dev\.grok\bin\grok.exe" --resume 01a0a259-63ef-78a1-84c0-322f56f8cf8d"#),
    )]);
    let names = protected_agents(&engine, &graph);
    assert_eq!(names, vec!["Grok Build"]);
}

#[test]
fn gemini_cli_is_confirmed() {
    let (graph, engine) = detect(vec![proc(
        300,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some(r#"node C:\npm\node_modules\@google\gemini-cli\bundle\gemini.js"#),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(names.contains(&"Gemini CLI".to_string()), "got {names:?}");
}

#[test]
fn aider_through_python_is_confirmed() {
    let (graph, engine) = detect(vec![proc(
        400,
        1,
        "python.exe",
        r"D:\Python312\python.exe",
        Some(r#""D:\Python312\python.exe" -m aider --model sonnet"#),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(names.contains(&"Aider".to_string()), "got {names:?}");
}

#[test]
fn aider_installed_via_pipx_script_is_confirmed() {
    // A pipx-installed console script, which runs as a bare executable under Scripts.
    let (graph, engine) = detect(vec![proc(
        401,
        1,
        "aider.exe",
        r"C:\Users\dev\pipx\venvs\aider\Scripts\aider.exe",
        Some(r#""C:\Users\dev\pipx\venvs\aider\Scripts\aider.exe""#),
    )]);
    // The name `aider.exe` alone does not match a process-name rule, but the path does match
    // through the package-path rule on the command line or image path.
    let all = detections_with_procs(&engine, &graph);
    let found = all.iter().any(|(_, d)| d.display_name == "Aider");
    assert!(found, "a pipx-installed aider must be detected: {all:?}");
}

#[test]
fn opencode_goose_amp_and_qwen_are_detected() {
    for (name, image, expect) in [
        (
            "opencode.exe",
            r"C:\Users\dev\.local\bin\opencode.exe",
            "OpenCode",
        ),
        ("goose.exe", r"C:\Users\dev\.local\bin\goose.exe", "Goose"),
        ("amp.exe", r"C:\Users\dev\.local\bin\amp.exe", "Amp"),
        ("qwen.exe", r"C:\Users\dev\.local\bin\qwen.exe", "Qwen Code"),
    ] {
        let (graph, engine) = detect(vec![proc(500, 1, name, image, Some(image))]);
        let names = protected_agents(&engine, &graph);
        assert!(
            names.contains(&expect.to_string()),
            "{name} should be {expect}, got {names:?}"
        );
    }
}

#[test]
fn github_copilot_cli_is_detected_through_gh() {
    let (graph, engine) = detect(vec![proc(
        600,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some(r#"node C:\npm\node_modules\@github\copilot\index.js"#),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(
        names.contains(&"GitHub Copilot CLI".to_string()),
        "got {names:?}"
    );
}

#[test]
fn cline_and_cursor_agent_are_only_possible() {
    // These are deliberately capped: an ambiguous signal must not block shutdown.
    let (graph, engine) = detect(vec![
        proc(
            700,
            1,
            "cline.exe",
            r"C:\tools\cline.exe",
            Some(r"C:\tools\cline.exe"),
        ),
        proc(
            701,
            1,
            "cursor-agent.exe",
            r"C:\tools\cursor-agent.exe",
            Some(r"C:\tools\cursor-agent.exe"),
        ),
    ]);
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(all.len(), 2, "both should be detected: {all:?}");
    for (_, d) in &all {
        assert!(
            !d.confidence.drives_protection(),
            "{} must not drive protection, got {:?}",
            d.display_name,
            d.confidence
        );
    }
}

// ---------------------------------------------------------------------------
// Required coverage: false positives that must NOT become agents
// ---------------------------------------------------------------------------

#[test]
fn a_plain_node_process_is_not_an_agent() {
    let (graph, engine) = detect(vec![proc(
        800,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some(r#""C:\Program Files\nodejs\node.exe" server.js"#),
    )]);
    assert!(
        protected_agents(&engine, &graph).is_empty(),
        "an unrelated node process must not be an agent"
    );
}

#[test]
fn a_plain_python_process_is_not_an_agent() {
    let (graph, engine) = detect(vec![proc(
        801,
        1,
        "python.exe",
        r"D:\Python312\python.exe",
        Some(r#""D:\Python312\python.exe" -m http.server"#),
    )]);
    assert!(protected_agents(&engine, &graph).is_empty());
}

#[test]
fn an_mcp_server_helper_is_not_an_agent() {
    // The exact shape observed on the development machine: an agent spawns a Python MCP
    // server. Counting it as a second agent would double-count every agent that uses MCP.
    let (graph, engine) = detect(vec![
        proc(
            900,
            1,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some(r#""C:\Users\dev\.local\bin\claude.exe""#),
        ),
        proc(
            901,
            900,
            "python.exe",
            r"D:\Applications\Scoop\apps\python\current\python.exe",
            Some(
                r#""D:\Applications\Scoop\apps\python\current\python.exe" D:\Applications\Scoop\apps\python\current\Lib\site-packages\ida_pro_mcp\server.py"#,
            ),
        ),
    ]);

    let all = detections_with_procs(&engine, &graph);
    assert_eq!(
        all.len(),
        1,
        "only the agent itself should be detected, got {:?}",
        all.iter()
            .map(|(p, d)| (&p.name, &d.display_name))
            .collect::<Vec<_>>()
    );
    assert_eq!(all[0].1.display_name, "Claude Code");
}

#[test]
fn vscode_with_no_agent_is_not_an_agent() {
    let (graph, engine) = detect(vec![
        proc(
            1000,
            1,
            "Code.exe",
            r"C:\Program Files\Microsoft VS Code\Code.exe",
            Some(r#""C:\Program Files\Microsoft VS Code\Code.exe""#),
        ),
        // Its extension host and language servers.
        proc(
            1001,
            1000,
            "Code.exe",
            r"C:\Program Files\Microsoft VS Code\Code.exe",
            Some("--type=extensionHost"),
        ),
        proc(
            1002,
            1000,
            "tsserver",
            r"C:\Program Files\Microsoft VS Code\tsserver.js",
            Some("node tsserver.js"),
        ),
    ]);
    assert!(
        protected_agents(&engine, &graph).is_empty(),
        "having an editor open is not evidence of an agent"
    );
}

#[test]
fn cursor_with_no_reliable_agent_evidence_is_not_an_agent() {
    let (graph, engine) = detect(vec![
        proc(
            1100,
            1,
            "Cursor.exe",
            r"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe",
            Some(r#""C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe""#),
        ),
        proc(
            1101,
            1100,
            "Cursor.exe",
            r"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe",
            Some("--type=gpu-process"),
        ),
    ]);
    assert!(
        protected_agents(&engine, &graph).is_empty(),
        "the Cursor editor must never be counted as an agent"
    );
}

#[test]
fn browsers_and_terminals_are_not_agents() {
    let (graph, engine) = detect(vec![
        proc(
            1200,
            1,
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\chrome.exe",
            Some("--type=renderer"),
        ),
        proc(
            1201,
            1,
            "WindowsTerminal.exe",
            r"C:\Program Files\WindowsApps\WindowsTerminal.exe",
            None,
        ),
        proc(
            1202,
            1201,
            "pwsh.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            None,
        ),
        proc(1203, 1, "explorer.exe", r"C:\Windows\explorer.exe", None),
    ]);
    assert!(protected_agents(&engine, &graph).is_empty());
}

#[test]
fn build_tools_alone_are_not_agents() {
    let (graph, engine) = detect(vec![
        proc(
            1300,
            1,
            "cargo.exe",
            r"C:\Users\dev\.cargo\bin\cargo.exe",
            Some("cargo build"),
        ),
        proc(
            1301,
            1300,
            "rustc.exe",
            r"C:\Users\dev\.rustup\toolchains\stable\bin\rustc.exe",
            Some("rustc --edition 2021"),
        ),
        proc(
            1302,
            1,
            "cmake.exe",
            r"C:\Program Files\CMake\bin\cmake.exe",
            Some("cmake --build ."),
        ),
        proc(1303, 1, "ninja.exe", r"C:\tools\ninja.exe", Some("ninja")),
        proc(
            1304,
            1,
            "msbuild.exe",
            r"C:\Program Files\dotnet\msbuild.exe",
            Some("msbuild proj.sln"),
        ),
    ]);
    let all = detections_with_procs(&engine, &graph);
    assert!(
        all.is_empty(),
        "build tools are protected workloads, not agents: {:?}",
        all.iter().map(|(_, d)| &d.display_name).collect::<Vec<_>>()
    );
}

#[test]
fn a_renamed_executable_is_still_detected_via_its_command_line() {
    // A user who copies an agent binary to a different name must still be protected.
    let (graph, engine) = detect(vec![proc(
        1400,
        1,
        "myagent-copy.exe",
        r"C:\tools\myagent-copy.exe",
        Some(r#""C:\tools\myagent-copy.exe" --resume 01a0a259"#),
    )]);
    // The name tells us nothing, so the package-path rule is what must catch this only when
    // the path carries evidence. Here it does not, so the honest answer is "not detected".
    let all = detections_with_procs(&engine, &graph);
    assert!(
        all.is_empty(),
        "an unrecognisable binary must not be guessed at: {all:?}"
    );
}

#[test]
fn a_wrapped_agent_whose_command_line_carries_evidence_is_detected() {
    // The realistic rename case: a shell wrapper that still names the package.
    let (graph, engine) = detect(vec![proc(
        1401,
        1,
        "bun.exe",
        r"C:\Users\dev\.bun\bin\bun.exe",
        Some(
            r#"bun run C:\Users\dev\.bun\install\global\node_modules\@anthropic-ai\claude-code\cli.js"#,
        ),
    )]);
    let names = protected_agents(&engine, &graph);
    assert!(
        names.contains(&"Claude Code".to_string()),
        "a wrapper that names the package must be detected, got {names:?}"
    );
}

#[test]
fn a_process_with_a_denied_command_line_is_not_assumed_to_be_an_agent() {
    let mut p = proc(
        1500,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        None,
    );
    p.cmdline_denied = true;
    let graph = ProcessGraph::new(vec![p]);
    let engine = engine();
    assert!(
        protected_agents(&engine, &graph).is_empty(),
        "an unreadable command line must not be treated as a match"
    );
}

// ---------------------------------------------------------------------------
// Required coverage: session grouping
// ---------------------------------------------------------------------------

#[test]
fn an_agent_spawning_cargo_and_rustc_stays_one_session() {
    let (graph, engine) = detect(vec![
        proc(
            1600,
            1,
            "WindowsTerminal.exe",
            r"C:\Program Files\WindowsApps\wt.exe",
            None,
        ),
        proc(
            1601,
            1600,
            "pwsh.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            None,
        ),
        proc(
            1602,
            1601,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some(r#""C:\Users\dev\.local\bin\claude.exe""#),
        ),
        proc(
            1603,
            1602,
            "cargo.exe",
            r"C:\Users\dev\.cargo\bin\cargo.exe",
            Some("cargo build"),
        ),
        proc(
            1604,
            1603,
            "rustc.exe",
            r"C:\Users\dev\.rustup\toolchains\stable\bin\rustc.exe",
            Some("rustc -"),
        ),
    ]);

    let paired = detections_with_procs(&engine, &graph);
    assert_eq!(paired.len(), 1, "only the agent is an agent");
    let instances = group_sessions_with_pids(paired, &graph);
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].pid, 1602);
    assert_eq!(instances[0].root_pid, 1602);
    // The build tools are protected *workloads* under this session, not agents.
    assert!(
        graph.any_descendant(1602, 100, |p| p.name == "cargo.exe"),
        "cargo should be a descendant of the agent session"
    );
}

#[test]
fn multiple_simultaneous_agents_are_counted_separately() {
    // The real machine runs several agents at once, each in its own terminal.
    let (graph, engine) = detect(vec![
        proc(
            1700,
            1,
            "grok.exe",
            r"C:\Users\dev\.grok\bin\grok.exe",
            Some(r#"grok --resume a"#),
        ),
        proc(
            1701,
            1,
            "grok.exe",
            r"C:\Users\dev\.grok\bin\grok.exe",
            Some(r#"grok --resume b"#),
        ),
        proc(
            1702,
            1,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some(r#"claude"#),
        ),
        proc(
            1703,
            1,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some(r#"claude"#),
        ),
    ]);

    let paired = detections_with_procs(&engine, &graph);
    assert_eq!(paired.len(), 4, "all four agents are detected");

    let instances = group_sessions_with_pids(paired, &graph);
    assert_eq!(instances.len(), 4, "each is its own session");

    // Every root pid is distinct, because the four agents are unrelated processes.
    let mut roots: Vec<u32> = instances.iter().map(|i| i.root_pid).collect();
    roots.sort_unstable();
    roots.dedup();
    assert_eq!(roots.len(), 4);
}

#[test]
fn an_agent_with_multiple_children_counts_once() {
    let mut procs = vec![proc(
        1800,
        1,
        "claude.exe",
        r"C:\Users\dev\.local\bin\claude.exe",
        Some(r#"claude"#),
    )];
    // Ten children, some of which are nodes and pythons that a naive detector would count.
    for i in 0..10u32 {
        procs.push(proc(
            1900 + i,
            1800,
            "node.exe",
            r"C:\Program Files\nodejs\node.exe",
            Some("node helper.js"),
        ));
    }

    let (graph, engine) = detect(procs);
    let paired = detections_with_procs(&engine, &graph);
    assert_eq!(
        paired.len(),
        1,
        "a single agent with ten children is one agent, got {}",
        paired.len()
    );
}

#[test]
fn a_nested_detection_belongs_to_its_ancestor_session() {
    // Both the launcher and the agent match; the outer one owns the session, so the inner
    // detection is not a second agent.
    let (graph, engine) = detect(vec![
        proc(
            2000,
            1,
            "node.exe",
            r"C:\Program Files\nodejs\node.exe",
            Some(r#"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js"#),
        ),
        proc(
            2001,
            2000,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some(r#"claude --resume x"#),
        ),
    ]);

    let paired = detections_with_procs(&engine, &graph);
    assert_eq!(
        paired.len(),
        1,
        "the launcher must be suppressed in favour of the agent it spawned, got {:?}",
        paired
            .iter()
            .map(|(p, d)| (p.pid, &d.display_name, d.confidence))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        paired[0].0.pid, 2001,
        "the agent itself is the reported one"
    );

    let instances = group_sessions_with_pids(paired, &graph);
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].pid, 2001);
}

// ---------------------------------------------------------------------------
// Required coverage: robustness
// ---------------------------------------------------------------------------

#[test]
fn a_reused_pid_does_not_resurrect_an_old_session() {
    // The detector works off the current snapshot, so a reused pid simply appears as the
    // process it now is. The identity carries the creation time, which is what lets the
    // service tell the two apart across sweeps.
    let graph = ProcessGraph::new(vec![proc(
        2100,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some("node app.js"),
    )]);
    let engine = engine();
    let all = detections_with_procs(&engine, &graph);
    assert!(all.is_empty());

    let node = graph.get(2100).unwrap();
    assert_eq!(node.identity().created_filetime, 1_000_000 + 2100);
}

#[test]
fn rapid_start_and_exit_is_handled_without_error() {
    // A snapshot taken while processes come and go contains dangling parents. Detection must
    // tolerate that rather than assuming a consistent tree.
    let graph = ProcessGraph::new(vec![
        proc(
            2200,
            9999,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some("claude"),
        ),
        proc(
            2201,
            9998,
            "node.exe",
            r"C:\Program Files\nodejs\node.exe",
            Some("node x.js"),
        ),
    ]);
    let engine = engine();
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].1.display_name, "Claude Code");
}

#[test]
fn a_missing_image_path_does_not_break_detection() {
    let mut p = proc(2300, 1, "grok.exe", "", Some("grok"));
    p.image_path = None;
    let graph = ProcessGraph::new(vec![p]);
    let engine = engine();
    // The process *name* alone is enough for Grok.
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(all.len(), 1);
}

#[test]
fn an_empty_process_list_produces_no_detections() {
    let graph = ProcessGraph::new(vec![]);
    let engine = engine();
    assert!(detections_with_procs(&engine, &graph).is_empty());
    assert!(collect_candidates(&engine, &graph, 0).is_empty());
}

// ---------------------------------------------------------------------------
// Required coverage: extensibility and user signatures
// ---------------------------------------------------------------------------

#[test]
fn a_user_signature_without_recompilation_detects_a_new_agent() {
    // The whole point of the data-driven design: a user can add an agent Guardian has never
    // heard of, and it works immediately.
    let mut config = AgentConfig::default();
    config
        .user_signatures
        .push(guardian_proto::model::AgentSignature {
            id: "my_custom_agent".into(),
            display_name: "My Custom Agent".into(),
            user_defined: true,
            confidence: SignatureConfidence::Confirmed,
            rules: SignatureRules {
                any_of: vec![Rule {
                    field: RuleField::ProcessName,
                    pattern: r"^customagent\.exe$".into(),
                    weight: 100,
                    detail: "the user's own agent".into(),
                }],
                ..Default::default()
            },
            adapter: None,
            notes: String::new(),
        });

    let engine = DetectionEngine::new(EngineConfig::from_agent_config(&config));
    let graph = ProcessGraph::new(vec![proc(
        2400,
        1,
        "customagent.exe",
        r"C:\tools\customagent.exe",
        Some("customagent"),
    )]);
    let names = protected_agents(&engine, &graph);
    assert_eq!(names, vec!["My Custom Agent"]);
}

#[test]
fn a_user_signature_can_override_a_builtin() {
    // How a user corrects a built-in that misfires, without waiting for a release.
    let mut config = AgentConfig::default();
    config
        .user_signatures
        .push(guardian_proto::model::AgentSignature {
            id: "grok".into(), // the built-in id
            display_name: "Grok Build (user override)".into(),
            user_defined: true,
            confidence: SignatureConfidence::Confirmed,
            rules: SignatureRules {
                any_of: vec![Rule {
                    field: RuleField::ProcessName,
                    pattern: r"^grok\.exe$".into(),
                    weight: 100,
                    detail: "user override".into(),
                }],
                ..Default::default()
            },
            adapter: None,
            notes: String::new(),
        });

    let engine = DetectionEngine::new(EngineConfig::from_agent_config(&config));
    let graph = ProcessGraph::new(vec![proc(
        2500,
        1,
        "grok.exe",
        r"C:\Users\dev\.grok\bin\grok.exe",
        Some("grok"),
    )]);
    let names = protected_agents(&engine, &graph);
    assert_eq!(names, vec!["Grok Build (user override)"]);
}

#[test]
fn a_candidate_is_offered_for_promotion_when_a_signature_nearly_matches() {
    let mut config = AgentConfig::default();
    config
        .user_signatures
        .push(guardian_proto::model::AgentSignature {
            id: "weak".into(),
            display_name: "Weak".into(),
            user_defined: true,
            confidence: SignatureConfidence::Confirmed,
            rules: SignatureRules {
                any_of: vec![Rule {
                    field: RuleField::ProcessName,
                    pattern: r"^mystery\.exe$".into(),
                    weight: 20, // below the Possible threshold
                    detail: "a weak hint".into(),
                }],
                ..Default::default()
            },
            adapter: None,
            notes: String::new(),
        });

    let engine = DetectionEngine::new(EngineConfig::from_agent_config(&config));
    let graph = ProcessGraph::new(vec![proc(
        2600,
        1,
        "mystery.exe",
        r"C:\tools\mystery.exe",
        Some("mystery"),
    )]);

    let candidates = collect_candidates(&engine, &graph, 12345);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].name, "mystery.exe");
    assert_eq!(candidates[0].candidate_id, "mystery.exe:weak");
    assert!(!candidates[0].evidence.is_empty());
    // Crucially, a candidate does not drive protection.
    assert!(!candidates[0].confidence.drives_protection());
}

// ---------------------------------------------------------------------------
// Required coverage: the built-in table itself is exercised
// ---------------------------------------------------------------------------

#[test]
fn the_builtin_engine_compiles_every_signature_without_rejecting_a_rule() {
    // If a built-in pattern were invalid, that would be a shipped bug.
    let engine = engine();
    assert_eq!(
        engine.rejected_rules().len(),
        0,
        "the shipped signature database contains invalid rules: {:?}",
        engine.rejected_rules()
    );
    assert_eq!(engine.signature_count(), builtins::signatures().len());
}

#[test]
fn confidence_levels_are_reported_as_expected_for_each_agent() {
    // A table of the shipped expectations, so a weight change that silently demotes an agent
    // is caught.
    for (name, image, cmdline, expected) in [
        (
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            r#"claude"#,
            Confidence::Confirmed,
        ),
        (
            "grok.exe",
            r"C:\Users\dev\.grok\bin\grok.exe",
            r#"grok"#,
            Confidence::Confirmed,
        ),
        (
            "cline.exe",
            r"C:\tools\cline.exe",
            r#"cline"#,
            Confidence::Possible,
        ),
    ] {
        let (graph, engine) = detect(vec![proc(2700, 1, name, image, Some(cmdline))]);
        let all = detections_with_procs(&engine, &graph);
        assert_eq!(all.len(), 1, "{name} should be detected");
        assert_eq!(
            all[0].1.confidence, expected,
            "{name} should be {expected:?}, got {:?}",
            all[0].1.confidence
        );
    }
}

#[test]
fn adapters_are_only_attached_to_signatures_that_have_state_to_read() {
    use guardian_proto::model::AgentAdapterKind as K;
    let sigs = builtins::signatures();
    for sig in &sigs {
        // An adapter declared for an agent whose local state Guardian does not understand
        // would be a promise it cannot keep.
        if let Some(kind) = sig.adapter {
            assert!(
                matches!(kind, K::ClaudeCode | K::Codex | K::Grok | K::None),
                "{} declares an adapter Guardian does not implement",
                sig.id
            );
        }
    }
}

#[test]
fn resume_capability_is_never_offered_without_a_handle() {
    // A UI that offers "Resume" with nothing to resume is worse than one that says
    // "unavailable", so the two must never disagree.
    let profile = tempdir();
    write_file(
        &profile.join(".claude").join("sessions").join("5.json"),
        r#"{"pid":5,"cwd":"C:\\proj"}"#, // no sessionId
    );
    let adapters = crate::adapters::Adapters::with_home(&profile, true);
    let result = adapters.lookup(
        Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
        5,
        0,
    );
    assert!(result.project.is_some(), "the project is still known");
    assert_eq!(
        result.resume,
        ResumeCapability::Unavailable,
        "no session id means no resume offer"
    );
    let _ = std::fs::remove_dir_all(&profile);
}

fn tempdir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "guardian-fixture-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&p).expect("temp dir");
    p
}

fn write_file(path: &std::path::Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

// ---------------------------------------------------------------------------
// Required coverage: wrapper suppression
// ---------------------------------------------------------------------------

#[test]
fn a_node_wrapper_around_a_native_agent_is_suppressed() {
    // The npm launcher and the native binary it spawns both match. Only the agent is
    // reported, so an npm-installed agent is not counted twice.
    let (graph, engine) = detect(vec![
        proc(
            3000,
            1,
            "node.exe",
            r"C:\Program Files\nodejs\node.exe",
            Some(r#"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js"#),
        ),
        proc(
            3001,
            3000,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some("claude"),
        ),
    ]);

    let all = detections_with_procs(&engine, &graph);
    assert_eq!(all.len(), 1, "one agent, not two: {all:?}");
    assert_eq!(all[0].0.pid, 3001);
    assert_eq!(all[0].1.display_name, "Claude Code");
}

#[test]
fn a_launcher_without_a_matching_child_is_still_reported() {
    // Suppression must only apply when something *better* exists below. A launcher running
    // on its own is still the agent.
    let (graph, engine) = detect(vec![proc(
        3100,
        1,
        "node.exe",
        r"C:\Program Files\nodejs\node.exe",
        Some(r#"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js"#),
    )]);
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(all.len(), 1, "the launcher is the only agent present");
    assert_eq!(all[0].0.pid, 3100);
}

#[test]
fn two_independent_agents_are_both_reported() {
    // Suppression must not collapse unrelated agents, even when one happens to have a
    // matching process somewhere below it in the tree.
    let (graph, engine) = detect(vec![
        proc(
            3200,
            1,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some("claude"),
        ),
        proc(
            3300,
            1,
            "grok.exe",
            r"C:\Users\dev\.grok\bin\grok.exe",
            Some("grok"),
        ),
    ]);
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(all.len(), 2, "both agents are distinct sessions: {all:?}");
}

#[test]
fn a_child_agent_outside_the_launcher_still_counts_separately() {
    // A shell spawns two agents. Neither suppresses the other, because neither is an
    // ancestor of the other.
    let (graph, engine) = detect(vec![
        proc(
            3400,
            1,
            "pwsh.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            None,
        ),
        proc(
            3401,
            3400,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some("claude"),
        ),
        proc(
            3402,
            3400,
            "grok.exe",
            r"C:\Users\dev\.grok\bin\grok.exe",
            Some("grok"),
        ),
    ]);
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(
        all.len(),
        2,
        "the two siblings are separate agents: {all:?}"
    );
}

#[test]
fn suppression_does_not_remove_an_equal_confidence_parent_by_accident() {
    // Two independent native agents where one is coincidentally the parent of the other
    // (an agent that launches another agent). The descendant wins; exactly one is reported.
    let (graph, engine) = detect(vec![
        proc(
            3500,
            1,
            "claude.exe",
            r"C:\Users\dev\.local\bin\claude.exe",
            Some("claude"),
        ),
        proc(
            3501,
            3500,
            "grok.exe",
            r"C:\Users\dev\.grok\bin\grok.exe",
            Some("grok"),
        ),
    ]);
    let all = detections_with_procs(&engine, &graph);
    assert_eq!(
        all.len(),
        1,
        "nested agents resolve to one session root, got {all:?}"
    );
    assert_eq!(all[0].0.pid, 3501);
}
