//! Validation against this machine's real process table.
//!
//! These tests use `guardian-win` to enumerate the live system and assert that the detector
//! behaves sensibly on it. They are read-only: nothing here starts, stops or signals a
//! process, because on a developer workstation that would risk terminating a real agent
//! session with hours of work in it.
//!
//! The assertions are deliberately about *properties* rather than exact counts, so they hold
//! on a machine with no agents installed and on one running six of them.

use guardian_core::ports::Clock;
use guardian_process::{DetectionEngine, EngineConfig, ProcessGraph};
use guardian_proto::model::{AgentConfig, Confidence};

fn live_graph() -> Option<ProcessGraph> {
    match guardian_win::process::enumerate_processes() {
        Ok(procs) if !procs.is_empty() => Some(ProcessGraph::new(procs)),
        _ => None,
    }
}

fn engine() -> DetectionEngine {
    DetectionEngine::new(EngineConfig::from_agent_config(&AgentConfig::default()))
}

#[test]
fn detection_runs_against_the_live_process_table() {
    let Some(graph) = live_graph() else {
        eprintln!("process enumeration unavailable in this context; skipping");
        return;
    };

    let engine = engine();
    let detections = engine.detect_agents(&graph);

    // Whatever is installed, the engine must produce a definite result without panicking,
    // and every detection must carry evidence explaining itself.
    for (process, det) in &detections {
        assert!(
            !det.evidence.is_empty(),
            "detection of {} (pid {}) has no evidence",
            process.name,
            process.pid
        );
        assert!(!det.signature_id.is_empty());
        eprintln!(
            "detected: {} pid={} confidence={:?} score={}",
            det.display_name, process.pid, det.confidence, det.score
        );
    }

    eprintln!("{} detection(s) on this machine", detections.len());
}

#[test]
fn system_processes_are_never_reported_as_agents() {
    // The most damaging false positive would be a Windows component, so this is asserted
    // explicitly rather than left to the never-agent list being correct.
    let Some(graph) = live_graph() else {
        return;
    };
    let engine = engine();
    let detections = engine.detect_agents(&graph);

    const FORBIDDEN: [&str; 14] = [
        "system",
        "registry",
        "memory compression",
        "idle",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "svchost.exe",
        "dwm.exe",
        "explorer.exe",
        "taskhostw.exe",
    ];

    for (process, det) in &detections {
        let name = process.name.to_ascii_lowercase();
        assert!(
            !FORBIDDEN.contains(&name.as_str()),
            "a system process was reported as an agent: {} as {}",
            process.name,
            det.display_name
        );
    }
}

#[test]
fn guardian_does_not_detect_itself() {
    // A self-detection would be embarrassing and would also inflate the agent count on every
    // machine that runs Guardian.
    let Some(graph) = live_graph() else {
        return;
    };
    let engine = engine();
    for (process, det) in engine.detect_agents(&graph) {
        assert!(
            !process.name.to_ascii_lowercase().contains("guardian"),
            "Guardian detected one of its own processes as {}: {}",
            det.display_name,
            process.name
        );
    }
}

#[test]
fn build_tools_on_this_machine_are_not_reported_as_agents() {
    let Some(graph) = live_graph() else {
        return;
    };
    let engine = engine();
    for (process, det) in engine.detect_agents(&graph) {
        let name = process.name.to_ascii_lowercase();
        for tool in [
            "cargo.exe",
            "rustc.exe",
            "msbuild.exe",
            "cmake.exe",
            "ninja.exe",
        ] {
            assert_ne!(
                name, tool,
                "{tool} was reported as the agent {}",
                det.display_name
            );
        }
    }
}

#[test]
fn every_live_detection_has_a_resolvable_identity() {
    let Some(graph) = live_graph() else {
        return;
    };
    let engine = engine();
    for (process, _) in engine.detect_agents(&graph) {
        // The identity must be stronger than a bare pid, because pids are reused.
        let id = process.identity();
        assert_eq!(id.pid, process.pid);
        if process.created_filetime != 0 {
            assert!(
                guardian_win::process::process_alive(process.pid, process.created_filetime),
                "{} (pid {}) was in the snapshot but is not alive at its recorded start time",
                process.name,
                process.pid
            );
        }
    }
}

#[test]
fn a_live_agent_session_is_grouped_into_one_instance() {
    // If real agents are running, each must appear as exactly one session, and any of their
    // helper children must not appear as additional agents.
    let Some(graph) = live_graph() else {
        return;
    };
    let engine = engine();
    let detections = engine.detect_agents(&graph);

    let instances = guardian_process::engine::group_sessions_with_pids(detections.clone(), &graph);

    // Every root pid must be distinct across instances: two instances sharing a root would
    // mean the same session was reported twice.
    let mut roots: Vec<u32> = instances.iter().map(|i| i.root_pid).collect();
    roots.sort_unstable();
    let before = roots.len();
    roots.dedup();
    assert_eq!(
        roots.len(),
        before,
        "two agent instances share a session root, so a session was counted twice"
    );

    // And the number of sessions cannot exceed the number of detections.
    assert!(instances.len() <= detections.len());
}

#[test]
fn the_clock_and_boot_identity_are_usable() {
    use guardian_win::clock::{SystemBootIdentity, SystemClock};
    let clock = SystemClock;
    assert!(clock.now_ms() > 0);
    assert!(!SystemBootIdentity::read().is_empty());
}

#[test]
fn high_confidence_detections_are_a_subset_of_all_detections() {
    let Some(graph) = live_graph() else {
        return;
    };
    let engine = engine();
    let all = engine.detect_agents(&graph);
    let protected: Vec<_> = all
        .iter()
        .filter(|(_, d)| d.confidence.drives_protection())
        .collect();

    // The property that matters: a Possible detection never drives protection.
    for (process, det) in &all {
        if det.confidence == Confidence::Possible {
            assert!(
                !det.confidence.drives_protection(),
                "{} at Possible must not drive protection",
                process.name
            );
        }
    }
    assert!(protected.len() <= all.len());
}
