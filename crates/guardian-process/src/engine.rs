//! The detection engine: weighted evidence scoring over a data-driven signature database.
//!
//! The engine itself is small and uniform. All agent-specific knowledge lives in
//! [`crate::builtins`] and in user configuration, both of which are plain data. That is the
//! property that keeps this maintainable: adding an agent is a data edit, and every rule is
//! exercised by the same well-tested scoring path.

use guardian_proto::model::{
    AgentCandidate, AgentConfig, AgentGroup, AgentInstance, AgentInventory, AgentSignature,
    AncestorRef, Confidence, Evidence, MonitorHealth, ProcessSnapshot, ProtectedWorkload, Rule,
    RuleField, SignatureConfidence,
};
use regex::Regex;

use crate::graph::ProcessGraph;

/// A compiled signature: the data form plus ready-to-run regexes.
#[derive(Debug)]
pub struct CompiledSignature {
    pub signature: AgentSignature,
    any_of: Vec<CompiledRule>,
    all_of: Vec<CompiledRule>,
    none_of: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledRule {
    field: RuleField,
    regex: Regex,
    weight: i32,
    detail: String,
    /// The original pattern text, for logging without re-deriving it.
    pattern: String,
}

/// A rule that could not be compiled, kept so the reason can be reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRule {
    pub signature_id: String,
    pub field: RuleField,
    pub pattern: String,
    pub reason: String,
}

/// The detection of one process by one signature.
#[derive(Debug, Clone)]
pub struct Detection {
    pub signature_id: String,
    pub display_name: String,
    pub confidence: Confidence,
    pub score: i32,
    pub evidence: Vec<Evidence>,
}

/// Why a process that scored above zero was not reported as an agent.
///
/// Recorded rather than discarded so `guardianctl doctor` can explain a near miss, which is
/// how a user debugs a missing detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionReason {
    pub pid: u32,
    pub name: String,
    pub signature_id: String,
    pub score: i32,
    pub required: i32,
    pub explanation: String,
}

/// Engine configuration derived from user settings.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Signatures to use, built-ins merged with user additions.
    pub signatures: Vec<AgentSignature>,
    /// Minimum score for `Possible`.
    pub possible_threshold: i32,
    /// Minimum score for `High`.
    pub high_threshold: i32,
    /// Minimum score for `Confirmed`.
    pub confirmed_threshold: i32,
    /// Process names that are never agents even if a rule matches. Guards against a
    /// mis-written signature turning every shell into an agent.
    pub never_agent_names: Vec<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            signatures: Vec::new(),
            // Thresholds are set so that a single strong, specific rule reaches High but a
            // generic hint does not, and so that Confirmed requires corroboration.
            possible_threshold: 40,
            high_threshold: 80,
            confirmed_threshold: 120,
            never_agent_names: vec![
                "system".into(),
                "registry".into(),
                "memory compression".into(),
                "idle".into(),
                "csrss.exe".into(),
                "wininit.exe".into(),
                "winlogon.exe".into(),
                "services.exe".into(),
                "lsass.exe".into(),
                "smss.exe".into(),
            ],
        }
    }
}

impl EngineConfig {
    /// Build from user configuration, merging user signatures over the built-ins.
    pub fn from_agent_config(config: &AgentConfig) -> Self {
        let mut signatures = crate::builtins::signatures();

        // A user signature with the same id as a built-in replaces it, which is how a user
        // corrects a built-in without patching the binary.
        for user in &config.user_signatures {
            if let Some(existing) = signatures.iter_mut().find(|s| s.id == user.id) {
                *existing = user.clone();
            } else {
                signatures.push(user.clone());
            }
        }

        EngineConfig {
            signatures,
            ..Default::default()
        }
    }
}

/// The detection engine.
#[derive(Debug)]
pub struct DetectionEngine {
    compiled: Vec<CompiledSignature>,
    config: EngineConfig,
    rejected_rules: Vec<RejectedRule>,
}

impl DetectionEngine {
    /// Compile the engine. Invalid patterns are rejected individually and recorded; a single
    /// bad rule never disables detection entirely.
    pub fn new(config: EngineConfig) -> Self {
        let mut compiled = Vec::with_capacity(config.signatures.len());
        let mut rejected = Vec::new();

        for sig in &config.signatures {
            let mut any_of = Vec::new();
            let mut all_of = Vec::new();
            let mut none_of = Vec::new();

            for (list_name, rules, out) in [
                ("any_of", &sig.rules.any_of, &mut any_of),
                ("all_of", &sig.rules.all_of, &mut all_of),
                ("none_of", &sig.rules.none_of, &mut none_of),
            ] {
                for rule in rules {
                    match compile_rule(rule) {
                        Ok(c) => out.push(c),
                        Err(reason) => rejected.push(RejectedRule {
                            signature_id: sig.id.clone(),
                            field: rule.field,
                            pattern: rule.pattern.clone(),
                            reason: format!("{list_name}: {reason}"),
                        }),
                    }
                }
            }

            // A signature with no positive rules can never match, so it is dropped rather
            // than compiled into a no-op.
            if any_of.is_empty() && all_of.is_empty() {
                rejected.push(RejectedRule {
                    signature_id: sig.id.clone(),
                    field: RuleField::ProcessName,
                    pattern: String::new(),
                    reason: "signature has no usable positive rule".into(),
                });
                continue;
            }

            compiled.push(CompiledSignature {
                signature: sig.clone(),
                any_of,
                all_of,
                none_of,
            });
        }

        DetectionEngine {
            compiled,
            config,
            rejected_rules: rejected,
        }
    }

    /// Rules that failed to compile, for diagnostics.
    pub fn rejected_rules(&self) -> &[RejectedRule] {
        &self.rejected_rules
    }

    pub fn signature_count(&self) -> usize {
        self.compiled.len()
    }

    /// Inspect one process.
    ///
    /// Returns `None` when nothing matched, or when the process is on the never-agent list.
    pub fn inspect(&self, process: &ProcessSnapshot, graph: &ProcessGraph) -> Option<Detection> {
        // A hard exclusion checked before any scoring: no signature may override it.
        let name_lower = process.name_lower();
        if self
            .config
            .never_agent_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&name_lower))
        {
            return None;
        }

        let mut best: Option<Detection> = None;

        for sig in &self.compiled {
            if let Some(det) = self.score(sig, process, graph) {
                // The highest-scoring signature wins. Ties break on signature id so the
                // result is deterministic across runs, which matters for reproducible logs
                // and for tests.
                let better = match &best {
                    None => true,
                    Some(b) => {
                        det.score > b.score
                            || (det.score == b.score && det.signature_id < b.signature_id)
                    }
                };
                if better {
                    best = Some(det);
                }
            }
        }

        best
    }

    /// Score one signature against one process.
    fn score(
        &self,
        sig: &CompiledSignature,
        process: &ProcessSnapshot,
        graph: &ProcessGraph,
    ) -> Option<Detection> {
        let mut evidence = Vec::new();
        let mut score = 0i32;
        let mut positive_matches = 0usize;

        // Vetoes are evaluated first: a single matching veto rule disqualifies the process
        // outright, regardless of how much positive evidence exists. This is what stops an
        // agent's own MCP helper from being reported as a second agent.
        for rule in &sig.none_of {
            if rule_matches(rule, process, graph) {
                tracing::trace!(
                    pid = process.pid,
                    signature = %sig.signature.id,
                    pattern = %rule.pattern,
                    "signature vetoed by a none_of rule"
                );
                return None;
            }
        }

        for rule in &sig.any_of {
            if rule_matches(rule, process, graph) {
                let matched = matched_text(rule, process, graph);
                evidence.push(Evidence::new(
                    rule.field_code(),
                    matched,
                    rule.weight,
                    rule.detail.clone(),
                ));
                score += rule.weight;
                positive_matches += 1;
            }
        }

        if !sig.all_of.is_empty() {
            let mut all_matched = true;
            let mut add: Vec<Evidence> = Vec::new();
            let mut add_score = 0i32;

            for rule in &sig.all_of {
                if rule_matches(rule, process, graph) {
                    let matched = matched_text(rule, process, graph);
                    add.push(Evidence::new(
                        rule.field_code(),
                        matched,
                        rule.weight,
                        rule.detail.clone(),
                    ));
                    add_score += rule.weight;
                } else {
                    all_matched = false;
                    break;
                }
            }

            if all_matched {
                evidence.extend(add);
                score += add_score;
                positive_matches += 1;
            }
        }

        if positive_matches == 0 {
            return None;
        }

        let confidence = self.confidence_for(sig, score);

        Some(Detection {
            signature_id: sig.signature.id.clone(),
            display_name: sig.signature.display_name.clone(),
            confidence,
            score,
            evidence,
        })
    }

    /// Map a score onto a confidence level.
    ///
    /// The signature's own declared confidence caps the result: a signature that ships as
    /// `Possible` (because its evidence is inherently weak, such as an IDE that *may* be
    /// running an agent) can never reach `Confirmed` no matter how much it matches.
    fn confidence_for(&self, sig: &CompiledSignature, score: i32) -> Confidence {
        let raw = if score >= self.config.confirmed_threshold {
            Confidence::Confirmed
        } else if score >= self.config.high_threshold {
            Confidence::High
        } else if score >= self.config.possible_threshold {
            Confidence::Possible
        } else {
            Confidence::Unknown
        };

        let cap = match sig.signature.confidence {
            SignatureConfidence::Confirmed => Confidence::Confirmed,
            SignatureConfidence::High => Confidence::High,
            SignatureConfidence::Possible => Confidence::Possible,
        };

        raw.min(cap)
    }

    /// Detect every agent-like process in a snapshot.
    ///
    /// Only processes that matched something are walked as subtree roots, so the cost scales
    /// with detections rather than with the process count.
    pub fn detect_all(&self, graph: &ProcessGraph) -> Vec<Detection> {
        let mut out = Vec::new();
        for process in graph.iter() {
            if let Some(d) = self.inspect(process, graph) {
                out.push(d);
            }
        }
        out
    }

    /// Detect agents, resolving wrapper chains so one agent is reported once.
    ///
    /// # The wrapper problem
    ///
    /// An agent launched through a package manager appears as *two* matching processes: the
    /// interpreter whose command line names the package, and the agent binary it spawns.
    /// Both legitimately match a signature, but counting both would double every npm- or
    /// wrappers-launched agent.
    ///
    /// The resolution rule is: when a matched process has a *descendant* that also matched
    /// with confidence at least as high, the ancestor is acting as a launcher and is not
    /// reported separately. This is deliberately generic — it knows nothing about which agent
    /// is which, only that a launcher and the thing it launches are one agent.
    ///
    /// Ties go to the descendant, because for a launcher/agent pair the more specific
    /// detection is the one closer to the actual work.
    pub fn detect_agents(&self, graph: &ProcessGraph) -> Vec<(ProcessSnapshot, Detection)> {
        let matched: Vec<(ProcessSnapshot, Detection)> = graph
            .iter()
            .filter_map(|p| self.inspect(p, graph).map(|d| (p.clone(), d)))
            .collect();

        if matched.len() < 2 {
            return matched;
        }

        // Snapshot the pids and confidences up front so the filter below borrows nothing
        // from `matched`, which is consumed by the iterator.
        let matched_pids: Vec<(u32, Confidence, i32)> = matched
            .iter()
            .map(|(p, d)| (p.pid, d.confidence, d.score))
            .collect();

        matched
            .into_iter()
            .filter(|(process, det)| {
                // Is there a descendant of this process that matched at least as strongly?
                let shadowed = graph.any_descendant(process.pid, 512, |candidate| {
                    matched_pids.iter().any(|(pid, conf, score)| {
                        *pid == candidate.pid
                            && (*conf > det.confidence
                                || (*conf == det.confidence && *score >= det.score))
                    })
                });

                if shadowed {
                    tracing::debug!(
                        pid = process.pid,
                        name = %process.name,
                        signature = %det.signature_id,
                        "suppressing a launcher process in favour of the agent it spawned"
                    );
                }
                !shadowed
            })
            .collect()
    }

    /// Explain why a process did not become a detection.
    ///
    /// Used by diagnostics: when a user reports "my agent was not detected", this says
    /// whether a rule nearly matched or nothing matched at all.
    pub fn explain(&self, process: &ProcessSnapshot, graph: &ProcessGraph) -> Vec<RejectionReason> {
        let mut out = Vec::new();
        let name_lower = process.name_lower();

        if self
            .config
            .never_agent_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&name_lower))
        {
            out.push(RejectionReason {
                pid: process.pid,
                name: process.name.clone(),
                signature_id: String::new(),
                score: 0,
                required: self.config.possible_threshold,
                explanation: "excluded by the never-agent list".into(),
            });
            return out;
        }

        for sig in &self.compiled {
            // Re-run scoring without the veto short-circuit so a veto can be reported.
            let veto = sig.none_of.iter().find(|r| rule_matches(r, process, graph));

            let mut score = 0i32;
            let mut matched = 0usize;
            for rule in &sig.any_of {
                if rule_matches(rule, process, graph) {
                    score += rule.weight;
                    matched += 1;
                }
            }
            if !sig.all_of.is_empty() && sig.all_of.iter().all(|r| rule_matches(r, process, graph))
            {
                score += sig.all_of.iter().map(|r| r.weight).sum::<i32>();
                matched += 1;
            }

            if matched == 0 && veto.is_none() {
                continue;
            }

            let explanation = if let Some(v) = veto {
                format!("vetoed by a none_of rule matching '{}'", v.pattern)
            } else if score < self.config.possible_threshold {
                format!(
                    "score {score} is below the {}-point threshold for Possible",
                    self.config.possible_threshold
                )
            } else {
                "matched".to_string()
            };

            out.push(RejectionReason {
                pid: process.pid,
                name: process.name.clone(),
                signature_id: sig.signature.id.clone(),
                score,
                required: self.config.possible_threshold,
                explanation,
            });
        }

        out
    }
}

impl CompiledRule {
    /// Stable evidence code for this field.
    fn field_code(&self) -> &'static str {
        match self.field {
            RuleField::ProcessName => "process_name",
            RuleField::ImagePath => "image_path",
            RuleField::CommandLine => "command_line",
            RuleField::ParentName => "parent_name",
            RuleField::ParentPath => "parent_path",
            RuleField::ChildName => "child_name",
            RuleField::PackagePath => "package_path",
        }
    }
}

/// Compile one rule's pattern.
fn compile_rule(rule: &Rule) -> Result<CompiledRule, String> {
    // Reuse the configuration validator so the bounds enforced at load time and at compile
    // time cannot diverge.
    guardian_core::config::validate_pattern(&rule.pattern)?;

    let regex = Regex::new(&format!("(?i){}", rule.pattern))
        .map_err(|e| e.to_string().replace('\n', " "))?;

    Ok(CompiledRule {
        field: rule.field,
        regex,
        weight: rule.weight,
        detail: rule.detail.clone(),
        pattern: rule.pattern.clone(),
    })
}

/// Whether a compiled rule matches a process.
fn rule_matches(rule: &CompiledRule, process: &ProcessSnapshot, graph: &ProcessGraph) -> bool {
    match rule.field {
        RuleField::ProcessName => rule.regex.is_match(&process.name),

        RuleField::ImagePath => process
            .image_path
            .as_deref()
            .map(|p| rule.regex.is_match(p))
            .unwrap_or(false),

        RuleField::CommandLine => process
            .cmdline
            .as_deref()
            .map(|c| rule.regex.is_match(c))
            .unwrap_or(false),

        RuleField::ParentName => graph
            .parent_of(process.pid)
            .map(|p| rule.regex.is_match(&p.name))
            .unwrap_or(false),

        RuleField::ParentPath => graph
            .parent_of(process.pid)
            .map(|p| {
                p.image_path
                    .as_deref()
                    .map(|path| rule.regex.is_match(path))
                    .unwrap_or(false)
                    || p.cmdline
                        .as_deref()
                        .map(|c| rule.regex.is_match(c))
                        .unwrap_or(false)
            })
            .unwrap_or(false),

        RuleField::ChildName => graph
            .child_names(process.pid)
            .iter()
            .any(|n| rule.regex.is_match(n)),

        RuleField::PackagePath => {
            // Package markers appear either in the image path or the command line,
            // depending on how the agent was launched. Both are checked so a wrapper script
            // and a direct binary are treated the same.
            let in_path = process
                .image_path
                .as_deref()
                .map(|p| rule.regex.is_match(p))
                .unwrap_or(false);
            let in_cmd = process
                .cmdline
                .as_deref()
                .map(|c| rule.regex.is_match(c))
                .unwrap_or(false);
            in_path || in_cmd
        }
    }
}

/// The text a rule matched, for the evidence record.
///
/// Bounded, and never the full command line: evidence is logged and shown in the UI, and a
/// command line can contain a path with a user name in it. Only the matching region is kept.
fn matched_text(rule: &CompiledRule, process: &ProcessSnapshot, graph: &ProcessGraph) -> String {
    let haystack: String = match rule.field {
        RuleField::ProcessName => process.name.clone(),
        RuleField::ImagePath => process.image_path.clone().unwrap_or_default(),
        RuleField::CommandLine => process.cmdline.clone().unwrap_or_default(),
        RuleField::ParentName => graph
            .parent_of(process.pid)
            .map(|p| p.name.clone())
            .unwrap_or_default(),
        RuleField::ParentPath => graph
            .parent_of(process.pid)
            .map(|p| {
                p.image_path
                    .clone()
                    .unwrap_or_else(|| p.cmdline.clone().unwrap_or_default())
            })
            .unwrap_or_default(),
        RuleField::ChildName => graph.child_names(process.pid).join(","),
        RuleField::PackagePath => process
            .image_path
            .clone()
            .unwrap_or_else(|| process.cmdline.clone().unwrap_or_default()),
    };

    match rule.regex.find(&haystack) {
        Some(m) => truncate_chars(m.as_str(), 160),
        // The rule matched, but through the combined path/cmdline check in a way this
        // single haystack does not reproduce. Report the pattern rather than inventing a
        // match that was not observed.
        None => format!("<matched pattern {}>", rule.pattern),
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(max.min(s.len()));
    for c in s.chars().take(max) {
        out.push(c);
    }
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// Group detections into sessions, taking the pid explicitly.
///
/// This is the variant the service uses: it pairs each detection with the process it scored,
/// which is what makes session grouping possible at all.
pub fn group_sessions_with_pids(
    detections: Vec<(ProcessSnapshot, Detection)>,
    graph: &ProcessGraph,
) -> Vec<AgentInstance> {
    let pids: Vec<(u32, Confidence)> = detections
        .iter()
        .map(|(p, d)| (p.pid, d.confidence))
        .collect();

    let mut instances = Vec::with_capacity(detections.len());

    for (process, det) in detections {
        let mut owner: Option<u32> = None;
        for ancestor in graph.ancestors(process.pid) {
            if let Some(&(apid, aconf)) = pids.iter().find(|(p, _)| *p == ancestor.pid) {
                if aconf >= det.confidence {
                    owner = Some(apid);
                    break;
                }
            }
        }

        let root_pid = owner.unwrap_or(process.pid);

        instances.push(AgentInstance {
            kind: det.signature_id,
            display_name: det.display_name,
            pid: process.pid,
            root_pid,
            identity: process.identity(),
            session_id: format!("{root_pid}"),
            confidence: det.confidence,
            evidence: det.evidence,
            started_at_filetime: process.created_filetime,
            started_at_ms: 0,
            image_path: process.image_path,
            cmdline: process.cmdline,
            ancestry: graph
                .ancestors(root_pid)
                .iter()
                .map(|a| AncestorRef {
                    pid: a.pid,
                    name: a.name.clone(),
                })
                .collect(),
            session_id_windows: process.session_id,
            user: None,
            project: None,
            resume: guardian_proto::model::ResumeCapability::Unavailable,
        });
    }

    instances
}

/// Assemble a complete inventory from detections.
///
/// This is the single place that turns raw detections into what the rest of the system consumes:
/// agents grouped into sessions, protected workloads attributed to their owning session, and the
/// unconfirmed candidates that never drive protection.
///
/// Workload attribution is the important part. A build tool spawned by an agent belongs to that
/// agent's session, which is what makes "cargo is running because Claude Code asked it to"
/// distinguishable from "some unrelated cargo is running".
pub fn build_inventory(
    detections: Vec<(ProcessSnapshot, Detection)>,
    graph: &ProcessGraph,
    adapters: &crate::adapters::Adapters,
    candidates: Vec<AgentCandidate>,
    now_ms: i64,
    monitor: MonitorHealth,
) -> AgentInventory {
    // Group into agent sessions first, so workloads can be attributed to them.
    let mut instances = group_sessions_with_pids(detections, graph);

    // Enrich with adapter metadata. Only agents whose signature declares an adapter are queried,
    // so an agent Guardian does not understand is left alone rather than guessed at.
    for instance in &mut instances {
        let adapter_kind = crate::builtins::signatures()
            .iter()
            .find(|s| s.id == instance.kind)
            .and_then(|s| s.adapter);

        let result = adapters.lookup(adapter_kind, instance.pid, instance.started_at_filetime);
        if result.project.is_some() {
            instance.project = result.project;
        }
        if result.resume != guardian_proto::model::ResumeCapability::Unavailable {
            instance.resume = result.resume;
        }
        instance.started_at_ms = crate::graph::filetime_to_unix_ms(instance.started_at_filetime);
    }

    // Build the session-id set for workload attribution.
    let session_roots: Vec<(u32, String, String)> = instances
        .iter()
        .map(|i| (i.root_pid, i.session_id.clone(), i.display_name.clone()))
        .collect();

    let workloads = detect_workloads(graph, &session_roots, now_ms);

    // Group instances by agent kind.
    let mut groups: std::collections::BTreeMap<String, AgentGroup> =
        std::collections::BTreeMap::new();
    for instance in instances {
        let entry = groups
            .entry(instance.kind.clone())
            .or_insert_with(|| AgentGroup {
                kind: instance.kind.clone(),
                display_name: instance.display_name.clone(),
                instances: Vec::new(),
                confidence: Confidence::Unknown,
            });
        // The group's confidence is the highest among its instances.
        if instance.confidence > entry.confidence {
            entry.confidence = instance.confidence;
        }
        entry.instances.push(instance);
    }

    AgentInventory {
        agents: groups.into_values().collect(),
        workloads,
        candidates,
        updated_at_ms: now_ms,
        monitor,
    }
}

/// Detect long-running development workloads and attribute them to an agent session.
///
/// A workload owned by an agent session is always protected, because the agent is waiting on it.
/// A standalone build is only protected when the caller asks for it, which is what keeps an idle
/// background process from blocking shutdown forever.
fn detect_workloads(
    graph: &ProcessGraph,
    session_roots: &[(u32, String, String)],
    now_ms: i64,
) -> Vec<ProtectedWorkload> {
    let rules = crate::builtins::workload_rules();
    let mut out = Vec::new();

    for process in graph.iter() {
        let name = process.name_lower();

        let Some(rule) = rules.iter().find(|r| {
            r.regex.is_match(&name)
                && r.cmdline
                    .as_ref()
                    .map(|c| {
                        process
                            .cmdline
                            .as_deref()
                            .map(|cmd| c.is_match(cmd))
                            .unwrap_or(false)
                    })
                    .unwrap_or(true)
        }) else {
            continue;
        };

        // Attribute this process to an agent session, if any ancestor owns one.
        // Attribute this process to an agent session when an agent owns it. The subtree walk is
        // bounded, and the rule set is small, so this stays cheap.
        let owner = session_roots
            .iter()
            .find(|(root, _, _)| {
                *root != process.pid && graph.subtree(*root, 512).contains(&process.pid)
            })
            .map(|(_, session, kind)| (session.clone(), kind.clone()));

        let started_ms = crate::graph::filetime_to_unix_ms(process.created_filetime);
        let running_ms = if started_ms > 0 {
            now_ms.saturating_sub(started_ms)
        } else {
            0
        };

        // A standalone workload must have run long enough to be worth protecting. An owned one is
        // protected immediately, because the agent that spawned it is blocked on it.
        let qualifies = if owner.is_some() {
            true
        } else {
            let threshold_ms = (rule.min_runtime_secs * 1000) as i64;
            threshold_ms == 0 || running_ms >= threshold_ms
        };

        if !qualifies {
            continue;
        }

        out.push(ProtectedWorkload {
            rule_id: rule.id.clone(),
            display_name: rule.display_name.clone(),
            pid: process.pid,
            identity: process.identity(),
            owner_session: owner.as_ref().map(|(s, _)| s.clone()),
            owner_kind: owner.map(|(_, k)| k),
            started_at_ms: started_ms,
            running_ms,
            image_path: process.image_path.clone(),
            cmdline: process.cmdline.clone(),
            reason: if owner_kind_present(graph, process.pid, session_roots) {
                "spawned by a detected agent and still running".to_string()
            } else {
                format!(
                    "running for {}s, over the {}s threshold",
                    running_ms / 1000,
                    rule.min_runtime_secs
                )
            },
        });
    }

    // Newest first, so the UI shows what just started at the top.
    out.sort_by_key(|w| std::cmp::Reverse(w.started_at_ms));
    out.truncate(64);
    out
}

fn owner_kind_present(graph: &ProcessGraph, pid: u32, roots: &[(u32, String, String)]) -> bool {
    roots
        .iter()
        .any(|(root, _, _)| *root != pid && graph.subtree(*root, 512).contains(&pid))
}

/// Build candidates for processes that look agent-like but scored below the reporting bar.
///
/// These are surfaced in diagnostics and can be promoted into a local signature, which is how
/// an unknown agent becomes a known one without a code change. They never block shutdown.
pub fn collect_candidates(
    engine: &DetectionEngine,
    graph: &ProcessGraph,
    now_ms: i64,
) -> Vec<AgentCandidate> {
    let mut out = Vec::new();

    for process in graph.iter() {
        let reasons = engine.explain(process, graph);
        for r in reasons {
            // Only report a candidate when something actually matched a rule; a process with
            // no matching evidence at all is not a candidate, it is just a process.
            if r.score <= 0 {
                continue;
            }
            out.push(AgentCandidate {
                candidate_id: format!("{}:{}", process.name_lower(), r.signature_id),
                pid: process.pid,
                identity: process.identity(),
                name: process.name.clone(),
                image_path: process.image_path.clone(),
                cmdline: process.cmdline.clone(),
                confidence: Confidence::Possible,
                evidence: vec![Evidence::new(
                    "near_miss",
                    r.signature_id.clone(),
                    r.score,
                    format!(
                        "matched {} point(s) for '{}' but {}",
                        r.score, r.signature_id, r.explanation
                    ),
                )],
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                observations: 1,
            });
        }
    }

    // Deduplicate by candidate id, keeping the highest-scoring observation.
    out.sort_by(|a, b| (a.candidate_id.as_str(), a.pid).cmp(&(b.candidate_id.as_str(), b.pid)));
    out.dedup_by(|a, b| a.candidate_id == b.candidate_id && a.pid == b.pid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::{Rule, SignatureRules};

    fn sig(id: &str, conf: SignatureConfidence, rules: SignatureRules) -> AgentSignature {
        AgentSignature {
            id: id.into(),
            display_name: id.into(),
            user_defined: false,
            confidence: conf,
            rules,
            adapter: None,
            notes: String::new(),
        }
    }

    fn rule(field: RuleField, pattern: &str, weight: i32) -> Rule {
        Rule {
            field,
            pattern: pattern.into(),
            weight,
            detail: format!("matched {pattern}"),
        }
    }

    fn proc(pid: u32, parent: u32, name: &str, cmdline: Option<&str>) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            parent_pid: parent,
            name: name.into(),
            image_path: Some(format!(r"C:\tools\{name}")),
            cmdline: cmdline.map(|s| s.to_string()),
            created_filetime: pid as u64,
            session_id: 1,
            user_sid: None,
            cmdline_denied: false,
        }
    }

    #[test]
    fn a_single_high_weight_rule_reaches_high_confidence() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "test",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"myagent\.exe", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "myagent.exe", None)]);
        let d = engine
            .inspect(graph.get(1).unwrap(), &graph)
            .expect("detected");
        assert_eq!(d.confidence, Confidence::High);
        assert_eq!(d.score, 100);
        assert!(d.confidence.drives_protection());
    }

    #[test]
    fn corroborating_rules_reach_confirmed() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "test",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![
                        rule(RuleField::ProcessName, r"myagent\.exe", 100),
                        rule(RuleField::PackagePath, r"my-agent-pkg", 50),
                    ],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(
            1,
            0,
            "myagent.exe",
            Some(r"C:\tools\my-agent-pkg\bin\myagent.exe"),
        )]);
        let d = engine.inspect(graph.get(1).unwrap(), &graph).unwrap();
        assert_eq!(d.confidence, Confidence::Confirmed);
        assert!(d.score >= 150);
    }

    #[test]
    fn a_weak_rule_alone_stays_below_the_bar() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "weak",
                SignatureConfidence::Possible,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"thing\.exe", 10)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "thing.exe", None)]);
        let d = engine.inspect(graph.get(1).unwrap(), &graph).unwrap();
        assert_eq!(d.confidence, Confidence::Unknown);
        assert!(
            !d.confidence.drives_protection(),
            "a weak match must not trigger WORKING protection"
        );
    }

    #[test]
    fn signature_confidence_caps_the_result() {
        // A signature whose evidence is inherently ambiguous can never claim Confirmed,
        // however many rules match.
        let cfg = EngineConfig {
            signatures: vec![sig(
                "maybe-ide",
                SignatureConfidence::Possible,
                SignatureRules {
                    any_of: vec![
                        rule(RuleField::ProcessName, r"code\.exe", 100),
                        rule(RuleField::PackagePath, r"agent", 100),
                    ],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "Code.exe", Some(r"C:\Code\agent\main.js"))]);
        let d = engine.inspect(graph.get(1).unwrap(), &graph).unwrap();
        assert_eq!(
            d.confidence,
            Confidence::Possible,
            "an ambiguous signature must not exceed its declared confidence"
        );
        assert!(!d.confidence.drives_protection());
    }

    #[test]
    fn a_veto_rule_disqualifies_even_with_strong_positive_evidence() {
        // This is how an agent's own helper process avoids being counted as an agent.
        let cfg = EngineConfig {
            signatures: vec![sig(
                "agent",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    // A strong positive: "this process has a python child".
                    any_of: vec![rule(RuleField::ChildName, r"python\.exe", 100)],
                    all_of: vec![],
                    // A veto expressed on our own command line, which is a field that can
                    // actually match. The property under test is that a matching veto wins
                    // over strong positive evidence.
                    none_of: vec![rule(RuleField::CommandLine, r"server\.py", -1)],
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![
            proc(1, 0, "helper.exe", Some("python server.py")),
            proc(2, 1, "python.exe", Some("python server.py")),
        ]);
        assert!(
            engine.inspect(graph.get(1).unwrap(), &graph).is_none(),
            "a matching veto must disqualify the process despite strong positive evidence"
        );
    }

    #[test]
    fn command_line_veto_works() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "agent",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"python\.exe", 100)],
                    all_of: vec![],
                    none_of: vec![rule(
                        RuleField::CommandLine,
                        r"[/\\]ida_pro_mcp[/\\]server\.py",
                        -1,
                    )],
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(
            1,
            0,
            "python.exe",
            Some(r"C:\py\ida_pro_mcp\server.py"),
        )]);
        assert!(
            engine.inspect(graph.get(1).unwrap(), &graph).is_none(),
            "the MCP helper must be vetoed, not detected as an agent"
        );
    }

    #[test]
    fn all_of_requires_every_rule() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "strict",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![],
                    all_of: vec![
                        rule(RuleField::ProcessName, r"node\.exe", 60),
                        rule(RuleField::CommandLine, r"some-cli-package", 60),
                    ],
                    none_of: vec![],
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);

        // Both conditions present.
        let g1 = ProcessGraph::new(vec![proc(
            1,
            0,
            "node.exe",
            Some("node C:\\npm\\some-cli-package\\cli.js"),
        )]);
        assert!(engine.inspect(g1.get(1).unwrap(), &g1).is_some());

        // Only the name matches: a plain node process must not be an agent.
        let g2 = ProcessGraph::new(vec![proc(1, 0, "node.exe", Some("node server.js"))]);
        assert!(
            engine.inspect(g2.get(1).unwrap(), &g2).is_none(),
            "an unrelated node process must not be detected"
        );

        // Only the command line matches, with the wrong image.
        let g3 = ProcessGraph::new(vec![proc(1, 0, "other.exe", Some("node some-cli-package"))]);
        assert!(engine.inspect(g3.get(1).unwrap(), &g3).is_none());
    }

    #[test]
    fn never_agent_list_is_absolute() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "everything",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r".*\.exe", 500)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(4, 0, "lsass.exe", None)]);
        assert!(
            engine.inspect(graph.get(4).unwrap(), &graph).is_none(),
            "a protected system process must never be reported as an agent"
        );
    }

    #[test]
    fn parent_rules_use_the_graph() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "child-of-terminal",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ParentName, r"^WindowsTerminal\.exe$", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![
            proc(1, 0, "WindowsTerminal.exe", None),
            proc(2, 1, "something.exe", None),
        ]);
        assert!(engine.inspect(graph.get(2).unwrap(), &graph).is_some());
        assert!(engine.inspect(graph.get(1).unwrap(), &graph).is_none());
    }

    #[test]
    fn child_rules_use_the_graph() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "has-agent-child",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ChildName, r"^claude\.exe$", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![
            proc(1, 0, "pwsh.exe", None),
            proc(2, 1, "claude.exe", None),
        ]);
        assert!(engine.inspect(graph.get(1).unwrap(), &graph).is_some());
        assert!(engine.inspect(graph.get(2).unwrap(), &graph).is_none());
    }

    #[test]
    fn a_signature_with_no_positive_rules_is_rejected_at_compile_time() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "useless",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![],
                    all_of: vec![],
                    none_of: vec![rule(RuleField::ProcessName, r".*", -100)],
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        assert_eq!(engine.signature_count(), 0);
        assert_eq!(engine.rejected_rules().len(), 1);
        assert!(engine.rejected_rules()[0]
            .reason
            .contains("no usable positive rule"));
    }

    #[test]
    fn an_invalid_pattern_is_rejected_without_disabling_the_signature() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "partly-broken",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![
                        rule(RuleField::ProcessName, r"good\.exe", 100),
                        rule(RuleField::CommandLine, "bad(unclosed", 50),
                    ],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        assert_eq!(engine.signature_count(), 1, "the signature still compiles");
        assert_eq!(engine.rejected_rules().len(), 1);
        assert!(engine.rejected_rules()[0].reason.contains("any_of"));

        let graph = ProcessGraph::new(vec![proc(1, 0, "good.exe", None)]);
        assert!(
            engine.inspect(graph.get(1).unwrap(), &graph).is_some(),
            "the surviving rule still works"
        );
    }

    #[test]
    fn highest_scoring_signature_wins_deterministically() {
        let cfg = EngineConfig {
            signatures: vec![
                sig(
                    "low",
                    SignatureConfidence::Confirmed,
                    SignatureRules {
                        any_of: vec![rule(RuleField::ProcessName, r"agent\.exe", 50)],
                        ..Default::default()
                    },
                ),
                sig(
                    "high",
                    SignatureConfidence::Confirmed,
                    SignatureRules {
                        any_of: vec![rule(RuleField::ProcessName, r"agent\.exe", 100)],
                        ..Default::default()
                    },
                ),
            ],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "agent.exe", None)]);
        let d = engine.inspect(graph.get(1).unwrap(), &graph).unwrap();
        assert_eq!(d.signature_id, "high");

        // Running again gives the same answer.
        let d2 = engine.inspect(graph.get(1).unwrap(), &graph).unwrap();
        assert_eq!(d.signature_id, d2.signature_id);
    }

    #[test]
    fn matching_is_case_insensitive() {
        // Windows paths and process names are case-insensitive; a rule must be too.
        let cfg = EngineConfig {
            signatures: vec![sig(
                "ci",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"Claude\.exe", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "CLAUDE.EXE", None)]);
        assert!(engine.inspect(graph.get(1).unwrap(), &graph).is_some());
    }

    #[test]
    fn missing_command_line_does_not_match_a_command_line_rule() {
        // A process whose command line could not be read must not be treated as though it
        // had no command line; absence of evidence is not evidence.
        let cfg = EngineConfig {
            signatures: vec![sig(
                "cmd",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::CommandLine, r".*", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let mut p = proc(1, 0, "x.exe", None);
        p.cmdline_denied = true;
        let graph = ProcessGraph::new(vec![p]);
        assert!(
            engine.inspect(graph.get(1).unwrap(), &graph).is_none(),
            "an unreadable command line must not match a wildcard"
        );
    }

    #[test]
    fn evidence_records_the_matched_text_and_weight() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "evidence",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"(claude)-\w*", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "claude-code.exe", None)]);
        let d = engine.inspect(graph.get(1).unwrap(), &graph).unwrap();
        assert_eq!(d.evidence.len(), 1);
        assert_eq!(d.evidence[0].code, "process_name");
        assert_eq!(d.evidence[0].matched, "claude-code");
        assert_eq!(d.evidence[0].weight, 100);
        assert!(!d.evidence[0].detail.is_empty());
    }

    #[test]
    fn explain_reports_a_veto_rather_than_nothing() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "vetoed",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"python\.exe", 100)],
                    none_of: vec![rule(RuleField::CommandLine, r"mcp", -1)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "python.exe", Some("python mcp/server.py"))]);
        let reasons = engine.explain(graph.get(1).unwrap(), &graph);
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].explanation.contains("vetoed"),
            "the veto must be the explanation: {reasons:?}"
        );
    }

    #[test]
    fn explain_reports_a_near_miss_score() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "weak",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"thing\.exe", 10)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "thing.exe", None)]);
        let reasons = engine.explain(graph.get(1).unwrap(), &graph);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].score, 10);
        assert!(reasons[0].explanation.contains("below"));
    }

    #[test]
    fn candidates_are_collected_for_near_misses() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "weak",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"mystery\.exe", 20)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![proc(1, 0, "mystery.exe", None)]);
        let candidates = collect_candidates(&engine, &graph, 1000);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "mystery.exe");
        assert!(candidates[0].candidate_id.contains("mystery"));
        assert_eq!(candidates[0].confidence, Confidence::Possible);
    }

    #[test]
    fn unrelated_processes_produce_no_candidates() {
        let cfg = EngineConfig {
            signatures: vec![sig(
                "specific",
                SignatureConfidence::Confirmed,
                SignatureRules {
                    any_of: vec![rule(RuleField::ProcessName, r"claude\.exe", 100)],
                    ..Default::default()
                },
            )],
            ..Default::default()
        };
        let engine = DetectionEngine::new(cfg);
        let graph = ProcessGraph::new(vec![
            proc(1, 0, "chrome.exe", None),
            proc(2, 0, "explorer.exe", None),
        ]);
        assert!(collect_candidates(&engine, &graph, 1000).is_empty());
    }
}
