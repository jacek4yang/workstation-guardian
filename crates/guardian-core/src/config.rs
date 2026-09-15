//! Configuration validation and migration.
//!
//! Two hard requirements drive the design:
//!
//! 1. **Bad configuration must not prevent update protection from starting.** Validation
//!    returns a corrected document plus warnings; it never returns "unusable".
//! 2. **Unknown future fields must not be destroyed.** The validator edits the document in
//!    place and leaves everything it does not recognise untouched.
//!
//! Migrations move an old `schema_version` forward. A document from a *newer* schema is
//! accepted as-is (best effort) rather than rejected, because refusing to start would be a
//! protection outage caused by a version skew.

use guardian_proto::model::*;
use regex::Regex;

/// Maximum length of a user-supplied regex. Patterns longer than this are almost always a
/// mistake, and bounding the length bounds the compile cost.
pub const MAX_PATTERN_LEN: usize = 512;

/// Maximum number of user signatures, to bound per-sweep matching cost.
pub const MAX_USER_SIGNATURES: usize = 256;

/// Maximum number of probes, to bound per-round network work.
pub const MAX_PROBES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    /// Fixed automatically; the stored document will differ from the input.
    Corrected,
    /// Kept but suspicious.
    Warning,
    /// The field was rejected and replaced with the default.
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    /// Dotted path of the offending field, e.g. `network.probes[2].target`.
    pub path: String,
    pub severity: Severity,
    pub message: String,
}

impl ConfigIssue {
    fn corrected(path: &str, message: impl Into<String>) -> Self {
        ConfigIssue {
            path: path.into(),
            severity: Severity::Corrected,
            message: message.into(),
        }
    }
    fn rejected(path: &str, message: impl Into<String>) -> Self {
        ConfigIssue {
            path: path.into(),
            severity: Severity::Rejected,
            message: message.into(),
        }
    }
    fn warning(path: &str, message: impl Into<String>) -> Self {
        ConfigIssue {
            path: path.into(),
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

/// The result of validating a document.
#[derive(Debug, Clone)]
pub struct Validated {
    pub document: ConfigDocument,
    pub issues: Vec<ConfigIssue>,
    /// True when validation changed anything, so the caller knows to re-persist.
    pub changed: bool,
}

impl Validated {
    pub fn has_rejections(&self) -> bool {
        self.issues.iter().any(|i| i.severity == Severity::Rejected)
    }
}

/// Load a document from JSON text, migrating and validating it.
///
/// Never fails: a document that cannot be parsed at all yields defaults with a rejection
/// recorded. The caller keeps protecting updates either way.
pub fn load_from_str(text: &str) -> Validated {
    match serde_json::from_str::<ConfigDocument>(text) {
        Ok(doc) => validate(migrate(doc)),
        Err(e) => {
            let mut v = validate(ConfigDocument::default());
            v.issues.push(ConfigIssue::rejected(
                "<document>",
                format!("configuration could not be parsed ({e}); using safe defaults"),
            ));
            v
        }
    }
}

/// Bring an older schema forward.
///
/// Migrations must be *additive and idempotent*. There is only one released schema today,
/// so this is where the framework lives rather than a set of real steps.
pub fn migrate(mut doc: ConfigDocument) -> ConfigDocument {
    // A document from the future: leave it exactly as-is. Downgrading fields we do not
    // understand would silently discard a newer build's settings.
    if doc.schema_version > CONFIG_SCHEMA_VERSION {
        return doc;
    }

    // Example of the shape future migrations take:
    //
    //   if doc.schema_version < 2 {
    //       doc.body.network.wifi_warm_standby = true;
    //       doc.schema_version = 2;
    //   }
    //
    // Kept as documentation of intent; no steps are needed at version 1 yet.

    doc.schema_version = CONFIG_SCHEMA_VERSION;
    doc
}

/// Validate and repair a document in place.
pub fn validate(mut doc: ConfigDocument) -> Validated {
    let mut issues = Vec::new();
    let before = serde_json::to_string(&doc).unwrap_or_default();

    validate_update(&mut doc.body.update, &mut issues);
    validate_network(&mut doc.body.network, &mut issues);
    validate_agents(&mut doc.body.agents, &mut issues);
    validate_maintenance(&mut doc.body.maintenance, &mut issues);
    validate_storage(&mut doc.body.storage, &mut issues);
    validate_logging(&mut doc.body.logging, &mut issues);

    // Schema version is always normalised on the way out.
    doc.schema_version = CONFIG_SCHEMA_VERSION;

    let after = serde_json::to_string(&doc).unwrap_or_default();
    Validated {
        document: doc,
        issues,
        changed: before != after,
    }
}

fn validate_update(c: &mut UpdateConfig, issues: &mut Vec<ConfigIssue>) {
    // Verification interval bounds. The lower bound is a deliberate floor: constant
    // registry polling would be a real resource cost for no benefit, since nothing changes
    // the policy between passes except something that would be caught within a couple of
    // minutes anyway.
    if c.verify_interval_secs < 30 {
        issues.push(ConfigIssue::corrected(
            "update.verify_interval_secs",
            "raised to the 30s minimum to avoid constant registry polling",
        ));
        c.verify_interval_secs = 30;
    }
    if c.verify_interval_secs > 3600 {
        issues.push(ConfigIssue::corrected(
            "update.verify_interval_secs",
            "clamped to 3600s; longer gaps would let tampering go unnoticed for too long",
        ));
        c.verify_interval_secs = 3600;
    }
    // Deliberately *not* corrected: `protect = false` is a legitimate operator choice and
    // silently re-enabling it would be a lie about the stored configuration. It is
    // surfaced as a warning so the UI can make it prominent.
    if !c.protect {
        issues.push(ConfigIssue::warning(
            "update.protect",
            "update protection is disabled in configuration; the machine is not protected",
        ));
    }
}

fn validate_network(c: &mut NetworkConfig, issues: &mut Vec<ConfigIssue>) {
    if c.check_interval_secs < 5 {
        issues.push(ConfigIssue::corrected(
            "network.check_interval_secs",
            "raised to the 5s minimum to bound probe traffic",
        ));
        c.check_interval_secs = 5;
    }
    if c.check_interval_secs > 300 {
        issues.push(ConfigIssue::corrected(
            "network.check_interval_secs",
            "clamped to 300s; a longer interval would delay failover too much",
        ));
        c.check_interval_secs = 300;
    }
    if c.failure_quorum == 0 {
        issues.push(ConfigIssue::corrected(
            "network.failure_quorum",
            "raised to 1; a quorum of zero would declare the link down immediately",
        ));
        c.failure_quorum = 1;
    }
    if c.success_quorum == 0 {
        issues.push(ConfigIssue::corrected(
            "network.success_quorum",
            "raised to 1; a quorum of zero would flap",
        ));
        c.success_quorum = 1;
    }
    // The stabilization window is the primary anti-flap control; a zero value would allow
    // the exact thrash this project must avoid.
    if c.stabilize_secs < 5 {
        issues.push(ConfigIssue::corrected(
            "network.stabilize_secs",
            "raised to 5s; a shorter window permits route flapping",
        ));
        c.stabilize_secs = 5;
    }

    if c.probes.is_empty() {
        issues.push(ConfigIssue::warning(
            "network.probes",
            "no connectivity probes configured; the built-in set will be used",
        ));
        c.probes = default_probes();
    }
    if c.probes.len() > MAX_PROBES {
        issues.push(ConfigIssue::corrected(
            "network.probes",
            format!("truncated to {MAX_PROBES} probes"),
        ));
        c.probes.truncate(MAX_PROBES);
    }

    let mut seen_ids = Vec::new();
    let mut keep = Vec::with_capacity(c.probes.len());
    for (i, p) in c.probes.drain(..).enumerate() {
        let path = format!("network.probes[{i}]");
        if p.id.trim().is_empty() {
            issues.push(ConfigIssue::rejected(&path, "probe has no id; dropped"));
            continue;
        }
        if seen_ids.contains(&p.id) {
            issues.push(ConfigIssue::rejected(
                &path,
                format!("duplicate probe id '{}'; dropped", p.id),
            ));
            continue;
        }
        if !probe_target_is_valid(&p) {
            issues.push(ConfigIssue::rejected(
                &path,
                format!(
                    "invalid {} target '{}'; dropped",
                    kind_name(p.kind),
                    p.target
                ),
            ));
            continue;
        }
        let mut p = p;
        if p.timeout_ms == 0 || p.timeout_ms > 30_000 {
            p.timeout_ms = p.timeout_ms.clamp(250, 30_000);
            issues.push(ConfigIssue::corrected(
                &format!("{path}.timeout_ms"),
                format!("clamped to {}ms", p.timeout_ms),
            ));
        }
        seen_ids.push(p.id.clone());
        keep.push(p);
    }
    c.probes = keep;

    if c.probes.iter().filter(|p| p.enabled).count() == 0 {
        issues.push(ConfigIssue::warning(
            "network.probes",
            "every probe is disabled; connectivity cannot be judged",
        ));
    }
}

fn kind_name(k: ProbeKind) -> &'static str {
    match k {
        ProbeKind::Tcp => "tcp",
        ProbeKind::Dns => "dns",
        ProbeKind::RasState => "ras",
        ProbeKind::Interface => "interface",
    }
}

/// Validate a probe target. For TCP, require `host:port` with a numeric port in range.
/// Hostnames are checked for obviously invalid characters rather than resolved, because
/// validation must not perform network I/O.
fn probe_target_is_valid(p: &ProbeConfig) -> bool {
    let t = p.target.trim();
    if t.is_empty() || t.len() > 255 {
        return false;
    }
    match p.kind {
        ProbeKind::Tcp => {
            let Some((host, port)) = t.rsplit_once(':') else {
                return false;
            };
            if host.is_empty() {
                return false;
            }
            match port.parse::<u16>() {
                Ok(p) => p != 0,
                Err(_) => false,
            }
        }
        ProbeKind::Dns => !t.contains(':') && !t.contains('/'),
        ProbeKind::RasState | ProbeKind::Interface => true,
    }
}

fn validate_agents(c: &mut AgentConfig, issues: &mut Vec<ConfigIssue>) {
    if c.sweep_interval_secs < 1 {
        issues.push(ConfigIssue::corrected(
            "agents.sweep_interval_secs",
            "raised to 1s",
        ));
        c.sweep_interval_secs = 1;
    }
    if c.sweep_interval_secs > 300 {
        issues.push(ConfigIssue::corrected(
            "agents.sweep_interval_secs",
            "clamped to 300s",
        ));
        c.sweep_interval_secs = 300;
    }
    if c.fallback_poll_interval_secs < 1 {
        issues.push(ConfigIssue::corrected(
            "agents.fallback_poll_interval_secs",
            "raised to 1s; sub-second polling is a 24/7 resource cost for no benefit",
        ));
        c.fallback_poll_interval_secs = 1;
    }

    if c.user_signatures.len() > MAX_USER_SIGNATURES {
        issues.push(ConfigIssue::corrected(
            "agents.user_signatures",
            format!("truncated to {MAX_USER_SIGNATURES} signatures"),
        ));
        c.user_signatures.truncate(MAX_USER_SIGNATURES);
    }

    let mut seen = Vec::new();
    let mut keep = Vec::with_capacity(c.user_signatures.len());
    for (i, sig) in c.user_signatures.drain(..).enumerate() {
        let path = format!("agents.user_signatures[{i}]");
        match validate_signature(sig, &path, issues) {
            Some(s) => {
                if seen.contains(&s.id) {
                    issues.push(ConfigIssue::rejected(
                        &path,
                        format!("duplicate signature id '{}'; dropped", s.id),
                    ));
                    continue;
                }
                seen.push(s.id.clone());
                keep.push(s);
            }
            None => continue,
        }
    }
    c.user_signatures = keep;

    let mut seen_rules = Vec::new();
    let mut keep_rules = Vec::with_capacity(c.user_workload_rules.len());
    #[allow(clippy::needless_range_loop)]
    for (i, rule) in c.user_workload_rules.drain(..).enumerate() {
        let path = format!("agents.user_workload_rules[{i}]");
        if rule.id.trim().is_empty() {
            issues.push(ConfigIssue::rejected(
                &path,
                "workload rule has no id; dropped",
            ));
            continue;
        }
        if seen_rules.contains(&rule.id) {
            issues.push(ConfigIssue::rejected(
                &path,
                format!("duplicate workload rule id '{}'; dropped", rule.id),
            ));
            continue;
        }
        if let Err(msg) = validate_pattern(&rule.name_pattern) {
            issues.push(ConfigIssue::rejected(
                &format!("{path}.name_pattern"),
                format!("{msg}; dropped"),
            ));
            continue;
        }
        if let Some(cp) = &rule.cmdline_pattern {
            if let Err(msg) = validate_pattern(cp) {
                issues.push(ConfigIssue::rejected(
                    &format!("{path}.cmdline_pattern"),
                    format!("{msg}; dropped"),
                ));
                continue;
            }
        }
        seen_rules.push(rule.id.clone());
        keep_rules.push(rule);
    }
    c.user_workload_rules = keep_rules;
}

/// Validate a single signature. Returns `None` when it must be dropped entirely (no
/// usable rules), otherwise the repaired signature.
fn validate_signature(
    mut sig: AgentSignature,
    path: &str,
    issues: &mut Vec<ConfigIssue>,
) -> Option<AgentSignature> {
    if sig.id.trim().is_empty() {
        issues.push(ConfigIssue::rejected(path, "signature has no id; dropped"));
        return None;
    }
    if sig.display_name.trim().is_empty() {
        sig.display_name = sig.id.clone();
        issues.push(ConfigIssue::corrected(
            &format!("{path}.display_name"),
            "was empty; set to the signature id",
        ));
    }
    sig.user_defined = true;

    let mut drop_signature = false;
    for (list_name, rules) in [
        ("any_of", &mut sig.rules.any_of),
        ("all_of", &mut sig.rules.all_of),
        ("none_of", &mut sig.rules.none_of),
    ] {
        let mut keep = Vec::with_capacity(rules.len());
        for (i, rule) in rules.iter().enumerate() {
            let rpath = format!("{path}.rules.{list_name}[{i}]");
            match validate_pattern(&rule.pattern) {
                Ok(()) => keep.push(rule.clone()),
                Err(msg) => issues.push(ConfigIssue::rejected(
                    &rpath,
                    format!("{msg}; rule dropped"),
                )),
            }
        }
        *rules = keep;
    }

    // A signature with no positive rule can never match, and one with only vetoes is a
    // footgun that silently disables detection for everything.
    if sig.rules.any_of.is_empty() && sig.rules.all_of.is_empty() {
        issues.push(ConfigIssue::rejected(
            path,
            "signature has no positive rule (any_of/all_of); dropped",
        ));
        drop_signature = true;
    }
    if sig.rules.none_of.len() > 32 {
        issues.push(ConfigIssue::corrected(
            &format!("{path}.rules.none_of"),
            "truncated to 32 veto rules",
        ));
        sig.rules.none_of.truncate(32);
    }

    if drop_signature {
        None
    } else {
        Some(sig)
    }
}

/// Validate a user-supplied regex.
///
/// Rejects patterns that could consume unreasonable CPU. Rust's `regex` crate is a
/// finite-automata engine with linear-time matching and no backreferences, so
/// catastrophic backtracking is structurally impossible. The remaining risks are
/// unbounded repetition over a very large input and plain compile cost, which the length
/// cap and the nesting check address.
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("pattern is empty".into());
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!(
            "pattern is {} bytes, over the {MAX_PATTERN_LEN} byte limit",
            pattern.len()
        ));
    }
    // Reject explicit counted repetition with a huge bound; it can blow up compile time
    // and memory in the automaton.
    if let Some(cap) = max_repetition_bound(pattern) {
        if cap > 1000 {
            return Err(format!("repetition bound {cap} is too large"));
        }
    }
    // Deeply nested groups make the automaton expensive to build.
    if nesting_depth(pattern) > 8 {
        return Err("pattern nests groups more than 8 deep".into());
    }
    Regex::new(pattern).map(|_| ()).map_err(|e| {
        // Collapse the multi-line regex error into one line for a config warning.
        let msg = e.to_string().replace('\n', " ");
        format!("invalid regular expression: {msg}")
    })
}

/// Find the largest `{n}` or `{n,}` bound in a pattern, if any.
fn max_repetition_bound(pattern: &str) -> Option<u64> {
    let bytes = pattern.as_bytes();
    let mut max = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped character
            continue;
        }
        if bytes[i] == b'{' {
            if let Some(end) = pattern[i..].find('}') {
                let inner = &pattern[i + 1..i + end];
                for part in inner.split(',') {
                    let part = part.trim();
                    if !part.is_empty() {
                        if let Ok(n) = part.parse::<u64>() {
                            max = Some(max.map_or(n, |m: u64| m.max(n)));
                        }
                    }
                }
                i += end + 1;
                continue;
            }
        }
        i += 1;
    }
    max
}

/// Approximate group nesting depth, ignoring escaped brackets and character classes.
fn nesting_depth(pattern: &str) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            chars.next();
            continue;
        }
        match c {
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => {
                depth += 1;
                max = max.max(depth);
            }
            ')' if !in_class => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn validate_maintenance(c: &mut MaintenanceConfig, issues: &mut Vec<ConfigIssue>) {
    // Reuse the machine's own bounds so configuration cannot widen the window beyond what
    // the state machine permits.
    let min = crate::maintenance::MIN_TTL_SECS;
    let max = crate::maintenance::MAX_TTL_SECS;
    if c.reboot_token_ttl_secs < min {
        issues.push(ConfigIssue::corrected(
            "maintenance.reboot_token_ttl_secs",
            format!("raised to the {min}s minimum"),
        ));
        c.reboot_token_ttl_secs = min;
    }
    if c.reboot_token_ttl_secs > max {
        issues.push(ConfigIssue::corrected(
            "maintenance.reboot_token_ttl_secs",
            format!("clamped to {max}s; a longer window risks a forgotten permit"),
        ));
        c.reboot_token_ttl_secs = max;
    }
    if c.override_phrase.trim().is_empty() {
        issues.push(ConfigIssue::corrected(
            "maintenance.override_phrase",
            "was empty, which would let any input satisfy the confirmation",
        ));
        c.override_phrase = MaintenanceConfig::default().override_phrase;
    }
    if !c.refuse_with_protected_work {
        issues.push(ConfigIssue::warning(
            "maintenance.refuse_with_protected_work",
            "maintenance can be entered while protected work is running",
        ));
    }
}

fn validate_storage(c: &mut StorageConfig, issues: &mut Vec<ConfigIssue>) {
    if let Some(dir) = &c.data_dir {
        let trimmed = dir.trim();
        if trimmed.is_empty() {
            issues.push(ConfigIssue::corrected(
                "storage.data_dir",
                "was empty; using the default ProgramData location",
            ));
            c.data_dir = None;
        } else if !is_plausible_absolute_windows_path(trimmed) {
            // A relative path here would resolve against the service's working directory,
            // which is attacker-influenced in principle and surprising in practice.
            issues.push(ConfigIssue::rejected(
                "storage.data_dir",
                format!("'{trimmed}' is not an absolute local path; using the default"),
            ));
            c.data_dir = None;
        } else if trimmed.split(['\\', '/']).any(|part| part == "..") {
            issues.push(ConfigIssue::rejected(
                "storage.data_dir",
                "path contains '..'; refusing to use it",
            ));
            c.data_dir = None;
        }
    }
    if c.journal_max_bytes < 256 * 1024 {
        issues.push(ConfigIssue::corrected(
            "storage.journal_max_bytes",
            "raised to 256 KiB",
        ));
        c.journal_max_bytes = 256 * 1024;
    }
}

fn validate_logging(c: &mut LoggingConfig, issues: &mut Vec<ConfigIssue>) {
    const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];
    let lvl = c.level.trim().to_ascii_lowercase();
    if !LEVELS.contains(&lvl.as_str()) {
        issues.push(ConfigIssue::rejected(
            "logging.level",
            format!("'{}' is not a log level; using 'info'", c.level),
        ));
        c.level = "info".into();
    } else {
        c.level = lvl;
    }
    if c.max_files == 0 {
        issues.push(ConfigIssue::corrected(
            "logging.max_files",
            "raised to 1; zero would discard logs entirely",
        ));
        c.max_files = 1;
    }
    if c.max_files > 64 {
        issues.push(ConfigIssue::corrected("logging.max_files", "clamped to 64"));
        c.max_files = 64;
    }
    if c.max_total_bytes < c.max_files as u64 * 4096 {
        let floor = c.max_files as u64 * 4096;
        issues.push(ConfigIssue::corrected(
            "logging.max_total_bytes",
            format!("raised to {floor} bytes so every retained file has room"),
        ));
        c.max_total_bytes = floor;
    }
}

/// Conservative check for a rooted local path. Does not touch the filesystem: this runs
/// during validation which must not perform I/O, and existence is checked separately.
fn is_plausible_absolute_windows_path(p: &str) -> bool {
    let bytes: Vec<char> = p.chars().collect();
    // Drive-letter form: `C:\...`
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == ':'
        && (bytes[2] == '\\' || bytes[2] == '/')
    {
        return true;
    }
    // UNC form: `\\server\share`. Requires *both* a server and a share component; a bare
    // `\\server` is not a usable directory and must not slip through as "plausible".
    if let Some(rest) = p.strip_prefix(r"\\") {
        let mut parts = rest.split(['\\', '/']).filter(|s| !s.is_empty());
        let server = parts.next();
        let share = parts.next();
        return server.is_some() && share.is_some();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_cleanly() {
        let v = validate(ConfigDocument::default());
        assert!(
            v.issues.is_empty(),
            "defaults must not need repair: {:?}",
            v.issues
        );
        assert!(!v.changed);
        assert!(v.document.body.update.protect);
    }

    #[test]
    fn json_round_trip_of_defaults_is_stable() {
        let text = serde_json::to_string(&ConfigDocument::default()).unwrap();
        let v = load_from_str(&text);
        assert!(v.issues.is_empty());
        let again = serde_json::to_string(&v.document).unwrap();
        assert_eq!(text, again, "validation must be a fixed point on defaults");
    }

    #[test]
    fn unparseable_config_yields_safe_defaults() {
        let v = load_from_str("{ this is not json");
        assert!(v.has_rejections());
        assert!(
            v.document.body.update.protect,
            "bad config must never disable update protection"
        );
    }

    #[test]
    fn empty_string_yields_defaults() {
        let v = load_from_str("");
        assert!(v.has_rejections());
        assert!(v.document.body.update.protect);
    }

    #[test]
    fn absurd_intervals_are_clamped_into_range() {
        let mut doc = ConfigDocument::default();
        doc.body.update.verify_interval_secs = 0;
        doc.body.network.check_interval_secs = 100_000;
        doc.body.network.stabilize_secs = 0;
        doc.body.agents.fallback_poll_interval_secs = 0;
        let v = validate(doc);
        assert_eq!(v.document.body.update.verify_interval_secs, 30);
        assert_eq!(v.document.body.network.check_interval_secs, 300);
        assert_eq!(v.document.body.network.stabilize_secs, 5);
        assert_eq!(v.document.body.agents.fallback_poll_interval_secs, 1);
        assert!(v.changed);
    }

    #[test]
    fn zero_quorums_are_raised() {
        let mut doc = ConfigDocument::default();
        doc.body.network.failure_quorum = 0;
        doc.body.network.success_quorum = 0;
        let v = validate(doc);
        assert_eq!(v.document.body.network.failure_quorum, 1);
        assert_eq!(v.document.body.network.success_quorum, 1);
    }

    #[test]
    fn bad_probe_targets_are_dropped_but_good_ones_survive() {
        let mut doc = ConfigDocument::default();
        doc.body.network.probes = vec![
            ProbeConfig {
                id: "good".into(),
                kind: ProbeKind::Tcp,
                target: "1.1.1.1:443".into(),
                timeout_ms: 2000,
                enabled: true,
            },
            ProbeConfig {
                id: "no-port".into(),
                kind: ProbeKind::Tcp,
                target: "1.1.1.1".into(),
                timeout_ms: 2000,
                enabled: true,
            },
            ProbeConfig {
                id: "bad-port".into(),
                kind: ProbeKind::Tcp,
                target: "host:99999".into(),
                timeout_ms: 2000,
                enabled: true,
            },
            ProbeConfig {
                id: "dnsthing".into(),
                kind: ProbeKind::Dns,
                target: "example.com".into(),
                timeout_ms: 2000,
                enabled: true,
            },
        ];
        let v = validate(doc);
        let ids: Vec<_> = v
            .document
            .body
            .network
            .probes
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, vec!["good", "dnsthing"]);
        assert!(v.issues.iter().any(|i| i.path.contains("[1]")));
    }

    #[test]
    fn duplicate_probe_ids_are_deduped() {
        let mut doc = ConfigDocument::default();
        doc.body.network.probes = vec![
            ProbeConfig {
                id: "dup".into(),
                kind: ProbeKind::Dns,
                target: "a.test".into(),
                timeout_ms: 1000,
                enabled: true,
            },
            ProbeConfig {
                id: "dup".into(),
                kind: ProbeKind::Dns,
                target: "b.test".into(),
                timeout_ms: 1000,
                enabled: true,
            },
        ];
        let v = validate(doc);
        assert_eq!(v.document.body.network.probes.len(), 1);
    }

    #[test]
    fn empty_probe_list_is_replaced_with_the_default_set() {
        let mut doc = ConfigDocument::default();
        doc.body.network.probes.clear();
        let v = validate(doc);
        assert_eq!(v.document.body.network.probes, default_probes());
    }

    #[test]
    fn signature_with_no_positive_rule_is_dropped() {
        let mut doc = ConfigDocument::default();
        doc.body.agents.user_signatures = vec![AgentSignature {
            id: "useless".into(),
            display_name: "Useless".into(),
            user_defined: true,
            confidence: SignatureConfidence::High,
            rules: SignatureRules {
                any_of: vec![],
                all_of: vec![],
                none_of: vec![Rule {
                    field: RuleField::ProcessName,
                    pattern: ".*".into(),
                    weight: -100,
                    detail: "veto everything".into(),
                }],
            },
            adapter: None,
            notes: String::new(),
        }];
        let v = validate(doc);
        assert!(v.document.body.agents.user_signatures.is_empty());
        assert!(v.has_rejections());
    }

    #[test]
    fn invalid_regex_is_rejected_and_valid_one_kept() {
        let mut doc = ConfigDocument::default();
        doc.body.agents.user_signatures = vec![AgentSignature {
            id: "mixed".into(),
            display_name: "Mixed".into(),
            user_defined: true,
            confidence: SignatureConfidence::High,
            rules: SignatureRules {
                any_of: vec![
                    Rule {
                        field: RuleField::ProcessName,
                        pattern: "myagent\\.exe".into(),
                        weight: 100,
                        detail: "ok".into(),
                    },
                    Rule {
                        field: RuleField::CommandLine,
                        pattern: "unclosed(".into(),
                        weight: 50,
                        detail: "broken".into(),
                    },
                ],
                all_of: vec![],
                none_of: vec![],
            },
            adapter: None,
            notes: String::new(),
        }];
        let v = validate(doc);
        let sig = &v.document.body.agents.user_signatures[0];
        assert_eq!(sig.rules.any_of.len(), 1, "the valid rule survives");
        assert_eq!(sig.rules.any_of[0].pattern, "myagent\\.exe");
        assert!(v
            .issues
            .iter()
            .any(|i| i.message.contains("invalid regular expression")));
    }

    #[test]
    fn pathological_patterns_are_rejected_by_validation() {
        // Length cap.
        assert!(validate_pattern(&"a".repeat(MAX_PATTERN_LEN + 1)).is_err());
        // Huge counted repetition.
        assert!(validate_pattern("a{1,100000}").is_err());
        // Excessive nesting.
        let deep = format!("{}a{}", "(".repeat(12), ")".repeat(12));
        assert!(validate_pattern(&deep).is_err());
        // Sane patterns pass.
        assert!(validate_pattern("claude(-code)?\\.exe").is_ok());
        assert!(validate_pattern(r"@anthropic-ai[/\\]claude-code").is_ok());
        // Escaped braces are not treated as repetition.
        assert!(validate_pattern(r"literal\{5000\}").is_ok());
    }

    #[test]
    fn empty_pattern_is_rejected() {
        assert!(validate_pattern("").is_err());
    }

    #[test]
    fn nesting_depth_ignores_escapes_and_classes() {
        assert_eq!(nesting_depth(r"\(\("), 0);
        assert_eq!(nesting_depth("[(]"), 0);
        assert_eq!(nesting_depth("(a(b))"), 2);
        assert_eq!(nesting_depth(r"\\(a"), 1);
    }

    #[test]
    fn maintenance_ttl_is_clamped_to_the_state_machine_window() {
        let mut doc = ConfigDocument::default();
        doc.body.maintenance.reboot_token_ttl_secs = 1;
        let v = validate(doc);
        assert_eq!(
            v.document.body.maintenance.reboot_token_ttl_secs,
            crate::maintenance::MIN_TTL_SECS
        );

        let mut doc2 = ConfigDocument::default();
        doc2.body.maintenance.reboot_token_ttl_secs = u64::MAX;
        let v2 = validate(doc2);
        assert_eq!(
            v2.document.body.maintenance.reboot_token_ttl_secs,
            crate::maintenance::MAX_TTL_SECS
        );
    }

    #[test]
    fn empty_override_phrase_is_replaced() {
        let mut doc = ConfigDocument::default();
        doc.body.maintenance.override_phrase = "   ".into();
        let v = validate(doc);
        assert!(!v
            .document
            .body
            .maintenance
            .override_phrase
            .trim()
            .is_empty());
    }

    #[test]
    fn relative_or_traversal_data_dir_is_rejected() {
        for bad in [r"relative\path", r"..\..\Windows", r"\\server"] {
            let mut doc = ConfigDocument::default();
            doc.body.storage.data_dir = Some(bad.into());
            let v = validate(doc);
            assert!(
                v.document.body.storage.data_dir.is_none(),
                "{bad} must be rejected"
            );
        }
        let mut doc = ConfigDocument::default();
        doc.body.storage.data_dir = Some(r"D:\GuardianData".into());
        let v = validate(doc);
        assert_eq!(
            v.document.body.storage.data_dir.as_deref(),
            Some(r"D:\GuardianData")
        );
    }

    #[test]
    fn bad_log_level_falls_back_to_info() {
        let mut doc = ConfigDocument::default();
        doc.body.logging.level = "verbose".into();
        let v = validate(doc);
        assert_eq!(v.document.body.logging.level, "info");
        assert!(v.has_rejections());

        let mut doc2 = ConfigDocument::default();
        doc2.body.logging.level = "DEBUG".into();
        let v2 = validate(doc2);
        assert_eq!(v2.document.body.logging.level, "debug");
        assert!(v2.issues.is_empty());
    }

    #[test]
    fn disabling_protection_warns_but_is_respected() {
        // Silently re-enabling would make the stored config a lie; the operator must see
        // what they actually configured.
        let mut doc = ConfigDocument::default();
        doc.body.update.protect = false;
        let v = validate(doc);
        assert!(!v.document.body.update.protect);
        assert!(v
            .issues
            .iter()
            .any(|i| i.path == "update.protect" && i.severity == Severity::Warning));
    }

    #[test]
    fn newer_schema_is_left_alone() {
        let raw = serde_json::json!({
            "schema_version": 999,
            "update": { "protect": true, "auto_restore": true, "verify_interval_secs": 120,
                        "disable_bsod_auto_restart": false },
            "future_section": { "keep": "me" }
        });
        let doc: ConfigDocument = serde_json::from_value(raw).unwrap();
        let migrated = migrate(doc);
        assert_eq!(
            migrated.schema_version, 999,
            "a newer document must not be downgraded"
        );
        let re = serde_json::to_value(&migrated).unwrap();
        assert_eq!(re.get("future_section").unwrap()["keep"], "me");
    }

    #[test]
    fn validation_preserves_unknown_fields() {
        let raw = serde_json::json!({
            "schema_version": 1,
            "update": { "protect": true, "auto_restore": true, "verify_interval_secs": 0,
                        "disable_bsod_auto_restart": false },
            "brand_new_thing": [1, 2, 3]
        });
        let v = load_from_str(&raw.to_string());
        assert_eq!(
            v.document.body.update.verify_interval_secs, 30,
            "was repaired"
        );
        let re = serde_json::to_value(&v.document).unwrap();
        assert_eq!(
            re.get("brand_new_thing").unwrap(),
            &serde_json::json!([1, 2, 3]),
            "unknown fields must survive repair"
        );
    }

    #[test]
    fn validation_is_idempotent() {
        let mut doc = ConfigDocument::default();
        doc.body.update.verify_interval_secs = 0;
        doc.body.network.probes.clear();
        doc.body.agents.user_signatures = vec![AgentSignature {
            id: "s".into(),
            display_name: String::new(),
            user_defined: true,
            confidence: SignatureConfidence::High,
            rules: SignatureRules {
                any_of: vec![Rule {
                    field: RuleField::ProcessName,
                    pattern: "x".into(),
                    weight: 1,
                    detail: "d".into(),
                }],
                all_of: vec![],
                none_of: vec![],
            },
            adapter: None,
            notes: String::new(),
        }];

        let once = validate(doc).document;
        let twice = validate(once.clone());
        assert!(!twice.changed, "a second pass must find nothing to fix");
        assert_eq!(once, twice.document);
    }
}
