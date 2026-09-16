//! Human-readable rendering of protocol responses.
//!
//! Every user-facing string comes from `guardian_proto::i18n`, so the CLI, the tray panel and the
//! service cannot disagree about what a state is called. Rendering takes a `Lang`; nothing else
//! branches on language.
//!
//! Deliberately plain: a diagnostics tool's output is read in a terminal, often over a remote
//! session, and columns that line up are worth more than colour.

use guardian_proto::i18n::msg;
use guardian_proto::model::{
    AgentInstance, AgentInventory, Confidence, Incident, IncidentKind, InternetHealth,
    NetworkSnapshot, PendingRebootReport, PendingRebootVerdict, ProtectionLevel, ProtectionMode,
    StatusSnapshot,
};
use guardian_proto::{Lang, Response};

/// Render any response in the given language.
pub fn render_response(response: &Response, lang: Lang) -> String {
    match response {
        Response::Hello {
            protocol,
            service_version,
            ..
        } => format!("service version {service_version} (protocol {protocol})"),
        Response::Status { snapshot } => status_text(snapshot, lang),
        Response::Agents { inventory } => agents_text(inventory, lang),
        Response::Network { snapshot } => network_text(snapshot, lang),
        Response::Incidents { incidents } => incidents_text(incidents, lang),
        Response::PendingReboot { report } => pending_reboot_text(report, lang),
        Response::Config { config } => match serde_json::to_string_pretty(config) {
            Ok(s) => s,
            Err(e) => format!("could not render the configuration: {e}"),
        },
        Response::Health { report } => crate::doctor::render(report, lang),
        Response::RebootAuthorization { authorization } => match authorization.as_ref() {
            Some(auth) => {
                let issued = section(lang, "Issued at", "签发于");
                let expires = section(lang, "Expires at", "过期于");
                let by = section(lang, "Issued by", "签发人");
                let consumed = section(lang, "Consumed", "已消费");
                let not_yet = section(lang, "not yet", "尚未");
                format!(
                    "{}\n  {}  {}\n  {}  {}\n  {}  {}\n  {}  {}",
                    section(lang, "A single reboot is authorized.", "已授权一次重启。"),
                    issued,
                    format_ms(auth.issued_at_ms),
                    expires,
                    format_ms(auth.expires_at_ms),
                    by,
                    auth.issued_by,
                    consumed,
                    auth.consumed_at_ms
                        .map(format_ms)
                        .unwrap_or_else(|| not_yet.to_string())
                )
            }
            None => section(lang, "No reboot is authorized.", "未授权重启。").to_string(),
        },
        Response::Ok { message } => message.clone(),
        Response::Error { error } => format!("error: {error}"),
    }
}

/// Render the main status screen.
pub fn status_text(s: &StatusSnapshot, lang: Lang) -> String {
    let mut out = String::new();

    out.push_str("WORKSTATION GUARDIAN\n\n");

    out.push_str(&format!("{}\n", section(lang, "Protection", "保护")));
    row(
        &mut out,
        msg::UPDATE_PROTECTION.get(lang),
        level_label(s.update.level, lang),
    );
    row(
        &mut out,
        msg::RESTART_PROTECTION.get(lang),
        level_label(s.restart_protection, lang),
    );
    row(
        &mut out,
        msg::SERVICE.get(lang),
        if s.service.running {
            msg::RUNNING.get(lang)
        } else {
            msg::STOPPED.get(lang)
        },
    );
    row(&mut out, msg::MODE.get(lang), mode_label(s.mode, lang));
    row(
        &mut out,
        msg::UPTIME.get(lang),
        &format_duration(s.service.uptime_ms),
    );
    if !s.service.degraded_components.is_empty() {
        row(
            &mut out,
            msg::DEGRADED_COMPONENTS.get(lang),
            &s.service.degraded_components.join(", "),
        );
    }

    out.push('\n');
    out.push_str(&format!("{}\n", msg::NETWORK.get(lang)));
    row(
        &mut out,
        msg::INTERNET.get(lang),
        internet_label(s.network.internet, lang),
    );
    row(
        &mut out,
        msg::PPPOE.get(lang),
        s.network
            .entry_name
            .as_deref()
            .unwrap_or(msg::NOT_CONFIGURED.get(lang)),
    );
    row(
        &mut out,
        msg::RAS_STATE.get(lang),
        &format!("{:?}", s.network.ras_state),
    );
    if let Some(uptime) = s.network.uptime_ms {
        row(
            &mut out,
            msg::CONNECTION_UPTIME.get(lang),
            &format_duration(uptime),
        );
    }
    if let Some(last) = s.network.last_reconnect_ms {
        row(&mut out, msg::LAST_RECONNECT.get(lang), &format_ms(last));
    }
    if let Some(outage) = &s.network.current_outage {
        let ongoing = section(lang, "ongoing", "进行中");
        let attempts = section(lang, "attempts", "次尝试");
        row(
            &mut out,
            msg::OUTAGE.get(lang),
            &format!(
                "{ongoing}, {} ({} {attempts})",
                format_duration(outage.downtime_ms.unwrap_or(0)),
                outage.dial_attempts
            ),
        );
    }

    out.push('\n');
    out.push_str(&format!("{}\n", msg::ACTIVE_WORK.get(lang)));
    render_active_work(&mut out, &s.agents, lang);

    out.push('\n');
    out.push_str(&format!("{}\n", msg::PENDING_REBOOT.get(lang)));
    row(
        &mut out,
        verdict_label(s.pending_reboot.verdict, lang),
        &s.pending_reboot.reasons().join("; "),
    );

    if let Some(auth) = &s.reboot_authorization {
        out.push('\n');
        out.push_str(&format!("{}\n", section(lang, "Maintenance", "维护模式")));
        row(
            &mut out,
            section(lang, "One reboot authorized", "已授权一次重启"),
            &format!(
                "{} {}",
                section(lang, "until", "至"),
                format_ms(auth.expires_at_ms)
            ),
        );
    }

    if !s.maintenance_denial_reasons.is_empty() {
        out.push('\n');
        out.push_str(&format!(
            "{}\n",
            section(
                lang,
                "Maintenance would currently be refused:",
                "当前将拒绝进入维护模式："
            )
        ));
        for r in &s.maintenance_denial_reasons {
            out.push_str(&format!("  {r}\n"));
        }
    }

    out
}

/// The "active work" block, shared by the status screen and the agent listing.
fn render_active_work(out: &mut String, agents: &AgentInventory, lang: Lang) {
    if agents.agent_count() == 0 && agents.workloads.is_empty() {
        out.push_str(&format!("  {}\n", msg::NOTHING_DETECTED.get(lang)));
        return;
    }

    for group in &agents.agents {
        let live = group
            .instances
            .iter()
            .filter(|i| i.confidence.drives_protection())
            .count();
        if live > 0 {
            row(out, &group.display_name, &live.to_string());
        }
    }

    // Reported, but explicitly not counted: surfacing these without pretending they protect
    // anything is the honest presentation.
    for group in &agents.agents {
        let possible = group
            .instances
            .iter()
            .filter(|i| i.confidence == Confidence::Possible)
            .count();
        if possible > 0 {
            let unconfirmed = section(lang, "unconfirmed", "未确认");
            row(
                out,
                &group.display_name,
                &format!("{possible} ({unconfirmed})"),
            );
        }
    }

    if !agents.workloads.is_empty() {
        row(
            out,
            msg::BUILD.get(lang),
            &agents.workloads.len().to_string(),
        );
    }
}

/// Render the agent inventory in full.
pub fn agents_text(inventory: &AgentInventory, lang: Lang) -> String {
    let mut out = String::new();

    if inventory.agent_count() == 0 {
        out.push_str(&format!("{}\n", msg::NOTHING_DETECTED.get(lang)));
    } else {
        let n = inventory.agent_count();
        out.push_str(&format!(
            "{}\n\n",
            if lang.resolve() == Lang::ZhCn {
                format!("检测到 {n} 个 Agent")
            } else {
                format!("{n} agent(s) detected")
            }
        ));
    }

    for group in &inventory.agents {
        for instance in &group.instances {
            render_instance(&mut out, instance, lang);
        }
    }

    if !inventory.workloads.is_empty() {
        out.push_str(&format!(
            "{}\n\n",
            section(lang, "Protected workloads", "受保护的构建任务")
        ));
        for w in &inventory.workloads {
            out.push_str(&format!("{}\n", w.display_name));
            row(&mut out, msg::PID.get(lang), &w.pid.to_string());
            row(
                &mut out,
                section(lang, "Running for", "已运行"),
                &format_duration(w.running_ms),
            );
            if let Some(owner) = &w.owner_kind {
                row(&mut out, section(lang, "Owner", "归属"), owner);
            }
            row(&mut out, section(lang, "Reason", "原因"), &w.reason);
        }
    }

    if !inventory.candidates.is_empty() {
        out.push_str(&format!(
            "\n{}\n\n",
            section(
                lang,
                "Unconfirmed candidates (reported, not protected)",
                "未确认的候选（仅供参考，不受保护）"
            )
        ));
        for c in &inventory.candidates {
            let why = c
                .evidence
                .first()
                .map(|e| e.detail.clone())
                .unwrap_or_default();
            out.push_str(&format!("  {} (pid {}) — {why}\n", c.name, c.pid));
        }
        out.push_str(&format!(
            "\n{}\n",
            section(
                lang,
                "These never block shutdown. Promote one with a custom agent signature if it is \
                 really an agent.",
                "这些不会阻止关机。如果确实是 Agent，可通过自定义签名转为正式识别。"
            )
        ));
    }

    out
}

fn render_instance(out: &mut String, instance: &AgentInstance, lang: Lang) {
    out.push_str(&format!("{}\n", instance.display_name));
    row(
        out,
        section(lang, "Confidence", "置信度"),
        confidence_label(instance.confidence, lang),
    );
    row(
        out,
        section(lang, "PID / root", "进程号 / 根进程"),
        &format!("{} / {}", instance.pid, instance.root_pid),
    );
    row(out, section(lang, "Session", "会话"), &instance.session_id);
    if let Some(path) = &instance.image_path {
        row(out, section(lang, "Image", "镜像路径"), path);
    }
    if let Some(project) = &instance.project {
        let from = section(lang, "from", "来源");
        row(
            out,
            msg::PROJECT.get(lang),
            &format!("{} ({from} {})", project.name, project.source),
        );
    }
    match &instance.resume {
        guardian_proto::model::ResumeCapability::Available { handle, hint } => {
            row(out, msg::RESUME.get(lang), handle);
            row(out, section(lang, "Resume with", "恢复命令"), hint);
        }
        guardian_proto::model::ResumeCapability::Unsupported => {
            row(
                out,
                msg::RESUME.get(lang),
                section(lang, "unavailable", "不可用"),
            );
        }
        guardian_proto::model::ResumeCapability::Unavailable => {}
    }
    if !instance.evidence.is_empty() {
        row(out, section(lang, "Evidence", "证据"), "");
        for e in &instance.evidence {
            out.push_str(&format!("    [{}] {} — {}\n", e.code, e.matched, e.detail));
        }
    }
    out.push('\n');
}

/// Render the network snapshot.
pub fn network_text(n: &NetworkSnapshot, lang: Lang) -> String {
    let mut out = String::new();

    out.push_str(&format!("{}\n\n", msg::NETWORK.get(lang)));
    row(
        &mut out,
        msg::INTERNET.get(lang),
        internet_label(n.internet, lang),
    );
    row(
        &mut out,
        section(lang, "Phase", "阶段"),
        &format!("{:?}", n.phase),
    );
    row(
        &mut out,
        section(lang, "PPPoE entry", "PPPoE 条目"),
        n.entry_name
            .as_deref()
            .unwrap_or(msg::NOT_CONFIGURED.get(lang)),
    );
    row(
        &mut out,
        msg::RAS_STATE.get(lang),
        &format!("{:?}", n.ras_state),
    );
    if let Some(uptime) = n.uptime_ms {
        row(
            &mut out,
            msg::CONNECTION_UPTIME.get(lang),
            &format_duration(uptime),
        );
    }
    if let Some(last) = n.last_reconnect_ms {
        row(&mut out, msg::LAST_RECONNECT.get(lang), &format_ms(last));
    }
    row(
        &mut out,
        section(lang, "Quorum", "法定票数"),
        &if lang.resolve() == Lang::ZhCn {
            format!(
                "需 {}，当前 {} 次成功",
                n.quorum_required, n.consecutive_successes
            )
        } else {
            format!(
                "{} of {} required",
                n.consecutive_successes, n.quorum_required
            )
        },
    );
    row(
        &mut out,
        section(lang, "Backoff", "退避"),
        &format_duration(n.backoff_ms as i64),
    );
    if let Some(err) = &n.last_error {
        row(&mut out, section(lang, "Last error", "最近错误"), err);
    }

    out.push_str(&format!("\n  {}\n", section(lang, "Probes", "连通性探测")));
    if n.probes.is_empty() {
        out.push_str(&format!(
            "    {}\n",
            section(lang, "(none configured)", "（未配置）")
        ));
    }
    for p in &n.probes {
        let state = if p.ok {
            section(lang, "ok", "正常")
        } else {
            section(lang, "FAIL", "失败")
        };
        let detail = p
            .error
            .clone()
            .unwrap_or_else(|| p.latency_ms.map(|ms| format!("{ms}ms")).unwrap_or_default());
        out.push_str(&format!("    {:<24}{:<6}{}\n", p.id, state, detail));
    }

    if let Some(outage) = &n.current_outage {
        out.push_str(&format!(
            "\n  {}\n",
            section(lang, "Current outage", "当前故障")
        ));
        row2(
            &mut out,
            section(lang, "Started", "开始于"),
            &format_ms(outage.started_at_ms),
        );
        row2(
            &mut out,
            section(lang, "Duration", "持续"),
            &format_duration(outage.downtime_ms.unwrap_or(0)),
        );
        row2(&mut out, section(lang, "Reason", "原因"), &outage.reason);
        row2(
            &mut out,
            section(lang, "Dial attempts", "拨号尝试"),
            &outage.dial_attempts.to_string(),
        );
        for e in &outage.ras_errors {
            out.push_str(&format!("    RAS {} — {}\n", e.code, e.message));
        }
    }

    if !n.recent_outages.is_empty() {
        out.push_str(&format!(
            "\n  {}\n",
            section(lang, "Recent outages", "近期故障")
        ));
        for o in &n.recent_outages {
            let for_word = section(lang, "for", "持续");
            let attempts = section(lang, "attempts", "次尝试");
            out.push_str(&format!(
                "    {} {for_word} {} ({}, {} {attempts})\n",
                format_ms(o.started_at_ms),
                format_duration(o.downtime_ms.unwrap_or(0)),
                o.reason,
                o.dial_attempts
            ));
        }
    }

    out
}

/// Render incidents.
pub fn incidents_text(incidents: &[Incident], lang: Lang) -> String {
    if incidents.is_empty() {
        return format!("{}\n", msg::NO_INCIDENTS.get(lang));
    }

    let mut out = if lang.resolve() == Lang::ZhCn {
        format!("{} 条事件记录，最新在前\n\n", incidents.len())
    } else {
        format!("{} incident(s), newest first\n\n", incidents.len())
    };

    for i in incidents {
        out.push_str(&format!(
            "{}  [{:?}] {}\n",
            format_ms(i.at_ms),
            i.severity,
            i.title
        ));
        out.push_str(&format!("  {}\n", i.summary));

        match i.kind {
            IncidentKind::UnexpectedRestart => {
                if let Some(r) = &i.details.unexpected_restart {
                    out.push_str(&format!(
                        "  {}: {} -> {}\n",
                        section(lang, "Boot", "启动"),
                        r.previous_boot_id,
                        r.current_boot_id
                    ));
                    if let Some(initiator) = &r.likely_initiator {
                        out.push_str(&format!(
                            "  {}: {initiator}\n",
                            section(lang, "Likely initiator", "可能的发起者")
                        ));
                    }
                    out.push_str(&format!(
                        "  {}: {:?}, {}: {:?}\n",
                        section(lang, "Confidence", "置信度"),
                        r.confidence,
                        section(lang, "Windows Update related", "与 Windows Update 相关"),
                        r.windows_update_related
                    ));
                    if !r.agents_lost.is_empty() {
                        out.push_str(&format!(
                            "  {}:\n",
                            section(lang, "Agents lost", "丢失的 Agent")
                        ));
                        for a in &r.agents_lost {
                            let unknown = section(lang, "unknown", "未知");
                            out.push_str(&format!(
                                "    {} (pid {}, {} {})\n",
                                a.display_name,
                                a.pid,
                                section(lang, "project", "项目"),
                                a.project.as_deref().unwrap_or(unknown)
                            ));
                        }
                    }
                    if !r.evidence.is_empty() {
                        out.push_str(&format!("  {}:\n", section(lang, "Evidence", "证据")));
                        for e in r.evidence.iter().take(10) {
                            out.push_str(&format!(
                                "    {}/{}: {}\n",
                                e.provider,
                                e.event_id,
                                truncate(&e.message, 120)
                            ));
                        }
                    }
                }
            }
            IncidentKind::PolicyTamper => {
                if let Some(t) = &i.details.policy_tamper {
                    out.push_str(&format!(
                        "  {}\\{}: {:?} -> {:?}, {}: {}\n",
                        t.key_path,
                        t.value_name,
                        t.expected,
                        t.observed,
                        section(lang, "restored", "已恢复"),
                        t.restored
                    ));
                }
            }
            IncidentKind::WorkerFailure => {
                if let Some(w) = &i.details.worker_failure {
                    out.push_str(&format!(
                        "  {} '{}' {} {}: {}\n",
                        section(lang, "Worker", "组件"),
                        w.worker,
                        section(lang, "failed", "失败"),
                        w.restarts,
                        w.error
                    ));
                }
            }
            _ => {}
        }

        for (k, v) in &i.details.extra {
            out.push_str(&format!("  {k}: {v}\n"));
        }

        out.push('\n');
    }

    out
}

/// Render a pending-reboot report.
pub fn pending_reboot_text(report: &PendingRebootReport, lang: Lang) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}: {}\n",
        msg::PENDING_REBOOT.get(lang),
        verdict_label(report.verdict, lang)
    ));
    out.push_str(&format!(
        "{}: {}\n\n",
        section(lang, "Checked at", "检测时间"),
        format_ms(report.checked_at_ms)
    ));

    if report.signals.is_empty() {
        out.push_str(&format!(
            "{}\n",
            section(lang, "No indicators were probed.", "未探测任何指标。")
        ));
        return out;
    }

    out.push_str(&format!("{}:\n", section(lang, "Indicators", "指标")));
    for s in &report.signals {
        let state = if s.read_failed {
            section(lang, "UNREADABLE", "无法读取").to_string()
        } else if s.present {
            format!("{} ({:?})", section(lang, "PRESENT", "存在"), s.weight)
        } else {
            section(lang, "absent", "不存在").to_string()
        };
        out.push_str(&format!("  {:<40}{}\n", s.id, state));
        out.push_str(&format!("      {}\n", s.detail));
    }

    out
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// The column at which values begin.
const COLUMN: usize = 26;

/// Write a label/value row with the columns aligned.
///
/// Padding is computed from *display* width rather than character count, because a CJK ideograph
/// occupies two terminal columns. Using `{:<24}` would leave every Chinese row short by one column
/// per ideograph, so the values would not line up.
fn row(out: &mut String, label: &str, value: &str) {
    out.push_str("  ");
    out.push_str(label);
    out.push_str(&" ".repeat(COLUMN.saturating_sub(display_width(label))));
    out.push_str(value);
    out.push('\n');
}

/// Write an indented label/value row, for nested blocks.
fn row2(out: &mut String, label: &str, value: &str) {
    out.push_str("    ");
    out.push_str(label);
    out.push_str(&" ".repeat((COLUMN - 2).saturating_sub(display_width(label))));
    out.push_str(value);
    out.push('\n');
}

/// The number of terminal columns a string occupies.
///
/// Counts East Asian wide and fullwidth characters as two. This is a deliberately small
/// approximation of Unicode's East Asian Width property, covering the ranges that appear in this
/// program's output; it is used only for alignment, so a mis-categorised exotic character costs a
/// space rather than correctness.
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    // Zero-width: combining marks and the common BOM/zero-width space range.
    if (0x0300..=0x036F).contains(&cp) || (0x200B..=0x200F).contains(&cp) {
        return 0;
    }
    let wide = (0x1100..=0x115F).contains(&cp)      // Hangul Jamo
        || (0x2E80..=0x303E).contains(&cp)          // CJK radicals, Kangxi, CJK symbols
        || (0x3041..=0x33FF).contains(&cp)          // Hiragana, Katakana, Bopomofo
        || (0x3400..=0x4DBF).contains(&cp)          // CJK Extension A
        || (0x4E00..=0x9FFF).contains(&cp)          // CJK Unified Ideographs
        || (0xA000..=0xA4CF).contains(&cp)          // Yi
        || (0xAC00..=0xD7A3).contains(&cp)          // Hangul syllables
        || (0xF900..=0xFAFF).contains(&cp)          // CJK Compatibility Ideographs
        || (0xFE10..=0xFE19).contains(&cp)          // Vertical forms
        || (0xFE30..=0xFE6F).contains(&cp)          // CJK Compatibility Forms
        || (0xFF00..=0xFF60).contains(&cp)          // Fullwidth forms
        || (0xFFE0..=0xFFE6).contains(&cp)          // Fullwidth signs
        || (0x1F300..=0x1F64F).contains(&cp)        // Emoji
        || (0x1F900..=0x1F9FF).contains(&cp)
        || (0x20000..=0x3FFFD).contains(&cp); // CJK Extensions B onward
    if wide {
        2
    } else {
        1
    }
}

/// The label shown for a protection level, in either language.
pub fn level_label(level: ProtectionLevel, lang: Lang) -> &'static str {
    match level {
        ProtectionLevel::Protected => msg::PROTECTED.get(lang),
        ProtectionLevel::Degraded => msg::DEGRADED.get(lang),
        ProtectionLevel::Maintenance => msg::MAINTENANCE.get(lang),
        ProtectionLevel::Unknown => msg::UNKNOWN.get(lang),
        ProtectionLevel::Unprotected => msg::UNPROTECTED.get(lang),
    }
}

/// The label shown for Internet health, in either language.
pub fn internet_label(health: InternetHealth, lang: Lang) -> &'static str {
    match health {
        InternetHealth::Healthy => msg::HEALTHY.get(lang),
        InternetHealth::Degraded => msg::DEGRADED.get(lang),
        InternetHealth::Down => msg::DOWN.get(lang),
        InternetHealth::Unknown => msg::UNKNOWN.get(lang),
    }
}

/// The label shown for a protection mode, in either language.
pub fn mode_label(mode: ProtectionMode, lang: Lang) -> &'static str {
    match mode {
        ProtectionMode::Normal => msg::MODE_NORMAL.get(lang),
        ProtectionMode::Working => msg::MODE_WORKING.get(lang),
        ProtectionMode::Maintenance => msg::MODE_MAINTENANCE.get(lang),
    }
}

/// The label shown for a confidence level, in either language.
pub fn confidence_label(c: Confidence, lang: Lang) -> &'static str {
    match c {
        Confidence::Confirmed => msg::CONFIDENCE_CONFIRMED.get(lang),
        Confidence::High => msg::CONFIDENCE_HIGH.get(lang),
        Confidence::Possible => msg::CONFIDENCE_POSSIBLE.get(lang),
        Confidence::Unknown => msg::CONFIDENCE_UNKNOWN.get(lang),
    }
}

/// The label shown for a pending-reboot verdict, in either language.
pub fn verdict_label(v: PendingRebootVerdict, lang: Lang) -> &'static str {
    match v {
        PendingRebootVerdict::NotPending => msg::NOT_PENDING.get(lang),
        PendingRebootVerdict::ProbablyPending => msg::PROBABLY_PENDING.get(lang),
        PendingRebootVerdict::Pending => msg::PENDING.get(lang),
        PendingRebootVerdict::Unknown => msg::UNKNOWN.get(lang),
    }
}

/// A section header in either language.
///
/// Section headers are not in the shared table because only the CLI renders them; the panel uses
/// HTML headings.
pub fn section(lang: Lang, en: &'static str, zh: &'static str) -> &'static str {
    match lang.resolve() {
        Lang::ZhCn => zh,
        _ => en,
    }
}

/// Render a Unix millisecond timestamp.
pub fn format_ms(ms: i64) -> String {
    if ms <= 0 {
        return "—".to_string();
    }
    // A compact, unambiguous rendering. A full calendar conversion is not worth a dependency for a
    // value that is only ever read as "roughly when".
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    format!(
        "day+{days} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Render a millisecond duration compactly.
pub fn format_duration(ms: i64) -> String {
    if ms < 0 {
        return "unknown".to_string();
    }
    let secs = ms / 1000;
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m {:02}s", secs % 60);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h {:02}m", mins % 60);
    }
    format!("{}d {:02}h", hours / 24, hours % 24)
}

/// Truncate for display, on a character boundary.
fn truncate(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}
