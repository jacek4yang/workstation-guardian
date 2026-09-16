//! `guardianctl doctor` — the diagnostic sweep.
//!
//! Runs without Guardian, reading system state directly, so it is useful exactly when Guardian is
//! broken. Every check is read-only: running diagnostics must never change the machine's protection
//! state, or the tool becomes part of the problem.
//!
//! The check set covers:
//!
//! ```text
//! whether the runtime answers                    RAS entries
//! elevation (can the policy be applied?)         selected PPPoE entry
//! session helper                                 network probes
//! Windows Update policy                          process-monitor health
//! conflicting external policy                    storage/journal health
//! pending reboot                                 log health
//! ```

use guardian_core::ports::{PendingRebootSource, UpdatePolicyBackend};
use guardian_network::probes::ProbeSource;
use guardian_proto::model::{
    FindingSeverity, HealthCheck, HealthReport, ManagementState, PendingRebootVerdict,
    ProtectionLevel,
};
use guardian_proto::Lang;

/// A check name in both languages.
///
/// The names identify a check in the output and in `--json`, so they must stay stable while being
/// readable. Keeping them in one table means a new check cannot be added with only one language.
fn check_name(id: &str, lang: Lang) -> String {
    let (en, zh) = match id {
        "runtime.reachable" => ("Guardian running", "Guardian 正在运行"),
        "runtime.installation" => ("Installation", "运行环境"),
        "helper.present" => ("Session helper", "会话助手"),
        // Named for what it measures, because it is `guardianctl` being described, not Guardian.
        // As "Diagnostic elevation" it read as a verdict on the running program, which is exactly
        // the kind of ambiguity that makes an operator chase a problem that is not there.
        "process.elevation" => ("This tool is elevated", "本工具已提权"),
        "update.protection" => ("Update protection", "更新保护"),
        "update.unapplied" => ("Update policy applied", "更新策略已应用"),
        "update.externally_managed" => ("Conflicting external policy", "外部策略冲突"),
        "update.policy_manager" => ("PolicyManager update policy", "PolicyManager 更新策略"),
        "reboot.pending" => ("Pending reboot", "待重启"),
        "network.ras_entries" => ("PPPoE entries", "PPPoE 条目"),
        "network.entry_selection" => ("PPPoE entry selection", "PPPoE 条目选择"),
        "network.connectivity" => ("Connectivity probes", "连通性探测"),
        "network.wifi" => ("Wi-Fi continuity", "Wi-Fi 备用连接"),
        "monitor.enumeration" => ("Process monitor", "进程监控"),
        "monitor.rejected_rules" => ("Agent signature rules", "Agent 签名规则"),
        "storage.root" => ("State directory", "状态目录"),
        "storage.config" => ("Configuration", "配置文件"),
        "storage.journal" => ("Recovery journal", "恢复日志"),
        "logging.size" => ("Log storage", "日志存储"),
        other => {
            // Per-item checks (one per probe, one per agent) carry their own label in the id.
            return other.to_string();
        }
    };
    crate::output::section(lang, en, zh).to_string()
}

/// The explanation shown for a check that has a fixed reason, in either language.
///
/// Kept beside [`check_name`] so a check cannot acquire a name in one language and an unexplained
/// failure in the other. Only static explanations live here; anything embedding a measured value
/// is formatted at the call site.
fn check_detail(id: &str, lang: Lang) -> String {
    let (en, zh): (&str, &str) = match id {
        "runtime.reachable" => (
            "the protection runtime is responding on its named pipe",
            "保护运行时已在其命名管道上响应",
        ),
        "runtime.not_running" => (
            "Guardian is not running, so Windows Update is not being held back; \
             start the tray application",
            "Guardian 未运行，Windows Update 未被抑制；请启动托盘程序",
        ),
        "helper.present" => (
            "the session helper is running in the interactive session",
            "会话助手正在交互式会话中运行",
        ),
        "helper.unknown" => (
            "guardian-session.exe is not running, so a shutdown in WORKING mode would not be \
             blocked; start it at logon",
            "guardian-session.exe 未运行，工作保护模式下的关机将不会被阻止；请设置登录时启动",
        ),
        "elevation.yes" => (
            "this diagnostic is running elevated, so it can read and write machine policy",
            "本诊断程序以管理员权限运行，可以读写机器策略",
        ),
        "elevation.no" => (
            "this diagnostic is not elevated. That does not describe Guardian: check the              'Guardian running' row for whether protection is active",
            "本诊断程序未提权。这并不代表 Guardian 的状态；请查看“Guardian 正在运行”一项以确认保护是否生效",
        ),
        "network.no_entries" => (
            "no RAS phonebook entries are configured; PPPoE management is not applicable",
            "未配置任何 RAS 电话簿条目；PPPoE 管理不适用",
        ),
        "network.no_wifi" => (
            "no wireless adapter; broadband continuity has no backup path on this machine",
            "无无线网卡；此机器上宽带中断没有备用通道",
        ),
        "storage.config_absent" => (
            "no configuration file yet; defaults apply and they protect updates",
            "尚无配置文件；使用默认值，且默认值会保护更新",
        ),
        "storage.journal_absent" => (
            "no journal yet; it is created when Guardian first starts",
            "尚无恢复日志；Guardian 首次启动时会创建",
        ),
        other => return other.to_string(),
    };
    crate::output::section(lang, en, zh).to_string()
}

/// Run the full sweep and render it.
pub fn run(json: bool, lang: Lang) -> Result<String, String> {
    let report = build_report(lang);

    if json {
        return serde_json::to_string_pretty(&report)
            .map_err(|e| format!("could not render the report as JSON: {e}"));
    }

    Ok(render(&report, lang))
}

/// The update-protection slice of the sweep.
pub fn update_report(json: bool, lang: Lang) -> Result<String, String> {
    let backend = guardian_win::policy::PolicyBackend::new();
    let managed = backend.management_state();

    let readback = match backend.read() {
        Ok(rb) => rb,
        Err(e) => {
            return Err(format!("could not read the Windows Update policy: {e}"));
        }
    };

    let analysis = guardian_core::update_policy::analyze(
        &readback,
        &managed,
        guardian_win::clock::unix_now_ms(),
        None,
    );
    let report = analysis.into_report(&managed, guardian_win::clock::unix_now_ms());

    if json {
        return serde_json::to_string_pretty(&report)
            .map_err(|e| format!("could not render the report as JSON: {e}"));
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{}\n\n",
        crate::output::section(lang, "WINDOWS UPDATE PROTECTION", "WINDOWS UPDATE 保护")
    ));
    kv(
        &mut out,
        lang,
        "Status",
        "状态",
        crate::output::level_label(report.level, lang),
    );
    kv(
        &mut out,
        lang,
        "Primary lock",
        "主锁",
        crate::output::section(
            lang,
            if report.primary_lock_effective {
                "NoAutoUpdate=1 is in effect"
            } else {
                "NOT in effect"
            },
            if report.primary_lock_effective {
                "NoAutoUpdate=1 已生效"
            } else {
                "未生效"
            },
        ),
    );
    let management = management_label(&report.management, lang);
    kv(&mut out, lang, "Management", "管理状态", &management);

    out.push_str(&format!(
        "\n  {}\n",
        crate::output::section(
            lang,
            "Guardian-owned policy values:",
            "Guardian 拥有的策略值："
        )
    ));
    if report.values.is_empty() {
        out.push_str(&format!(
            "    {}\n",
            crate::output::section(lang, "(none could be read)", "（无法读取）")
        ));
    }
    for v in &report.values {
        let state = if v.matches {
            crate::output::section(lang, "OK", "正常")
        } else {
            crate::output::section(lang, "MISMATCH", "不一致")
        };
        let expected = crate::output::section(lang, "expected", "期望");
        let found = crate::output::section(lang, "found", "实际");
        out.push_str(&format!(
            "    {:<36} {:<12} {expected} {:?}, {found} {:?}\n",
            v.name, state, v.desired, v.observed
        ));
    }

    if !report.neutralized_deadlines.is_empty() {
        out.push_str(&format!(
            "\n  {}\n",
            crate::output::section(lang, "Restart deadline policies:", "重启截止策略：")
        ));
        for d in &report.neutralized_deadlines {
            out.push_str(&format!(
                "    {:<36} {}\n",
                d.name,
                if d.neutralized {
                    crate::output::section(lang, "neutralized", "已中和")
                } else {
                    crate::output::section(lang, "PRESENT", "存在")
                }
            ));
        }
    }

    if !report.findings.is_empty() {
        out.push_str(&format!(
            "\n  {}\n",
            crate::output::section(lang, "Findings:", "发现：")
        ));
        for f in &report.findings {
            out.push_str(&format!(
                "    [{:?}] {}\n        {}\n",
                f.severity, f.code, f.message
            ));
        }
    }

    Ok(out)
}

/// Write a label/value row, translated.
fn kv(out: &mut String, lang: Lang, en: &'static str, zh: &'static str, value: &str) {
    out.push_str(&format!(
        "  {:<20}{value}
",
        crate::output::section(lang, en, zh)
    ));
}

/// Describe the management state in the requested language.
fn management_label(m: &ManagementState, lang: Lang) -> String {
    use guardian_proto::i18n::msg::*;
    let _ = (PROTECTED, DEGRADED);
    match m {
        ManagementState::Unmanaged => {
            crate::output::section(lang, "not externally managed", "未受外部管理").to_string()
        }
        ManagementState::DomainJoined { domain } => {
            if lang.resolve() == Lang::ZhCn {
                format!("已加入域（{domain}）")
            } else {
                format!("domain joined ({domain})")
            }
        }
        ManagementState::MdmEnrolled { provider } => {
            if lang.resolve() == Lang::ZhCn {
                format!("已注册 MDM（{provider}）")
            } else {
                format!("MDM enrolled ({provider})")
            }
        }
        ManagementState::DomainAndMdm { domain, provider } => {
            if lang.resolve() == Lang::ZhCn {
                format!("已加入域（{domain}）且注册 MDM（{provider}）")
            } else {
                format!("domain joined ({domain}) and MDM enrolled ({provider})")
            }
        }
        ManagementState::Unknown => crate::output::section(
            lang,
            "management state could not be determined",
            "无法确定管理状态",
        )
        .to_string(),
    }
}

/// Build the full health report.
pub fn build_report(lang: Lang) -> HealthReport {
    let mut checks = Vec::new();

    checks.extend(service_checks(lang));
    checks.extend(update_checks(lang));
    checks.extend(pending_reboot_checks(lang));
    checks.extend(network_checks(lang));
    checks.extend(monitor_checks(lang));
    checks.extend(storage_checks(lang));

    HealthReport {
        checks,
        generated_at_ms: guardian_win::clock::unix_now_ms(),
    }
}

/// Whether Guardian is running, and whether it is running with the rights it needs.
///
/// There is no service to inspect. Guardian is a tray application, so the question an operator
/// actually has is "is anything protecting this machine right now, and can it?" That is answered by
/// whether the runtime answers over IPC, and whether this process is elevated.
fn service_checks(lang: Lang) -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    let elevated = crate::install::is_elevated();

    // Whether the runtime answers over IPC is the practical question. A Guardian that is running
    // but unreachable is not protecting anything an operator can see, and one that is not running
    // at all leaves Windows Update fully unlocked.
    let online = guardian_service::ipc::IpcClient::connect(1_500)
        .and_then(|mut c| {
            c.call_expect(&guardian_proto::Request::Hello {
                protocol: guardian_proto::PROTOCOL_VERSION,
            })
            .map(|_| ())
        })
        .is_ok();

    checks.push(HealthCheck {
        id: "runtime.reachable".into(),
        name: check_name("runtime.reachable", lang),
        ok: online,
        severity: if online {
            FindingSeverity::Info
        } else {
            // Not running means the update policy is unmanaged. That is a real problem, not a
            // cosmetic one, so it is an error rather than a warning.
            FindingSeverity::Error
        },
        detail: if online {
            check_detail("runtime.reachable", lang).to_string()
        } else {
            check_detail("runtime.not_running", lang).to_string()
        },
    });

    // Elevation decides whether the policy can be applied at all. Reporting it here saves an
    // operator from diagnosing a registry write that silently failed.
    checks.push(HealthCheck {
        id: "process.elevation".into(),
        name: check_name("process.elevation", lang),
        ok: elevated,
        severity: if elevated {
            FindingSeverity::Info
        } else {
            FindingSeverity::Error
        },
        detail: if elevated {
            check_detail("elevation.yes", lang).to_string()
        } else {
            check_detail("elevation.no", lang).to_string()
        },
    });

    // The session helper is what turns WORKING mode into an actual shutdown block, and it is a
    // separate per-user process rather than part of the tray application.
    //
    // The verdict must reflect whether it is actually running. Reporting "pass" beside a detail
    // that says it is not running would be exactly the kind of reassuring lie this project exists
    // to prevent — and it is worse here than elsewhere, because the operator reading it is asking
    // whether their build is safe from a shutdown.
    let helper_running = guardian_win::process::enumerate_processes()
        .map(|procs| {
            procs
                .iter()
                .any(|p| p.name.eq_ignore_ascii_case("guardian-session.exe"))
        })
        .unwrap_or(false);

    checks.push(HealthCheck {
        id: "helper.present".into(),
        name: check_name("helper.present", lang),
        ok: helper_running,
        // A missing helper is a warning rather than an error: protection is still running, and the
        // machine is only exposed to a shutdown while work is actually in progress.
        severity: if helper_running {
            FindingSeverity::Info
        } else {
            FindingSeverity::Warning
        },
        detail: if helper_running {
            check_detail("helper.present", lang).to_string()
        } else {
            check_detail("helper.unknown", lang).to_string()
        },
    });

    // The data-directory summary is a single multi-line block; it is surfaced as one check so the
    // per-check table does not fill with paths.
    checks.push(HealthCheck {
        id: "runtime.installation".into(),
        name: check_name("runtime.installation", lang),
        ok: true,
        severity: FindingSeverity::Info,
        detail: summarize_installation(),
    });

    checks
}

/// Flatten the multi-line installation summary into one check detail.
///
/// The table format is one line per check, so embedded newlines would break it. The paths are
/// still fully present, just joined.
fn summarize_installation() -> String {
    crate::install::installation_summary()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Windows Update policy checks.
fn update_checks(lang: Lang) -> Vec<HealthCheck> {
    let mut checks = Vec::new();
    let backend = guardian_win::policy::PolicyBackend::new();

    let readback = backend.read();
    let managed = backend.management_state();

    match readback {
        Ok(rb) => {
            let analysis = guardian_core::update_policy::analyze(
                &rb,
                &managed,
                guardian_win::clock::unix_now_ms(),
                None,
            );
            let level = analysis.level;

            checks.push(HealthCheck {
                id: "update.protection".into(),
                name: check_name("update.protection", lang),
                ok: level.is_protected(),
                severity: match level {
                    ProtectionLevel::Protected => FindingSeverity::Info,
                    ProtectionLevel::Degraded => FindingSeverity::Warning,
                    _ => FindingSeverity::Error,
                },
                detail: format!(
                    "{} (primary lock {})",
                    level.as_str(),
                    if analysis.primary_lock_effective {
                        "in effect"
                    } else {
                        "NOT in effect"
                    }
                ),
            });

            if !analysis.writes_needed.is_empty() {
                checks.push(HealthCheck {
                    id: "update.unapplied".into(),
                    name: check_name("update.unapplied", lang),
                    ok: false,
                    severity: FindingSeverity::Warning,
                    detail: format!(
                        "{} Guardi-owned value(s) differ from the intended policy; \
                         the service will re-apply them",
                        analysis.writes_needed.len()
                    ),
                });
            }
        }
        Err(e) => {
            checks.push(HealthCheck {
                id: "update.protection".into(),
                name: check_name("update.protection", lang),
                ok: false,
                // Being unable to read policy is an error, not a warning: protection cannot
                // be confirmed, so it must not be reported as fine.
                severity: FindingSeverity::Error,
                detail: format!("the Windows Update policy could not be read: {e}"),
            });
        }
    }

    // A machine under external management can have its policy overridden at any refresh, and
    // Guardian must say so rather than claiming protection it cannot deliver.
    match &managed {
        ManagementState::Unmanaged => {}
        other => {
            checks.push(HealthCheck {
                id: "update.externally_managed".into(),
                name: check_name("update.externally_managed", lang),
                ok: false,
                severity: FindingSeverity::Warning,
                detail: format!(
                    "this machine is {}; Group Policy or MDM can override local update policy, \
                     so protection is reported as Degraded",
                    other.describe()
                ),
            });
        }
    }

    // Report CSP-level detail so the operator can name the specific conflict.
    for line in backend.management_detail() {
        checks.push(HealthCheck {
            id: "update.policy_manager".into(),
            name: check_name("update.policy_manager", lang),
            ok: false,
            severity: FindingSeverity::Warning,
            detail: line,
        });
    }

    checks
}

/// Pending-reboot checks.
fn pending_reboot_checks(lang: Lang) -> Vec<HealthCheck> {
    let probe = guardian_win::boot::RebootProbe::new();
    let signals = match probe.collect() {
        Ok(s) => s,
        Err(e) => {
            return vec![HealthCheck {
                id: "reboot.pending".into(),
                name: check_name("reboot.pending", lang),
                ok: false,
                severity: FindingSeverity::Warning,
                detail: format!("the pending-reboot probe failed: {e}"),
            }];
        }
    };

    let report = guardian_core::reboot::classify_signals(
        signals.clone(),
        guardian_win::clock::unix_now_ms(),
    );

    let mut checks = vec![HealthCheck {
        id: "reboot.pending".into(),
        name: check_name("reboot.pending", lang),
        ok: matches!(report.verdict, PendingRebootVerdict::NotPending),
        severity: match report.verdict {
            PendingRebootVerdict::NotPending => FindingSeverity::Info,
            PendingRebootVerdict::ProbablyPending => FindingSeverity::Warning,
            PendingRebootVerdict::Pending => FindingSeverity::Warning,
            PendingRebootVerdict::Unknown => FindingSeverity::Warning,
        },
        detail: format!(
            "{} ({})",
            report.verdict.as_str(),
            report.reasons().join("; ")
        ),
    }];

    // Report which signals actually fired, so a contested verdict can be examined.
    for s in signals.iter().filter(|s| s.present || s.read_failed) {
        checks.push(HealthCheck {
            id: format!("reboot.signal.{}", s.id),
            name: format!("Reboot indicator: {}", s.id),
            ok: false,
            severity: if s.read_failed {
                FindingSeverity::Warning
            } else {
                FindingSeverity::Info
            },
            detail: s.detail.clone(),
        });
    }

    checks
}

/// Network checks.
fn network_checks(lang: Lang) -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    let entries = guardian_win::ras::enum_entries().unwrap_or_default();

    checks.push(HealthCheck {
        id: "network.ras_entries".into(),
        name: check_name("network.ras_entries", lang),
        ok: true,
        severity: FindingSeverity::Info,
        detail: if entries.is_empty() {
            check_detail("network.no_entries", lang)
        } else {
            format!(
                "{} entr{}: {}",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" },
                entries
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    });

    if !entries.is_empty() {
        let selection = guardian_network::worker::select_entry(&entries, None);
        checks.push(HealthCheck {
            id: "network.entry_selection".into(),
            name: check_name("network.entry_selection", lang),
            ok: selection.is_ok(),
            severity: if selection.is_ok() {
                FindingSeverity::Info
            } else {
                FindingSeverity::Warning
            },
            detail: match &selection {
                Ok(Some(name)) => format!("an unambiguous entry is available: {name}"),
                Ok(None) => "no entry is available".into(),
                Err(e) => e.to_string(),
            },
        });
    }

    // Reachability by quorum, using a small ad-hoc set so `doctor` works without configuration.
    let probes = guardian_network::ProbeRunner::new(guardian_proto::model::default_probes());
    let results = probes.run_round();
    let passed = results.iter().filter(|r| r.ok).count();
    let total = results.len();

    checks.push(HealthCheck {
        id: "network.connectivity".into(),
        name: check_name("network.connectivity", lang),
        ok: passed > 0,
        severity: if passed == total && total > 0 {
            FindingSeverity::Info
        } else if passed > 0 {
            FindingSeverity::Warning
        } else {
            FindingSeverity::Error
        },
        detail: format!("{passed}/{total} probes succeeded"),
    });

    for r in &results {
        checks.push(HealthCheck {
            id: format!("network.probe.{}", r.id),
            name: format!("Probe {}", r.id),
            ok: r.ok,
            severity: if r.ok {
                FindingSeverity::Info
            } else {
                FindingSeverity::Warning
            },
            detail: match (&r.error, r.latency_ms) {
                (_, Some(ms)) if r.ok => format!("{}: {}ms", r.target, ms),
                (Some(e), _) => format!("{}: {e}", r.target),
                (None, _) => r.target.clone(),
            },
        });
    }

    // Wi-Fi is the continuity path; its absence is worth stating explicitly rather than
    // silently skipping.
    let wifi_present = guardian_win::wifi::has_wireless_interface();
    checks.push(HealthCheck {
        id: "network.wifi".into(),
        name: check_name("network.wifi", lang),
        ok: true,
        severity: FindingSeverity::Info,
        detail: if wifi_present {
            match guardian_win::wifi::current_connection() {
                Some((adapter, ssid)) => format!("{adapter} connected to '{ssid}'"),
                None => "a wireless adapter is present but not connected".into(),
            }
        } else {
            check_detail("network.no_wifi", lang)
        },
    });

    checks
}

/// Process-monitor health.
fn monitor_checks(lang: Lang) -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    match guardian_win::process::enumerate_processes() {
        Ok(procs) => {
            let graph = guardian_process::ProcessGraph::new(procs);
            let engine = guardian_process::default_engine(&Default::default());
            let detections = engine.detect_agents(&graph);

            checks.push(HealthCheck {
                id: "monitor.enumeration".into(),
                name: check_name("monitor.enumeration", lang),
                ok: true,
                severity: FindingSeverity::Info,
                detail: format!(
                    "{} processes enumerated; {} agent(s) detected",
                    graph.len(),
                    detections.len()
                ),
            });

            // Report any signature that failed to compile, so a broken user rule is visible.
            if !engine.rejected_rules().is_empty() {
                checks.push(HealthCheck {
                    id: "monitor.rejected_rules".into(),
                    name: check_name("monitor.rejected_rules", lang),
                    ok: false,
                    severity: FindingSeverity::Warning,
                    detail: format!(
                        "{} rule(s) could not be compiled and are inactive: {}",
                        engine.rejected_rules().len(),
                        engine
                            .rejected_rules()
                            .iter()
                            .map(|r| format!("{} ({})", r.pattern, r.reason))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                });
            }

            for (process, det) in &detections {
                checks.push(HealthCheck {
                    id: format!("monitor.agent.{}", process.pid),
                    name: format!("Agent: {}", det.display_name),
                    ok: true,
                    severity: FindingSeverity::Info,
                    detail: format!(
                        "pid {} at {:?} (score {})",
                        process.pid, det.confidence, det.score
                    ),
                });
            }
        }
        Err(e) => {
            checks.push(HealthCheck {
                id: "monitor.enumeration".into(),
                name: check_name("monitor.enumeration", lang),
                ok: false,
                severity: FindingSeverity::Error,
                detail: format!("process enumeration failed: {e}"),
            });
        }
    }

    checks
}

/// Storage, journal and log health.
fn storage_checks(lang: Lang) -> Vec<HealthCheck> {
    let mut checks = Vec::new();
    let paths = guardian_storage::GuardianPaths::production();

    let root = paths.root();
    let writable = check_writable(root);
    checks.push(HealthCheck {
        id: "storage.root".into(),
        name: check_name("storage.root", lang),
        ok: writable.is_ok(),
        severity: if writable.is_ok() {
            FindingSeverity::Info
        } else {
            FindingSeverity::Error
        },
        detail: match &writable {
            Ok(()) => format!("{} exists and is writable", root.display()),
            Err(e) => format!("{}: {e}", root.display()),
        },
    });

    // Config: report corruption, since it falls back to defaults.
    match std::fs::read_to_string(paths.config_file()) {
        Ok(text) => {
            let validated = guardian_core::config::load_from_str(&text);
            checks.push(HealthCheck {
                id: "storage.config".into(),
                name: check_name("storage.config", lang),
                ok: !validated.has_rejections(),
                severity: if validated.has_rejections() {
                    FindingSeverity::Warning
                } else {
                    FindingSeverity::Info
                },
                detail: if validated.issues.is_empty() {
                    "configuration is valid".into()
                } else {
                    format!(
                        "{} issue(s): {}",
                        validated.issues.len(),
                        validated
                            .issues
                            .iter()
                            .map(|i| format!("{}: {}", i.path, i.message))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                },
            });
        }
        Err(_) => {
            checks.push(HealthCheck {
                id: "storage.config".into(),
                name: check_name("storage.config", lang),
                ok: true,
                severity: FindingSeverity::Info,
                detail: check_detail("storage.config_absent", lang),
            });
        }
    }

    // Journal: a torn tail is worth reporting, because it means the last stop was abrupt.
    let journal_path = paths.journal_file();
    if journal_path.exists() {
        let previous = guardian_service::journal::read_previous_session(&journal_path);
        checks.push(HealthCheck {
            id: "storage.journal".into(),
            name: check_name("storage.journal", lang),
            ok: !previous.truncated,
            severity: if previous.truncated {
                FindingSeverity::Warning
            } else {
                FindingSeverity::Info
            },
            detail: guardian_service::journal::describe_previous(&previous),
        });
    } else {
        checks.push(HealthCheck {
            id: "storage.journal".into(),
            name: check_name("storage.journal", lang),
            ok: true,
            severity: FindingSeverity::Info,
            detail: check_detail("storage.journal_absent", lang),
        });
    }

    // Logs: report size so unbounded growth is noticeable.
    let log_dir = paths.logs_dir();
    let size = guardian_service::logging::log_directory_size(&log_dir);
    let files = guardian_service::logging::log_files(&log_dir);
    checks.push(HealthCheck {
        id: "logging.size".into(),
        name: check_name("logging.size", lang),
        ok: size < 64 * 1024 * 1024,
        severity: if size < 64 * 1024 * 1024 {
            FindingSeverity::Info
        } else {
            FindingSeverity::Warning
        },
        detail: format!(
            "{} file(s), {:.1} MiB in {}",
            files.len(),
            size as f64 / (1024.0 * 1024.0),
            log_dir.display()
        ),
    });

    checks
}

/// Check that a directory exists and can be written to.
fn check_writable(dir: &std::path::Path) -> Result<(), String> {
    if !dir.exists() {
        return Err("the directory does not exist".into());
    }
    // Probe with a uniquely named temporary file rather than checking permissions, which is
    // unreliable on Windows with inherited and denied ACEs.
    let probe = dir.join(format!(".guardian-write-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!("not writable: {e}")),
    }
}

/// Render a health report as text.
pub fn render(report: &HealthReport, lang: Lang) -> String {
    let mut out = String::new();

    let ok = report.checks.iter().filter(|c| c.ok).count();
    let failed: Vec<&HealthCheck> = report.checks.iter().filter(|c| !c.ok).collect();

    out.push_str(&format!(
        "{}\n\n",
        crate::output::section(
            lang,
            "WORKSTATION GUARDIAN — DIAGNOSTICS",
            "WORKSTATION GUARDIAN — 诊断"
        )
    ));

    let worst = report.worst();
    if lang.resolve() == Lang::ZhCn {
        out.push_str(&format!(
            "  概要：{} / {} 项检查通过（{:?}）\n\n",
            ok,
            report.checks.len(),
            worst
        ));
    } else {
        out.push_str(&format!(
            "  Summary: {} of {} checks passed ({:?})\n\n",
            ok,
            report.checks.len(),
            worst
        ));
    }

    if failed.is_empty() {
        out.push_str(&format!(
            "  {}\n",
            crate::output::section(lang, "Every check passed.", "所有检查均已通过。")
        ));
    } else {
        out.push_str(&format!(
            "  {}\n",
            crate::output::section(lang, "Problems found:", "发现的问题：")
        ));
        for c in &failed {
            out.push_str(&format!(
                "    [{:?}] {}\n        {}\n",
                c.severity, c.name, c.detail
            ));
        }
    }

    out.push_str(&format!(
        "\n  {}\n",
        crate::output::section(lang, "Full check list:", "完整检查列表：")
    ));
    for c in &report.checks {
        // The status word is padded to a fixed display width so the columns line up in either
        // language; `{:<34}` would be wrong for CJK names.
        let status = if c.ok {
            crate::output::section(lang, "ok  ", "通过")
        } else {
            crate::output::section(lang, "FAIL", "失败")
        };
        let pad = 6usize.saturating_sub(crate::output::display_width(status));
        out.push_str(&format!(
            "    {status}{}{}{}\n",
            " ".repeat(pad),
            c.name,
            padded_detail(&c.name, &c.detail)
        ));
    }

    out
}

/// Pad a check name so its explanation begins at a fixed column, counting CJK as two.
fn padded_detail(name: &str, detail: &str) -> String {
    const NAME_COLUMN: usize = 34;
    let pad = NAME_COLUMN.saturating_sub(crate::output::display_width(name));
    format!("{}{detail}", " ".repeat(pad.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_sweep_runs_without_panicking() {
        // The most important property of a diagnostic tool: it must survive a machine in any
        // state, including one where the service is not installed.
        let report = build_report(Lang::En);
        assert!(!report.checks.is_empty(), "the sweep must produce checks");

        for c in &report.checks {
            assert!(!c.id.is_empty(), "a check needs an id");
            assert!(!c.name.is_empty(), "check {} needs a name", c.id);
            assert!(!c.detail.is_empty(), "check {} needs an explanation", c.id);
            assert!(
                !c.detail.contains('\n'),
                "check {} has a multi-line detail, which breaks the table layout",
                c.id
            );
        }
    }

    #[test]
    fn check_ids_are_unique() {
        // Duplicate ids would make JSON consumers silently overwrite each other. Some ids are
        // deliberately per-item (per probe, per agent), so this checks the static ones.
        let report = build_report(Lang::En);
        let static_ids = [
            "service.installed",
            "service.reachable",
            "helper.present",
            "update.protection",
            "reboot.pending",
            "network.ras_entries",
            "network.connectivity",
            "network.wifi",
            "monitor.enumeration",
            "storage.root",
            "storage.config",
            "storage.journal",
            "logging.size",
        ];

        for id in static_ids {
            let count = report.checks.iter().filter(|c| c.id == id).count();
            assert!(
                count <= 1,
                "check id '{id}' appears {count} times; ids must be unique"
            );
        }
    }

    #[test]
    fn required_checks_are_all_present() {
        // The specification names these explicitly; a regression that drops one should fail.
        let report = build_report(Lang::En);
        let ids: Vec<&str> = report.checks.iter().map(|c| c.id.as_str()).collect();

        for required in [
            "runtime.reachable",
            "runtime.installation",
            "process.elevation",
            "helper.present",
            "update.protection",
            "reboot.pending",
            "network.ras_entries",
            "network.connectivity",
            "network.wifi",
            "monitor.enumeration",
            "storage.root",
            "storage.config",
            "storage.journal",
            "logging.size",
        ] {
            assert!(
                ids.contains(&required),
                "the doctor sweep must include the '{required}' check"
            );
        }
    }

    #[test]
    fn update_protection_is_reported_honestly() {
        // Whatever this machine's state, the check must reflect it rather than assuming.
        let report = build_report(Lang::En);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "update.protection")
            .expect("the update check must exist");

        // If the check passes, the detail must actually say it is protected.
        if check.ok {
            assert!(
                check.detail.contains("Protected"),
                "a passing update check must report Protected, got: {}",
                check.detail
            );
        }
        // And if it fails, it must not claim protection.
        if !check.ok {
            assert!(
                !check.detail.contains("Protected ("),
                "a failing update check must not claim Protected: {}",
                check.detail
            );
        }
    }

    #[test]
    fn rendering_produces_readable_output() {
        let report = build_report(Lang::En);
        let text = render(&report, Lang::En);

        assert!(text.contains("WORKSTATION GUARDIAN"));
        assert!(text.contains("Summary:"));
        assert!(text.contains("Full check list:"));
        assert!(!text.is_empty());
        // Every check id should be discoverable through the output.
        for c in &report.checks {
            assert!(
                text.contains(&c.name),
                "the rendered output must include check '{}'",
                c.name
            );
        }
    }

    #[test]
    fn rendering_an_all_green_report_says_so() {
        let report = HealthReport {
            checks: vec![HealthCheck {
                id: "a".into(),
                name: "A".into(),
                ok: true,
                severity: FindingSeverity::Info,
                detail: "fine".into(),
            }],
            generated_at_ms: 0,
        };
        let text = render(&report, Lang::En);
        assert!(text.contains("Every check passed"));
        assert!(report.all_ok());
        assert_eq!(report.worst(), FindingSeverity::Info);
    }

    #[test]
    fn the_worst_severity_is_reported() {
        let report = HealthReport {
            checks: vec![
                HealthCheck {
                    id: "a".into(),
                    name: "A".into(),
                    ok: true,
                    severity: FindingSeverity::Info,
                    detail: "fine".into(),
                },
                HealthCheck {
                    id: "b".into(),
                    name: "B".into(),
                    ok: false,
                    severity: FindingSeverity::Error,
                    detail: "broken".into(),
                },
            ],
            generated_at_ms: 0,
        };
        assert_eq!(report.worst(), FindingSeverity::Error);
        assert!(!report.all_ok());
    }

    #[test]
    fn the_update_report_runs_without_the_service() {
        // `guardianctl update` must work when the service is down; that is when it is needed.
        let result = update_report(false, Lang::En);
        match result {
            Ok(text) => {
                assert!(text.contains("WINDOWS UPDATE PROTECTION"));
                assert!(text.contains("Primary lock"));
                assert!(text.contains("Management"));
            }
            Err(e) => panic!("the update report must work standalone, got: {e}"),
        }
    }

    #[test]
    fn the_update_report_renders_as_json() {
        let text = update_report(true, Lang::En).expect("standalone report");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(parsed.get("level").is_some());
        assert!(parsed.get("primary_lock_effective").is_some());
    }

    #[test]
    fn the_full_report_renders_as_json() {
        let text = run(true, Lang::En).expect("standalone report");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(parsed.get("checks").and_then(|c| c.as_array()).is_some());
    }

    #[test]
    fn json_output_is_not_polluted_by_other_text() {
        // The `--json` contract is that stdout is parseable. Anything else printed would break
        // every consumer.
        let text = run(true, Lang::En).expect("report");
        assert!(
            serde_json::from_str::<serde_json::Value>(&text).is_ok(),
            "JSON output must parse cleanly"
        );
    }

    #[test]
    fn write_probe_detects_an_unwritable_directory() {
        let missing = std::path::Path::new(r"C:\definitely-not-a-real-directory-8f3a2b");
        assert!(check_writable(missing).is_err());

        // A real, writable directory should pass.
        let temp = std::env::temp_dir();
        assert!(
            check_writable(&temp).is_ok(),
            "the temp directory is writable"
        );

        // And the probe must not leave anything behind.
        let leftover = temp.join(format!(".guardian-write-probe-{}", std::process::id()));
        assert!(
            !leftover.exists(),
            "the write probe must clean up after itself"
        );
    }

    #[test]
    fn a_check_never_passes_while_its_detail_says_it_did_not() {
        // The worst failure this tool can produce is a green "pass" beside a detail sentence
        // explaining that the thing is not running. An operator skimming the table reads the
        // verdict, not the detail, and would conclude their work is safe when it is not.
        //
        // The two static details that describe a *problem* are the ones that must never appear
        // next to a passing check.
        for lang in [Lang::En, Lang::ZhCn] {
            let report = build_report(lang);
            for check in &report.checks {
                if !check.ok {
                    continue;
                }
                for bad in ["helper.unknown", "elevation.no", "runtime.not_running"] {
                    let problem = check_detail(bad, lang);
                    assert_ne!(
                        check.detail, problem,
                        "check '{}' passed while its detail says '{problem}'",
                        check.id
                    );
                }
            }
        }
    }
}
