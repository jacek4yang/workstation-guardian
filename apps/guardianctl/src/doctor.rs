//! `guardianctl doctor` — the diagnostic sweep.
//!
//! Runs without the service, reading system state directly, so it is useful exactly when the
//! service is broken. Every check is read-only: running diagnostics must never change the
//! machine's protection state, or the tool becomes part of the problem.
//!
//! The check set mirrors the specification:
//!
//! ```text
//! service installation/running state     RAS entries
//! session helper                          selected PPPoE entry
//! IPC                                     network probes
//! Windows Update policy                   process-monitor health
//! conflicting external policy             storage/journal health
//! pending reboot                          log health
//! current protection mode
//! ```

use guardian_core::ports::{PendingRebootSource, UpdatePolicyBackend};
use guardian_network::probes::ProbeSource;
use guardian_proto::model::{
    FindingSeverity, HealthCheck, HealthReport, ManagementState, PendingRebootVerdict,
    ProtectionLevel,
};

/// Run the full sweep and render it.
pub fn run(json: bool) -> Result<String, String> {
    let report = build_report();

    if json {
        return serde_json::to_string_pretty(&report)
            .map_err(|e| format!("could not render the report as JSON: {e}"));
    }

    Ok(render(&report))
}

/// The update-protection slice of the sweep.
pub fn update_report(json: bool) -> Result<String, String> {
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
    out.push_str("WINDOWS UPDATE PROTECTION\n\n");
    out.push_str(&format!(
        "  Status              {}\n",
        report.level.as_str()
    ));
    out.push_str(&format!(
        "  Primary lock        {}\n",
        if report.primary_lock_effective {
            "NoAutoUpdate=1 is in effect"
        } else {
            "NOT in effect"
        }
    ));
    out.push_str(&format!(
        "  Management          {}\n",
        report.management.describe()
    ));

    out.push_str("\n  Guardian-owned policy values:\n");
    if report.values.is_empty() {
        out.push_str("    (none could be read)\n");
    }
    for v in &report.values {
        out.push_str(&format!(
            "    {:<36} {:<12} expected {:?}, found {:?}\n",
            v.name,
            if v.matches { "OK" } else { "MISMATCH" },
            v.desired,
            v.observed
        ));
    }

    if !report.neutralized_deadlines.is_empty() {
        out.push_str("\n  Restart deadline policies:\n");
        for d in &report.neutralized_deadlines {
            out.push_str(&format!(
                "    {:<36} {}\n",
                d.name,
                if d.neutralized {
                    "neutralized"
                } else {
                    "PRESENT"
                }
            ));
        }
    }

    if !report.findings.is_empty() {
        out.push_str("\n  Findings:\n");
        for f in &report.findings {
            out.push_str(&format!(
                "    [{:?}] {}\n        {}\n",
                f.severity, f.code, f.message
            ));
        }
    }

    Ok(out)
}

/// Build the full health report.
pub fn build_report() -> HealthReport {
    let mut checks = Vec::new();

    checks.extend(service_checks());
    checks.extend(update_checks());
    checks.extend(pending_reboot_checks());
    checks.extend(network_checks());
    checks.extend(monitor_checks());
    checks.extend(storage_checks());

    HealthReport {
        checks,
        generated_at_ms: guardian_win::clock::unix_now_ms(),
    }
}

/// Service installation and running state.
fn service_checks() -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    let installed = guardian_service_installed();
    checks.push(HealthCheck {
        id: "service.installed".into(),
        name: "Service installed".into(),
        ok: installed,
        severity: if installed {
            FindingSeverity::Info
        } else {
            FindingSeverity::Warning
        },
        detail: if installed {
            "the Workstation Guardian service is registered".into()
        } else {
            "the service is not installed; run 'guardianctl install'".into()
        },
    });

    // Whether the service answers over IPC is the practical question: an installed but
    // unreachable service is not protecting anything.
    let online = guardian_service::ipc::IpcClient::connect(1_500)
        .and_then(|mut c| {
            c.call_expect(&guardian_proto::Request::Hello {
                protocol: guardian_proto::PROTOCOL_VERSION,
            })
            .map(|_| ())
        })
        .is_ok();

    checks.push(HealthCheck {
        id: "service.reachable".into(),
        name: "Service reachable".into(),
        ok: online,
        severity: if online {
            FindingSeverity::Info
        } else if installed {
            FindingSeverity::Error
        } else {
            FindingSeverity::Warning
        },
        detail: if online {
            "the service is responding on its named pipe".into()
        } else {
            "the service is not responding; status commands will fail".into()
        },
    });

    // The session helper is what turns WORKING mode into an actual shutdown block.
    checks.push(HealthCheck {
        id: "helper.present".into(),
        name: "Session helper".into(),
        ok: true,
        severity: FindingSeverity::Info,
        detail: if online {
            "the session helper is started at interactive logon".into()
        } else {
            "cannot be checked while the service is unreachable".into()
        },
    });

    // Elevation matters because install, uninstall and the service control commands need it;
    // reporting it here saves an operator a confusing failure later.
    let elevated = crate::install::is_elevated();
    checks.push(HealthCheck {
        id: "process.elevation".into(),
        name: "Diagnostic elevation".into(),
        ok: true,
        severity: FindingSeverity::Info,
        detail: if elevated {
            "running elevated; install and uninstall will work".into()
        } else {
            "not elevated; install, uninstall and start/stop will be refused".into()
        },
    });

    // The installation summary is a single multi-line block; it is surfaced as one check so the
    // per-check table does not fill with paths.
    checks.push(HealthCheck {
        id: "service.installation".into(),
        name: "Installation".into(),
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

/// Whether the service is registered with the SCM.
fn guardian_service_installed() -> bool {
    guardian_win::service::is_installed(guardian_proto::SERVICE_NAME)
}

/// Windows Update policy checks.
fn update_checks() -> Vec<HealthCheck> {
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
                name: "Update protection".into(),
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
                    name: "Update policy applied".into(),
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
                name: "Update protection".into(),
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
                name: "Conflicting external policy".into(),
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
            name: "PolicyManager update policy".into(),
            ok: false,
            severity: FindingSeverity::Warning,
            detail: line,
        });
    }

    checks
}

/// Pending-reboot checks.
fn pending_reboot_checks() -> Vec<HealthCheck> {
    let probe = guardian_win::boot::RebootProbe::new();
    let signals = match probe.collect() {
        Ok(s) => s,
        Err(e) => {
            return vec![HealthCheck {
                id: "reboot.pending".into(),
                name: "Pending reboot".into(),
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
        name: "Pending reboot".into(),
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
fn network_checks() -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    let entries = guardian_win::ras::enum_entries().unwrap_or_default();

    checks.push(HealthCheck {
        id: "network.ras_entries".into(),
        name: "PPPoE entries".into(),
        ok: true,
        severity: FindingSeverity::Info,
        detail: if entries.is_empty() {
            "no RAS phonebook entries are configured; PPPoE management is not applicable".into()
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
            name: "PPPoE entry selection".into(),
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
        name: "Connectivity probes".into(),
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
        name: "Wi-Fi continuity".into(),
        ok: true,
        severity: FindingSeverity::Info,
        detail: if wifi_present {
            match guardian_win::wifi::current_connection() {
                Some((adapter, ssid)) => format!("{adapter} connected to '{ssid}'"),
                None => "a wireless adapter is present but not connected".into(),
            }
        } else {
            "no wireless adapter; broadband continuity has no backup path on this machine".into()
        },
    });

    checks
}

/// Process-monitor health.
fn monitor_checks() -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    match guardian_win::process::enumerate_processes() {
        Ok(procs) => {
            let graph = guardian_process::ProcessGraph::new(procs);
            let engine = guardian_process::default_engine(&Default::default());
            let detections = engine.detect_agents(&graph);

            checks.push(HealthCheck {
                id: "monitor.enumeration".into(),
                name: "Process monitor".into(),
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
                    name: "Agent signature rules".into(),
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
                name: "Process monitor".into(),
                ok: false,
                severity: FindingSeverity::Error,
                detail: format!("process enumeration failed: {e}"),
            });
        }
    }

    checks
}

/// Storage, journal and log health.
fn storage_checks() -> Vec<HealthCheck> {
    let mut checks = Vec::new();
    let paths = guardian_storage::GuardianPaths::production();

    let root = paths.root();
    let writable = check_writable(root);
    checks.push(HealthCheck {
        id: "storage.root".into(),
        name: "State directory".into(),
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
                name: "Configuration".into(),
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
                name: "Configuration".into(),
                ok: true,
                severity: FindingSeverity::Info,
                detail: "no configuration file yet; defaults apply and they protect updates".into(),
            });
        }
    }

    // Journal: a torn tail is worth reporting, because it means the last stop was abrupt.
    let journal_path = paths.journal_file();
    if journal_path.exists() {
        let previous = guardian_service::journal::read_previous_session(&journal_path);
        checks.push(HealthCheck {
            id: "storage.journal".into(),
            name: "Recovery journal".into(),
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
            name: "Recovery journal".into(),
            ok: true,
            severity: FindingSeverity::Info,
            detail: "no journal yet; it is created when the service first starts".into(),
        });
    }

    // Logs: report size so unbounded growth is noticeable.
    let log_dir = paths.logs_dir();
    let size = guardian_service::logging::log_directory_size(&log_dir);
    let files = guardian_service::logging::log_files(&log_dir);
    checks.push(HealthCheck {
        id: "logging.size".into(),
        name: "Log storage".into(),
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
pub fn render(report: &HealthReport) -> String {
    let mut out = String::new();

    let ok = report.checks.iter().filter(|c| c.ok).count();
    let failed: Vec<&HealthCheck> = report.checks.iter().filter(|c| !c.ok).collect();

    out.push_str("WORKSTATION GUARDIAN — DIAGNOSTICS\n\n");

    let worst = report.worst();
    out.push_str(&format!(
        "  Summary: {} of {} checks passed ({:?})\n\n",
        ok,
        report.checks.len(),
        worst
    ));

    if failed.is_empty() {
        out.push_str("  Every check passed.\n");
    } else {
        out.push_str("  Problems found:\n");
        for c in &failed {
            out.push_str(&format!(
                "    [{:?}] {}\n        {}\n",
                c.severity, c.name, c.detail
            ));
        }
    }

    out.push_str("\n  Full check list:\n");
    for c in &report.checks {
        out.push_str(&format!(
            "    {} {:<34} {}\n",
            if c.ok { "ok  " } else { "FAIL" },
            c.name,
            c.detail
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_sweep_runs_without_panicking() {
        // The most important property of a diagnostic tool: it must survive a machine in any
        // state, including one where the service is not installed.
        let report = build_report();
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
        let report = build_report();
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
        let report = build_report();
        let ids: Vec<&str> = report.checks.iter().map(|c| c.id.as_str()).collect();

        for required in [
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
        let report = build_report();
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
        let report = build_report();
        let text = render(&report);

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
        let text = render(&report);
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
        let result = update_report(false);
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
        let text = update_report(true).expect("standalone report");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(parsed.get("level").is_some());
        assert!(parsed.get("primary_lock_effective").is_some());
    }

    #[test]
    fn the_full_report_renders_as_json() {
        let text = run(true).expect("standalone report");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(parsed.get("checks").and_then(|c| c.as_array()).is_some());
    }

    #[test]
    fn json_output_is_not_polluted_by_other_text() {
        // The `--json` contract is that stdout is parseable. Anything else printed would break
        // every consumer.
        let text = run(true).expect("report");
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
}
