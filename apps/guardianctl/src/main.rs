//! `guardianctl` — diagnostics for Workstation Guardian.
//!
//! Operates in two modes:
//!
//! * **Offline** (no arguments that need the runtime): reads system state directly. This is what
//!   makes `guardianctl doctor` work when Guardian is *not* running, which is exactly when it is
//!   most needed.
//! * **Online**: talks to the running Guardian over its named pipe.
//!
//! There is no `install` or `uninstall`: Guardian registers no Windows service and creates no
//! scheduled task. It is a tray application, so running it is the whole installation. The one thing
//! that does need undoing — the Windows Update policy it writes — is reached through
//! `restore-policy`, which is explicit and never a side effect of deleting files.
//!
//! No routine diagnostic requires PowerShell, `sc.exe`, `reg.exe` or any other external tool.

#![deny(unsafe_op_in_unsafe_fn)]

mod doctor;
mod install;
mod output;

use std::process::ExitCode;

use guardian_proto::i18n::Lang;
use guardian_proto::{Request, Response};

/// Command-line surface. Hand-parsed: the shape is small and fixed, and this avoids a
/// dependency whose version churn would have to be tracked for no benefit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status {
        json: bool,
    },
    Agents {
        json: bool,
    },
    Network {
        json: bool,
    },
    Update {
        json: bool,
    },
    Incidents {
        json: bool,
        limit: u16,
    },
    Doctor {
        json: bool,
    },
    /// Undo the Windows Update policy Guardian wrote. The only protection-reducing command.
    RestorePolicy,
    Help,
    Version,
}

impl Command {
    /// Whether this command needs the runtime to be running.
    pub fn needs_runtime(&self) -> bool {
        matches!(
            self,
            Command::Status { .. }
                | Command::Agents { .. }
                | Command::Network { .. }
                | Command::Incidents { .. }
        )
    }

    pub fn wants_json(&self) -> bool {
        matches!(
            self,
            Command::Status { json: true }
                | Command::Agents { json: true }
                | Command::Network { json: true }
                | Command::Update { json: true }
                | Command::Incidents { json: true, .. }
                | Command::Doctor { json: true }
        )
    }
}

/// Parse the command line.
///
/// An unrecognised argument is an error rather than being ignored: silently doing something
/// other than what was asked is how an operator ends up misdiagnosing a machine.
pub fn parse_args(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Ok(Command::Help);
    }

    let subcommand = args[0].as_str();
    let rest = &args[1..];

    let json = rest.iter().any(|a| a == "--json");

    // Reject anything that is not a flag we understand, so a typo is caught here rather than
    // changing behaviour silently. `--limit` and `--lang` take values, so their arguments are
    // skipped.
    let mut index = 0usize;
    while index < rest.len() {
        let a = rest[index].as_str();
        match a {
            "--json" => {}
            "--lang" | "--limit" => {
                // Consumed, with their value checked below where it matters. Skipping the value
                // here stops it being mistaken for an unknown flag.
                index += 1;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag '{other}'"));
            }
            // A bare positional argument is not part of any command's syntax.
            other => return Err(format!("unexpected argument '{other}'")),
        }
        index += 1;
    }

    let limit = rest
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| rest.get(i + 1))
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(50);

    match subcommand {
        "status" => Ok(Command::Status { json }),
        "agents" => Ok(Command::Agents { json }),
        "network" => Ok(Command::Network { json }),
        "update" => Ok(Command::Update { json }),
        "incidents" => Ok(Command::Incidents { json, limit }),
        "doctor" => Ok(Command::Doctor { json }),
        "restore-policy" => Ok(Command::RestorePolicy),
        "help" | "--help" | "-h" => Ok(Command::Help),
        "version" | "--version" | "-V" => Ok(Command::Version),
        other => Err(format!(
            "unknown command '{other}'; run 'guardianctl help' for the list"
        )),
    }
}

fn help_text() -> &'static str {
    "\
guardianctl — Workstation Guardian diagnostics

USAGE:
    guardianctl <command> [--json] [options]

COMMANDS:
    status           Overall protection, network and agent state
    agents           Detected AI coding agents and protected workloads
    network          PPPoE and Wi-Fi state, including outage history
    update           Windows Update protection state and policy detail
    incidents        Recorded incidents, newest first
    doctor           Full diagnostic sweep of every subsystem
    restore-policy   Undo the Windows Update policy Guardian wrote
    help             Show this text
    version          Show the version

OPTIONS:
    --json              Machine-readable output
    --limit <n>         Maximum incidents to show (default 50)
    --lang <code>       Language: auto, en, zh-CN (default: from configuration)

Guardian runs as a tray application; there is no service to install or start.
Diagnostics never require PowerShell, reg.exe or sc.exe. Output is local only:
nothing is uploaded."
}

/// Read the value of a `--flag value` pair from the argument list.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

/// The language to render in.
///
/// Read from the machine configuration, so the CLI and the tray panel agree. A missing or corrupt
/// file yields `Auto`, which follows the operating system.
fn configured_language() -> Lang {
    let paths = guardian_storage::GuardianPaths::production();
    match std::fs::read_to_string(paths.config_file()) {
        Ok(text) => {
            let validated = guardian_core::config::load_from_str(&text);
            validated.document.body.language
        }
        Err(_) => Lang::Auto,
    }
}

/// Run a command that requires the service.
fn run_online(command: &Command, json: bool, lang: Lang) -> Result<String, String> {
    let mut client = guardian_service::ipc::IpcClient::connect(5_000).map_err(|e| {
        format!(
            "could not reach the Workstation Guardian service: {e}\n\
             The service may not be running. Run 'guardianctl doctor' for a full check."
        )
    })?;

    // Negotiate the protocol version first, so a mismatch is reported clearly rather than
    // producing a confusing decode error.
    match client.call_expect(&Request::Hello {
        protocol: guardian_proto::PROTOCOL_VERSION,
    })? {
        Response::Hello {
            protocol,
            service_version,
            ..
        } => {
            if protocol != guardian_proto::PROTOCOL_VERSION {
                return Err(format!(
                    "protocol mismatch: this tool speaks {} but the service speaks {protocol} \
                     (service version {service_version})",
                    guardian_proto::PROTOCOL_VERSION
                ));
            }
        }
        other => {
            return Err(format!(
                "unexpected reply to the version handshake: {other:?}"
            ))
        }
    }

    let request = match command {
        Command::Status { .. } => Request::GetStatus,
        Command::Agents { .. } => Request::GetAgents,
        Command::Network { .. } => Request::GetNetwork,
        Command::Incidents { limit, .. } => Request::GetIncidents { limit: *limit },
        other => return Err(format!("{other:?} does not require the runtime")),
    };

    let response = client.call_expect(&request)?;

    if json {
        return serde_json::to_string_pretty(&response)
            .map_err(|e| format!("could not render the response as JSON: {e}"));
    }

    Ok(output::render_response(&response, lang))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let command = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardianctl: {e}");
            return ExitCode::from(2);
        }
    };

    // Diagnostics write to stdout; initialise logging to stderr so it does not corrupt JSON.
    guardian_service::logging::init_stderr(&guardian_proto::model::LoggingConfig {
        level: "warn".into(),
        ..Default::default()
    });

    // The language is taken from `--lang` when given, and from configuration otherwise. Falling
    // back to `auto` means a user gets their own language without setting anything, while an
    // operator debugging a machine can still read output in theirs.
    let lang = flag_value(&args, "--lang")
        .map(|v| Lang::parse(&v))
        .unwrap_or_else(configured_language);

    let json = command.wants_json();

    let result: Result<Option<String>, String> = match &command {
        Command::Help => {
            println!("{}", help_text());
            Ok(None)
        }
        Command::Version => {
            println!("guardianctl {}", env!("CARGO_PKG_VERSION"));
            Ok(None)
        }
        Command::Status { .. }
        | Command::Agents { .. }
        | Command::Network { .. }
        | Command::Incidents { .. } => run_online(&command, json, lang).map(Some),
        Command::Update { .. } => doctor::update_report(json, lang).map(Some),
        Command::Doctor { .. } => doctor::run(json, lang).map(Some),
        // The one command that reduces protection. It is named for what it does so it cannot be
        // mistaken for routine cleanup, and it reports exactly which values it restored.
        Command::RestorePolicy => install::restore_policy().map(Some),
    };

    match result {
        Ok(Some(text)) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("guardianctl: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn every_documented_command_parses() {
        assert_eq!(parse_args(&args(&[])).unwrap(), Command::Help);
        assert_eq!(
            parse_args(&args(&["status"])).unwrap(),
            Command::Status { json: false }
        );
        assert_eq!(
            parse_args(&args(&["status", "--json"])).unwrap(),
            Command::Status { json: true }
        );
        assert_eq!(
            parse_args(&args(&["agents"])).unwrap(),
            Command::Agents { json: false }
        );
        assert_eq!(
            parse_args(&args(&["network"])).unwrap(),
            Command::Network { json: false }
        );
        assert_eq!(
            parse_args(&args(&["update"])).unwrap(),
            Command::Update { json: false }
        );
        assert_eq!(
            parse_args(&args(&["doctor"])).unwrap(),
            Command::Doctor { json: false }
        );
        assert_eq!(
            parse_args(&args(&["incidents"])).unwrap(),
            Command::Incidents {
                json: false,
                limit: 50
            }
        );
    }

    #[test]
    fn incident_limit_is_parsed() {
        assert_eq!(
            parse_args(&args(&["incidents", "--limit", "5"])).unwrap(),
            Command::Incidents {
                json: false,
                limit: 5
            }
        );
        // A malformed limit falls back to the default rather than failing.
        assert_eq!(
            parse_args(&args(&["incidents", "--limit", "abc"])).unwrap(),
            Command::Incidents {
                json: false,
                limit: 50
            }
        );
    }

    #[test]
    fn the_restore_policy_command_replaces_the_old_service_commands() {
        assert_eq!(
            parse_args(&args(&["restore-policy"])).unwrap(),
            Command::RestorePolicy
        );

        // The service-era commands must now be rejected rather than silently accepted, because
        // there is no service to install, start or stop. An operator with an old script must be
        // told, not left believing something happened.
        for gone in ["install", "uninstall", "start", "stop"] {
            let err = parse_args(&args(&[gone])).unwrap_err();
            assert!(
                err.contains(gone),
                "'{gone}' must be reported as unknown, got: {err}"
            );
        }
    }

    #[test]
    fn the_removed_flags_are_no_longer_accepted() {
        // `--force` and `--keep-policy` only ever meant anything to install/uninstall.
        for flag in ["--force", "--keep-policy"] {
            let err = parse_args(&args(&["restore-policy", flag])).unwrap_err();
            assert!(err.contains(flag), "flag {flag} must be rejected: {err}");
        }
    }

    #[test]
    fn an_unknown_command_is_an_error() {
        // Silently doing nothing (or something else) would mislead an operator.
        let err = parse_args(&args(&["frobnicate"])).unwrap_err();
        assert!(err.contains("frobnicate"));
        assert!(err.contains("help"));
    }

    #[test]
    fn an_unknown_flag_is_an_error() {
        let err = parse_args(&args(&["status", "--turbo"])).unwrap_err();
        assert!(err.contains("--turbo"));
    }

    #[test]
    fn help_and_version_aliases_work() {
        for alias in ["help", "--help", "-h"] {
            assert_eq!(parse_args(&args(&[alias])).unwrap(), Command::Help);
        }
        for alias in ["version", "--version", "-V"] {
            assert_eq!(parse_args(&args(&[alias])).unwrap(), Command::Version);
        }
    }

    #[test]
    fn runtime_dependent_commands_are_identified() {
        assert!(Command::Status { json: false }.needs_runtime());
        assert!(Command::Agents { json: false }.needs_runtime());
        assert!(Command::Network { json: false }.needs_runtime());
        assert!(Command::Incidents {
            json: false,
            limit: 1
        }
        .needs_runtime());

        // These must work *without* the runtime, since that is when they matter most: an operator
        // diagnosing a machine where Guardian is not running.
        assert!(!Command::Update { json: false }.needs_runtime());
        assert!(!Command::Doctor { json: false }.needs_runtime());
        assert!(!Command::RestorePolicy.needs_runtime());
    }

    #[test]
    fn the_lang_flag_is_accepted_with_its_value() {
        // The value must be consumed so it is not mistaken for an unknown flag.
        assert_eq!(
            parse_args(&args(&["status", "--lang", "zh-CN"])).unwrap(),
            Command::Status { json: false }
        );
        assert_eq!(
            parse_args(&args(&["doctor", "--lang", "en", "--json"])).unwrap(),
            Command::Doctor { json: true }
        );
        assert_eq!(
            flag_value(&args(&["status", "--lang", "en"]), "--lang").as_deref(),
            Some("en")
        );
        assert_eq!(flag_value(&args(&["status"]), "--lang"), None);
    }

    #[test]
    fn json_is_requested_only_where_documented() {
        assert!(Command::Status { json: true }.wants_json());
        assert!(!Command::Status { json: false }.wants_json());
        assert!(Command::Doctor { json: true }.wants_json());
        assert!(!Command::RestorePolicy.wants_json());
    }

    #[test]
    fn help_text_documents_every_command() {
        let help = help_text();
        for command in [
            "status",
            "agents",
            "network",
            "update",
            "incidents",
            "doctor",
            "restore-policy",
        ] {
            assert!(
                help.contains(command),
                "the help text must document '{command}'"
            );
        }
        assert!(help.contains("--json"));
        assert!(help.contains("--lang"));

        // The help must not advertise a service that no longer exists. Matching on the command
        // *line* rather than the whole text, because "restore-policy" contains "install" as a
        // substring and a naive search would flag it.
        for gone in ["install", "uninstall", "start", "stop"] {
            let listed = help.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with(&format!("{gone} "))
                    || trimmed.starts_with(&format!("{gone}\t"))
            });
            assert!(
                !listed,
                "the help text still lists the removed '{gone}' command"
            );
        }
        for gone in ["--force", "--keep-policy"] {
            assert!(!help.contains(gone), "the help still offers '{gone}'");
        }
    }
}
