//! `guardianctl` — diagnostics, installation and service control.
//!
//! Operates in two modes:
//!
//! * **Offline** (no arguments that need the service): reads system state directly. This is what
//!   makes `guardianctl doctor` work when the service is *not* running, which is exactly when it
//!   is most needed.
//! * **Online**: talks to the running service over the named pipe.
//!
//! No routine diagnostic requires PowerShell, `sc.exe`, `reg.exe` or any other external tool.

#![deny(unsafe_op_in_unsafe_fn)]

mod doctor;
mod install;
mod output;

use std::process::ExitCode;

use guardian_proto::{Request, Response};

/// Command-line surface. Hand-parsed: the shape is small and fixed, and this avoids a
/// dependency whose version churn would have to be tracked for no benefit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status { json: bool },
    Agents { json: bool },
    Network { json: bool },
    Update { json: bool },
    Incidents { json: bool, limit: u16 },
    Doctor { json: bool },
    Install { force: bool },
    Uninstall { keep_policy: bool },
    Start,
    Stop,
    Help,
    Version,
}

impl Command {
    /// Whether this command needs the service to be running.
    pub fn needs_service(&self) -> bool {
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
    let force = rest.iter().any(|a| a == "--force");
    let keep_policy = rest.iter().any(|a| a == "--keep-policy");

    // Reject anything that is not a flag we understand, so a typo is caught here rather than
    // changing behaviour silently. `--limit` takes a value, so its argument is skipped.
    let mut index = 0usize;
    while index < rest.len() {
        let a = rest[index].as_str();
        match a {
            "--json" | "--force" | "--keep-policy" => {}
            "--limit" => {
                // The value is validated below; here we only need to know it was consumed so it
                // is not mistaken for an unknown flag.
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
        "install" => Ok(Command::Install { force }),
        "uninstall" => Ok(Command::Uninstall { keep_policy }),
        "start" => Ok(Command::Start),
        "stop" => Ok(Command::Stop),
        "help" | "--help" | "-h" => Ok(Command::Help),
        "version" | "--version" | "-V" => Ok(Command::Version),
        other => Err(format!(
            "unknown command '{other}'; run 'guardianctl help' for the list"
        )),
    }
}

fn help_text() -> &'static str {
    "\
guardianctl — Workstation Guardian diagnostics and control

USAGE:
    guardianctl <command> [--json] [options]

COMMANDS:
    status        Overall protection, network and agent state
    agents        Detected AI coding agents and protected workloads
    network       PPPoE and Wi-Fi state, including outage history
    update        Windows Update protection state and policy detail
    incidents     Recorded incidents, newest first
    doctor        Full diagnostic sweep of every subsystem
    install       Install the service and supporting components
    uninstall     Remove the service and report policy restoration
    start         Start the service
    stop          Stop the service
    help          Show this text
    version       Show the version

OPTIONS:
    --json              Machine-readable output
    --limit <n>         Maximum incidents to show (default 50)
    --force             Reinstall even if already installed
    --keep-policy       Leave update policy in place when uninstalling

Diagnostics never require PowerShell, reg.exe or sc.exe. Output is local only:
nothing is uploaded."
}

/// Run a command that requires the service.
fn run_online(command: &Command, json: bool) -> Result<String, String> {
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
        other => return Err(format!("{other:?} does not require the service")),
    };

    let response = client.call_expect(&request)?;

    if json {
        return serde_json::to_string_pretty(&response)
            .map_err(|e| format!("could not render the response as JSON: {e}"));
    }

    Ok(output::render_response(&response))
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
        | Command::Incidents { .. } => run_online(&command, json).map(Some),
        Command::Update { .. } => doctor::update_report(json).map(Some),
        Command::Doctor { .. } => doctor::run(json).map(Some),
        Command::Install { force } => install::install(*force).map(Some),
        Command::Uninstall { keep_policy } => install::uninstall(*keep_policy).map(Some),
        Command::Start => install::control_service(install::ServiceAction::Start).map(Some),
        Command::Stop => install::control_service(install::ServiceAction::Stop).map(Some),
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
    fn install_and_uninstall_flags_are_recognized() {
        assert_eq!(
            parse_args(&args(&["install", "--force"])).unwrap(),
            Command::Install { force: true }
        );
        assert_eq!(
            parse_args(&args(&["uninstall", "--keep-policy"])).unwrap(),
            Command::Uninstall { keep_policy: true }
        );
        assert_eq!(
            parse_args(&args(&["uninstall"])).unwrap(),
            Command::Uninstall { keep_policy: false }
        );
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
    fn service_dependent_commands_are_identified() {
        assert!(Command::Status { json: false }.needs_service());
        assert!(Command::Agents { json: false }.needs_service());
        assert!(Command::Network { json: false }.needs_service());
        assert!(Command::Incidents {
            json: false,
            limit: 1
        }
        .needs_service());

        // These must work *without* the service, since that is when they matter most.
        assert!(!Command::Update { json: false }.needs_service());
        assert!(!Command::Doctor { json: false }.needs_service());
        assert!(!Command::Install { force: false }.needs_service());
        assert!(!Command::Uninstall { keep_policy: false }.needs_service());
    }

    #[test]
    fn json_is_requested_only_where_documented() {
        assert!(Command::Status { json: true }.wants_json());
        assert!(!Command::Status { json: false }.wants_json());
        assert!(Command::Doctor { json: true }.wants_json());
        assert!(!Command::Install { force: false }.wants_json());
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
            "install",
            "uninstall",
            "start",
            "stop",
        ] {
            assert!(
                help.contains(command),
                "the help text must document '{command}'"
            );
        }
        assert!(help.contains("--json"));
    }
}
