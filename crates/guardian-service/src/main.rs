//! `guardian-service` — console harness for the Guardian runtime.
//!
//! Guardian runs as an ordinary elevated tray application, not as a Windows service. This binary
//! exists so the runtime can be run, observed and tested without a GUI, which is what development
//! and diagnostics need.
//!
//! It registers nothing, installs nothing, and leaves nothing behind.

use std::time::Duration;

use guardian_service::runtime::{run, RuntimeOptions};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("guardian {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "guardian — Workstation Guardian runtime (console)

             USAGE:
    guardian [--run-for-seconds=<n>]

             Runs the protection runtime in the foreground. Run elevated for update protection to
             be effective. Normal use is the tray application (guardian-ui.exe)."
        );
        return;
    }

    let run_for = args
        .iter()
        .find_map(|a| a.strip_prefix("--run-for-seconds="))
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);

    match run_for {
        Some(d) => println!("running for {} seconds", d.as_secs()),
        None => println!("running; press Ctrl+C to stop"),
    }

    run(
        RuntimeOptions {
            run_for,
            echo_errors: true,
        },
        |_runtime| {},
    );
}
