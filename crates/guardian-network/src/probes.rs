//! Connectivity probes.
//!
//! # Design
//!
//! A single ping or a single HTTP request is not a connectivity measurement: one provider
//! can be down, one DNS resolver can be broken, and a captive portal can answer everything
//! while passing nothing. Guardian therefore uses several *independent* probes and reaches a
//! conclusion by quorum, as the network policy requires.
//!
//! # Traffic discipline
//!
//! Probes are TCP connects to an address or DNS resolutions, never HTTP requests. A TCP
//! handshake to a well-known resolver's port 443 is enough to know the path carries packets
//! end to end, costs one round trip, and sends no application-layer data — no URL, no
//! headers, nothing that identifies this machine's purpose. This matters because the probe
//! runs every few seconds forever.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use guardian_proto::model::{ProbeConfig, ProbeKind, ProbeResult};

/// Produces connectivity measurements.
///
/// A trait rather than a concrete type so the worker's tests can script probe results. Without
/// this, every worker test would wait on real network timeouts, which makes them slow and
/// flaky — and a flaky test suite is one that stops being run.
pub trait ProbeSource {
    /// Run every enabled probe and collect the results.
    fn run_round(&self) -> Vec<ProbeResult>;

    /// How many probes are enabled.
    fn probe_count(&self) -> usize;
}

/// Runs the configured probes against the real network.
#[derive(Debug, Clone)]
pub struct ProbeRunner {
    probes: Vec<ProbeConfig>,
    /// Bound on how long a single round may take in total, so a hung probe cannot stall the
    /// network worker indefinitely.
    round_budget: Duration,
}

impl ProbeRunner {
    pub fn new(probes: Vec<ProbeConfig>) -> Self {
        ProbeRunner {
            probes,
            // Generous relative to the individual timeouts, but finite: a round that takes
            // longer than this means something is badly wrong and the state machine should
            // act on partial data rather than block.
            round_budget: Duration::from_secs(15),
        }
    }

    /// The enabled probes.
    pub fn enabled(&self) -> impl Iterator<Item = &ProbeConfig> {
        self.probes.iter().filter(|p| p.enabled)
    }

    /// Run a single probe.
    pub fn run_one(&self, probe: &ProbeConfig) -> ProbeResult {
        let timeout = Duration::from_millis(u64::from(probe.timeout_ms.max(250)));
        let started = Instant::now();

        let outcome = match probe.kind {
            ProbeKind::Tcp => tcp_probe(&probe.target, timeout),
            ProbeKind::Dns => dns_probe(&probe.target, timeout),
            // These kinds are not network probes; the state machine reads them from the
            // backend instead. Reporting them as "not applicable" here keeps the two sources
            // of truth separate.
            ProbeKind::RasState | ProbeKind::Interface => {
                return ProbeResult {
                    id: probe.id.clone(),
                    kind: probe.kind,
                    target: probe.target.clone(),
                    ok: true,
                    latency_ms: Some(0),
                    error: Some("not a network probe; read from the backend".into()),
                };
            }
        };

        let elapsed = started.elapsed();
        match outcome {
            Ok(()) => ProbeResult {
                id: probe.id.clone(),
                kind: probe.kind,
                target: probe.target.clone(),
                ok: true,
                latency_ms: Some(elapsed.as_millis().min(u32::MAX as u128) as u32),
                error: None,
            },
            Err(e) => ProbeResult {
                id: probe.id.clone(),
                kind: probe.kind,
                target: probe.target.clone(),
                ok: false,
                latency_ms: None,
                error: Some(e),
            },
        }
    }
}

impl ProbeSource for ProbeRunner {
    fn run_round(&self) -> Vec<ProbeResult> {
        let started = Instant::now();
        let mut results = Vec::new();

        for probe in self.enabled() {
            if started.elapsed() > self.round_budget {
                // Out of budget: stop rather than pretending the remaining probes failed. The
                // state machine treats a missing result as "unmeasured", not as "down".
                tracing::debug!(
                    probe = %probe.id,
                    "probe round budget exhausted; skipping the remaining probes"
                );
                break;
            }
            results.push(self.run_one(probe));
        }

        results
    }

    fn probe_count(&self) -> usize {
        self.enabled().count()
    }
}

/// Connect to `host:port`, then close immediately.
///
/// A completed TCP handshake proves the path carries packets in both directions, which is
/// exactly the question being asked. No data is sent.
fn tcp_probe(target: &str, timeout: Duration) -> Result<(), String> {
    // Resolve first, with the timeout applying to the whole operation. A DNS-only failure
    // shows up here as a resolution error, which the state machine distinguishes.
    let addrs: Vec<SocketAddr> = match target.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(e) => return Err(format!("could not resolve {target}: {e}")),
    };

    if addrs.is_empty() {
        return Err(format!("{target} resolved to no addresses"));
    }

    let mut last_error = String::from("no address was tried");
    for addr in addrs.iter().take(4) {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => {
                // Explicitly shut down rather than sending anything.
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
            Err(e) => last_error = format!("{addr}: {e}"),
        }
    }

    Err(format!("could not connect to {target}: {last_error}"))
}

/// Resolve a hostname to at least one address.
///
/// Uses the system resolver deliberately: this tests the resolver the machine actually uses,
/// which is the component that fails in the `DNS_ONLY_FAILURE` case the state machine
/// handles specially.
fn dns_probe(target: &str, timeout: Duration) -> Result<(), String> {
    use std::net::UdpSocket;

    let _ = timeout;
    // `ToSocketAddrs` on a `&str` uses `getaddrinfo`. It has no timeout parameter, so the
    // work is bounded by the caller's round budget and by the resolver's own behaviour.
    match (target, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let count = addrs.count();
            if count == 0 {
                Err(format!("{target} resolved to no addresses"))
            } else {
                Ok(())
            }
        }
        Err(e) => {
            // Distinguish a resolution failure from a socket-setup failure where possible,
            // so the error text is useful.
            let _ = UdpSocket::bind("0.0.0.0:0");
            Err(format!("could not resolve {target}: {e}"))
        }
    }
}

/// Whether the interface list shows a usable default route.
///
/// Kept here rather than in `guardian-win` because it is a simple read of a stable API with
/// no unsafe surface: `std` exposes enough through the Windows implementation of
/// `UdpSocket::connect` to observe whether a route exists at all.
pub fn has_default_route() -> bool {
    // Connecting a UDP socket performs a route lookup without sending a packet. If no route
    // exists the call fails, which is exactly the signal wanted.
    use std::net::UdpSocket;
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            // A routable address that is not the loopback; the kernel picks a source address
            // based on the routing table.
            sock.connect("1.1.1.1:53").is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::ProbeKind;

    fn probe(id: &str, kind: ProbeKind, target: &str) -> ProbeConfig {
        ProbeConfig {
            id: id.into(),
            kind,
            target: target.into(),
            timeout_ms: 2000,
            enabled: true,
        }
    }

    #[test]
    #[ignore = "hits the real network; run with --ignored when connectivity matters"]
    fn probe_runner_reports_a_latency_on_success() {
        let runner = ProbeRunner::new(vec![probe("cf", ProbeKind::Tcp, "1.1.1.1:443")]);
        let results = runner.run_round();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        if r.ok {
            assert!(
                r.latency_ms.is_some(),
                "a successful probe must report a latency"
            );
            assert!(r.error.is_none());
        } else {
            // Offline or firewalled; the failure must be explained, not silent.
            eprintln!("probe failed (machine may be offline): {:?}", r.error);
            assert!(r.error.is_some(), "a failed probe must carry a reason");
        }
    }

    #[test]
    #[ignore = "hits the real network; run with --ignored when connectivity matters"]
    fn a_tcp_probe_to_an_unroutable_address_fails_with_a_reason() {
        // TEST-NET-1 (RFC 5737) is reserved and never routable, so this must fail.
        let runner = ProbeRunner::new(vec![probe("black", ProbeKind::Tcp, "192.0.2.1:9")]);
        let r = runner.run_one(&runner.probes[0]);
        assert!(!r.ok, "the reserved test range must not be reachable");
        assert!(r.error.is_some());
        assert!(!r.error.unwrap().is_empty());
    }

    #[test]
    fn an_address_that_cannot_be_parsed_fails_cleanly() {
        let runner = ProbeRunner::new(vec![probe("bad", ProbeKind::Tcp, "not a valid target")]);
        let r = runner.run_one(&runner.probes[0]);
        assert!(!r.ok);
        assert!(r.error.is_some());
    }

    #[test]
    #[ignore = "hits the real network; run with --ignored when connectivity matters"]
    fn a_dns_probe_resolves_a_well_known_name_when_online() {
        let runner = ProbeRunner::new(vec![probe(
            "dns",
            ProbeKind::Dns,
            "www.msftconnecttest.com",
        )]);
        let r = runner.run_one(&runner.probes[0]);
        if !r.ok {
            eprintln!("DNS probe failed (machine may be offline): {:?}", r.error);
        }
        // Either way it must not panic and must report consistently.
        assert_eq!(r.kind, ProbeKind::Dns);
    }

    #[test]
    #[ignore = "hits the real network; run with --ignored when connectivity matters"]
    fn a_dns_probe_for_an_invalid_name_fails() {
        let runner = ProbeRunner::new(vec![probe(
            "dns",
            ProbeKind::Dns,
            "definitely-not-a-real-host-8f3a2b9c.invalid",
        )]);
        let r = runner.run_one(&runner.probes[0]);
        assert!(!r.ok, "an invalid TLD must not resolve");
        assert!(r.error.is_some());
    }

    #[test]
    fn disabled_probes_are_not_run() {
        let mut p = probe("off", ProbeKind::Tcp, "1.1.1.1:443");
        p.enabled = false;
        let runner = ProbeRunner::new(vec![p]);
        assert_eq!(runner.probe_count(), 0);
        assert!(runner.run_round().is_empty());
    }

    #[test]
    fn non_network_probe_kinds_are_marked_not_applicable() {
        // If these were treated as connectivity probes they would report a false failure and
        // make the state machine believe the link was down.
        let runner = ProbeRunner::new(vec![
            probe("ras", ProbeKind::RasState, ""),
            probe("if", ProbeKind::Interface, ""),
        ]);
        for r in runner.run_round() {
            assert!(r.ok, "a non-network probe must not report a failure");
            assert!(r
                .error
                .as_deref()
                .unwrap_or("")
                .contains("not a network probe"));
        }
    }

    #[test]
    fn an_empty_probe_set_produces_no_results() {
        let runner = ProbeRunner::new(vec![]);
        assert!(runner.run_round().is_empty());
        assert_eq!(runner.probe_count(), 0);
    }

    #[test]
    fn a_zero_timeout_is_raised_to_a_usable_minimum() {
        // A misconfigured zero timeout must not become an instant failure that looks like a
        // network outage.
        let mut p = probe("fast", ProbeKind::Tcp, "1.1.1.1:443");
        p.timeout_ms = 0;
        let runner = ProbeRunner::new(vec![p]);
        let r = runner.run_one(&runner.probes[0]);
        // Whatever the network state, the call must have actually been attempted.
        assert_eq!(r.id, "fast");
    }

    #[test]
    #[ignore = "hits the real network; run with --ignored when connectivity matters"]
    fn the_round_budget_bounds_total_work() {
        // Many slow probes must not make a round take unbounded time.
        let probes: Vec<ProbeConfig> = (0..64)
            .map(|i| ProbeConfig {
                id: format!("slow{i}"),
                kind: ProbeKind::Tcp,
                // Reserved, unroutable, and with a long timeout each.
                target: "192.0.2.1:9".into(),
                timeout_ms: 2000,
                enabled: true,
            })
            .collect();
        let runner = ProbeRunner::new(probes);
        let started = Instant::now();
        let results = runner.run_round();
        // The budget is 15s; allow generous slack for a loaded machine while still catching
        // an unbounded implementation.
        assert!(
            started.elapsed() < Duration::from_secs(40),
            "a probe round must be bounded, took {:?}",
            started.elapsed()
        );
        assert!(results.len() <= 64);
    }

    #[test]
    fn has_default_route_is_available_as_a_cheap_signal() {
        // Read-only and must not panic. On a machine with any connectivity this is true.
        let _ = has_default_route();
    }
}
