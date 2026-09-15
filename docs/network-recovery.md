# Network recovery

## The invariant

> **Broadband recovery attempts must not unnecessarily take the machine offline.**

Concretely: when PPPoE drops, Guardian establishes Wi-Fi continuity *first* and repairs PPPoE *in
parallel*, never by tearing down the only working path.

## Uplink order

```text
1. Healthy PPPoE / broadband
2. Healthy configured Wi-Fi
3. No connectivity
```

Broadband is always preferred. Wi-Fi is a backup, a warm standby, and a continuity path. It is
never promoted to preferred merely because it happened to recover first.

### Warm standby

By default Wi-Fi stays associated while broadband is healthy, at lower priority. When broadband
fails, failover is nearly immediate rather than waiting for an association.

## Why the RAS API, not `rasdial.exe`

Shelling out means spawning a process, parsing localised console output, and getting no structured
error codes. The RAS API reports each condition as a distinct code, in-process.

## Credentials

`RasDialW` is called with the **entry name only**. `szUserName` and `szPassword` are left empty, so
RAS uses the credentials stored with the phonebook entry, which live in Windows' own protected
storage.

Guardian never holds the broadband password, so it cannot leak it. Nothing in the network crate
accepts a password parameter.

## State machine

Two uplinks, modelled independently.

```text
PPPoE:   DISCONNECTED → CONNECTING → AUTHENTICATING → VERIFYING → HEALTHY
                                                          │
                                                          └→ DEGRADED / RECONNECTING / FAILED

Wi-Fi:   DISCONNECTED → CONNECTING → AUTHENTICATING → VERIFYING → HEALTHY / CONTINUITY / DEGRADED

Global:  BROADBAND_PRIMARY │ WIFI_CONTINUITY │ RECOVERING_BROADBAND │ DEGRADED │ OFFLINE
```

`UplinkPreference` is **derived** from the two uplink states on every evaluation, never assigned, so
the preference rule lives in exactly one place.

### A successful dial is not recovery

```text
PPPoE fails → Wi-Fi carries traffic → PPPoE reconnects
            → verify (RAS, route, DNS, several probes) → stabilization window → switch back
```

Before traffic moves back to broadband, the link must stay healthy through a stabilization window
(default 20s, configurable). This prevents the classic flap:

```text
PPPoE connects → route switches → PPPoE dies 2s later → switch back → reconnect → ...
```

If a link keeps failing shortly after being promoted, the required window **widens automatically**.
A link that repeatedly aborts is trusted less each time, not more.

## Link evidence versus path evidence

This distinction was learned from a real failure and is worth stating plainly.

* **Link evidence** — the session exists, has an address, and has a default route. It comes from the
  interface and routing layers and cannot be confused by a filtered network.
* **Path evidence** — a quorum of probes succeeds. It proves the *path*, not the link.

Conflating them caused an endless dial loop on a real network: a campus connection blocked direct
TCP to public resolver IPs, so a perfectly healthy PPPoE session failed its probe quorum, was
classified "session up but useless", was hung up, and was dialled again — forever.

So a freshly established link is judged on **link evidence alone** while it settles. Probe failures
demote only a link that was already proven healthy, where losing them is a real signal.

Both directions are covered by regression tests: a fresh link is not torn down prematurely, and an
established link that stops passing its probes is still demoted.

## Backoff

```text
0, 1s, 2s, 4s, 8s, 15s, 30s, 60s  (with jitter)
```

The schedule resets **only when a link reaches `Healthy`**. Entering verification does not reset it.

That is not a detail. A half-dead session — where RAS reports the connection as established while
the underlying link is gone — would otherwise reset the schedule on every attempt and redial at the
initial interval forever. Against a real ISP that is indistinguishable from an attack.

Verified on the machine: `0ms`, then `1161ms`, then `2052ms`.

### Concurrency

There is never more than one `RasDialW` in flight for an entry. The state machine serializes dial
decisions, and the backend holds a guard as insurance against a future refactor weakening that.

## Connectivity probes

Several independent probes, reaching a conclusion by **quorum**. One dead endpoint is not an outage.

Probes are TCP connects and DNS lookups — **never HTTP**. A TCP handshake to a well-known endpoint
is enough to know the path carries packets, costs one round trip, and sends no application-layer
data. That matters on a loop that runs every few seconds forever.

The default set mixes a hostname probe, a well-known IP, and a DNS lookup, so a network that
filters direct connections to public IPs still produces a usable signal. Every target is
configurable.

## Failure classification

```text
PPPOE_SESSION_LOST   NO_IP_CONFIGURATION   ROUTE_FAILURE   DNS_ONLY_FAILURE
AUTHENTICATION_FAILED   UPSTREAM_CONNECTIVITY_FAILURE   HIGH_PACKET_LOSS
PARTIAL_CONNECTIVITY   UNKNOWN
```

Two classifications change behaviour:

* **`DNS_ONLY_FAILURE`** — a working PPPoE session is **never** torn down for a resolver problem.
  All connectivity probes pass and DNS fails; destroying a good session would turn a fixable problem
  into an outage.
* **`AUTHENTICATION_FAILED`** — retrying with the same credentials is pointless, and retrying
  anyway looks like a dial loop in the log. Guardian stops and reports until the configuration
  changes.

## Session cleanup

A session that is up but useless — no IP, no route, nothing upstream answering — is hung up and
re-dialled. Hanging up is only done when something else is already carrying traffic, or nothing was
carrying it to begin with. Guardian never removes the only path to fix a path.

## UI

The panel shows broadband, Wi-Fi, and which is carrying traffic:

```text
Internet              Healthy
PPPoE entry           宽带连接
RAS state             Connected
Connection uptime     4s
Outage                ongoing, 30s (3 attempts) · PPPOE_SESSION_LOST · no answer (678)
```

The raw RAS error code is always shown alongside the translation, because a translation that is
missing is far better than one that is wrong.

```powershell
guardianctl network
```

prints the same, plus probe results and recent outage history.
