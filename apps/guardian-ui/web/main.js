/*
 * Workstation Guardian control panel.
 *
 * Every value shown here comes from the service, and every action is a request to the service.
 * Nothing in this file decides anything about protection: if this script were deleted, the machine
 * would remain exactly as protected as it is now.
 */

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

let current = null;
let refreshTimer = null;

/* ------------------------------------------------------------------ helpers */

function el(id) {
  return document.getElementById(id);
}

function show(node, visible) {
  if (node) node.hidden = !visible;
}

function clear(node) {
  if (node) node.replaceChildren();
}

function addItem(list, text, className) {
  const li = document.createElement("li");
  li.textContent = text;
  if (className) li.className = className;
  list.appendChild(li);
}

/* Render a protection level, tagging it so the stylesheet can colour it. The text itself is the
   authority: colour is a convenience. */
function setLevel(id, level) {
  const node = el(id);
  if (!node) return;
  const text = level || "Unknown";
  node.textContent = text;
  node.dataset.level = String(text).toLowerCase();
}

function formatDuration(ms) {
  if (ms === null || ms === undefined || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, "0")}m`;
  return `${Math.floor(h / 24)}d ${String(h % 24).padStart(2, "0")}h`;
}

function formatTime(ms) {
  if (!ms) return "—";
  return new Date(ms).toLocaleTimeString();
}

/* ------------------------------------------------------------------ rendering */

function renderStatus(status) {
  current = status;

  setLevel("update-level", status.update.level);
  setLevel("restart-level", status.restart_protection);
  el("mode").textContent = status.mode;
  el("service").textContent = status.service.running
    ? `Running (${status.service.version})`
    : "Stopped";
  el("uptime").textContent = formatDuration(status.service.uptime_ms);

  const degraded = status.service.degraded_components || [];
  show(el("degraded-row"), degraded.length > 0);
  if (degraded.length) el("degraded").textContent = degraded.join(", ");

  el("pending").textContent = status.pending_reboot.verdict;

  renderUpdateDetail(status.update);
  renderNetwork(status.network);
  renderAgents(status.agents);
  renderMaintenance(status);

  el("subtitle").textContent = `Boot ${status.boot_id} · checked ${formatTime(status.generated_at_ms)}`;
}

function renderUpdateDetail(update) {
  const list = el("policy-values");
  clear(list);

  if (!update.values || update.values.length === 0) {
    addItem(list, "No policy values could be read.");
  } else {
    for (const v of update.values) {
      const observed = v.observed === null ? "absent" : describeValue(v.observed);
      addItem(list, `${v.name}: ${v.matches ? "ok" : "mismatch"} (expected ${describeValue(v.desired)}, found ${observed})`);
    }
  }

  const findings = el("update-findings");
  clear(findings);
  for (const f of update.findings || []) {
    addItem(findings, `${f.message}`, f.severity === "warning" ? "warn" : "");
  }

  if (update.management && update.management.kind !== "unmanaged") {
    addItem(findings, "This machine is externally managed, so update policy can be overridden.", "warn");
  }
}

function describeValue(value) {
  if (value === null || value === undefined) return "absent";
  if (typeof value === "object" && "type" in value) {
    return `${value.type} ${value.value}`;
  }
  return String(value);
}

function renderNetwork(network) {
  el("internet").textContent = network.internet
    ? network.internet[0].toUpperCase() + network.internet.slice(1)
    : "Unknown";
  el("entry").textContent = network.entry_name || "(not configured)";
  el("net-uptime").textContent = formatDuration(network.uptime_ms);

  // An ongoing outage is shown with its dial attempts and the last RAS error, because "it is
  // retrying" and "it has given up because your password changed" need different responses.
  const outage = network.current_outage;
  show(el("outage-row"), Boolean(outage));
  if (outage) {
    const lastError = (outage.ras_errors || []).slice(-1)[0];
    el("outage").textContent =
      `${formatDuration(outage.downtime_ms)} · ${outage.reason} · ${outage.dial_attempts} attempt(s)` +
      (lastError ? ` · ${lastError.message} (${lastError.code})` : "");
  }

  const probes = el("probes");
  clear(probes);
  if (!network.probes || network.probes.length === 0) {
    addItem(probes, "No connectivity probes are configured.");
  } else {
    for (const p of network.probes) {
      const detail = p.ok
        ? `${p.latency_ms ?? "?"}ms`
        : p.error || "failed";
      addItem(probes, `${p.id}: ${detail}`, p.ok ? "" : "warn");
    }
  }
}

function renderAgents(agents) {
  const body = el("agents-body");
  clear(body);

  const instances = [];
  for (const group of agents.agents || []) {
    for (const inst of group.instances || []) {
      instances.push(inst);
    }
  }

  show(el("agents-empty"), instances.length === 0);
  show(el("agents-table"), instances.length > 0);

  for (const inst of instances) {
    const tr = document.createElement("tr");
    const resumable =
      inst.resume && inst.resume.kind === "available" ? inst.resume.handle : "—";

    for (const text of [
      inst.display_name,
      inst.confidence,
      String(inst.pid),
      inst.project ? inst.project.name : "unknown",
      resumable,
    ]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }

  // Protected builds, attributed to their owning agent where known.
  const list = el("workloads-list");
  clear(list);
  const workloads = agents.workloads || [];
  show(el("workloads"), workloads.length > 0);
  for (const w of workloads) {
    const owner = w.owner_kind ? ` under ${w.owner_kind}` : "";
    addItem(list, `${w.display_name} (pid ${w.pid}, ${formatDuration(w.running_ms)})${owner}`);
  }

  // Candidates are shown but explicitly labelled as not protected, so nobody believes an
  // unconfirmed match is being defended.
  const candidates = el("candidates-list");
  clear(candidates);
  const cands = agents.candidates || [];
  show(el("candidates"), cands.length > 0);
  for (const c of cands) {
    const why = (c.evidence || [])[0];
    addItem(candidates, `${c.name} (pid ${c.pid}) — ${why ? why.detail : "matched some evidence"}`);
  }
}

function renderMaintenance(status) {
  const inMaintenance = String(status.mode).toUpperCase() === "MAINTENANCE";
  show(el("maintenance-locked"), !inMaintenance);
  show(el("maintenance-active"), inMaintenance);

  const blockers = status.maintenance_denial_reasons || [];
  show(el("blockers"), blockers.length > 0);
  const list = el("blockers-list");
  clear(list);
  for (const b of blockers) addItem(list, b);

  el("reboot-auth").textContent = status.reboot_authorization
    ? `armed until ${formatTime(status.reboot_authorization.expires_at_ms)}`
    : "none";
}

async function renderIncidents() {
  const res = await invoke("get_incidents", { limit: 50 });
  const list = el("incidents-list");
  clear(list);

  if (!res.ok) {
    show(el("incidents-empty"), true);
    el("incidents-empty").textContent = res.error;
    return;
  }

  const incidents = res.incidents || [];
  show(el("incidents-empty"), incidents.length === 0);

  for (const i of incidents) {
    const li = document.createElement("li");
    const when = document.createElement("span");
    when.className = "muted small";
    when.textContent = `${formatTime(i.at_ms)} — `;
    li.appendChild(when);
    li.appendChild(document.createTextNode(`${i.title}: ${i.summary}`));
    list.appendChild(li);
  }
}

/* ------------------------------------------------------------------ actions */

function setError(message) {
  const banner = el("error");
  if (message) {
    banner.textContent = message;
    banner.hidden = false;
    el("subtitle").textContent = "Service unreachable";
  } else {
    banner.hidden = true;
    banner.textContent = "";
  }
}

async function refresh() {
  const res = await invoke("get_status");
  if (res && res.ok) {
    setError(null);
    renderStatus(res.status);
    await renderIncidents();
  } else {
    // The service is the authority. If it cannot be reached, the panel says so rather than
    // continuing to show the last snapshot as though it were current - a stale "Protected" would
    // be the single most harmful thing this UI could display.
    setError(
      `Cannot reach the Workstation Guardian service${res && res.error ? `: ${res.error}` : ""}. ` +
        `Protection state is unknown. Run \`guardianctl doctor\` for details.`
    );
  }
}

/*
 * Ask for confirmation before an action that weakens protection.
 *
 * `requirePhrase` makes the operator type an exact string. That is deliberately more friction
 * than a second button: the whole design rests on updates being unlocked only by an explicit,
 * deliberate act.
 */
function confirmAction({ title, body, phrase }) {
  return new Promise((resolve) => {
    const dialog = el("confirm-dialog");
    el("confirm-title").textContent = title;
    el("confirm-body").textContent = body;
    show(el("confirm-phrase-row"), Boolean(phrase));
    if (phrase) {
      el("confirm-phrase").textContent = phrase;
      el("confirm-input").value = "";
    }

    const done = (value) => {
      dialog.close();
      el("confirm-ok").onclick = null;
      el("confirm-cancel").onclick = null;
      resolve(value);
    };

    el("confirm-ok").onclick = () => done(phrase ? el("confirm-input").value : true);
    el("confirm-cancel").onclick = () => done(null);
    dialog.showModal();
  });
}

async function enterMaintenance() {
  const hasBlockers = !el("blockers").hidden;
  let confirmation = "";
  let override = false;

  if (hasBlockers) {
    const answer = await confirmAction({
      title: "Protected work is running",
      body:
        "Entering maintenance mode while agents or builds are running risks losing their work if " +
        "Windows restarts. Guardian normally refuses this. To override, type the exact phrase below.",
      phrase: "I understand the risk",
    });
    if (answer === null) return;
    confirmation = answer;
    override = true;
  } else {
    const answer = await confirmAction({
      title: "Enter maintenance mode?",
      body:
        "This unlocks Windows Update so it can install. Guardian will still never authorize an " +
        "automatic restart on your behalf. You can leave maintenance at any time.",
    });
    if (!answer) return;
  }

  const res = await invoke("enter_maintenance", {
    overrideProtectedWork: override,
    confirmation,
  });
  if (!res.ok) {
    setError(res.error);
  } else {
    setError(null);
  }
  await refresh();
}

async function exitMaintenance() {
  const res = await invoke("exit_maintenance");
  if (!res.ok) setError(res.error);
  await refresh();
}

async function armReboot() {
  const answer = await confirmAction({
    title: "Authorize one reboot?",
    body:
      "This permits exactly one restart to proceed. It expires automatically, cannot be reused, " +
      "and is discarded on the next boot. Windows Update stays locked throughout.",
  });
  if (!answer) return;

  const res = await invoke("arm_reboot", { ttlSecs: 1800 });
  if (!res.ok) setError(res.error);
  await refresh();
}

async function disarmReboot() {
  const res = await invoke("disarm_reboot");
  if (!res.ok) setError(res.error);
  await refresh();
}

async function reconnect() {
  const res = await invoke("reconnect", { reason: "requested from the control panel" });
  if (!res.ok) setError(res.error);
  await refresh();
}

/* ------------------------------------------------------------------ wiring */

window.addEventListener("DOMContentLoaded", async () => {
  el("refresh").addEventListener("click", refresh);
  el("reconnect").addEventListener("click", reconnect);
  el("enter-maintenance").addEventListener("click", enterMaintenance);
  el("exit-maintenance").addEventListener("click", exitMaintenance);
  el("arm-reboot").addEventListener("click", armReboot);
  el("disarm-reboot").addEventListener("click", disarmReboot);
  el("exit-ui").addEventListener("click", async () => {
    const answer = await confirmAction({
      title: "Exit the control panel?",
      body:
        "This closes the panel only. The guardian service keeps running and your work stays " +
        "protected. Reopen it from the tray icon.",
    });
    if (answer) await invoke("exit_ui");
  });

  // The service pushes on a timer from the Rust side; the panel just re-renders.
  await listen("guardian://status", (event) => {
    const payload = event.payload;
    if (payload && payload.ok) {
      setError(null);
      renderStatus(payload.status);
    } else if (payload && payload.error) {
      setError(payload.error);
    }
  });

  await refresh();
  refreshTimer = setInterval(refresh, 10000);
});

window.addEventListener("beforeunload", () => {
  if (refreshTimer) clearInterval(refreshTimer);
});
