/*
 * Workstation Guardian control panel.
 *
 * Every value shown here comes from the runtime, and every label is looked up by key. Nothing in
 * this file decides anything about protection: if this script were deleted, the machine would
 * remain exactly as protected as it is now.
 *
 * The rule the whole project rests on applies here too. A stale "Protected" is the single most
 * harmful thing this panel could show, so when the panel cannot reach the runtime it says so rather
 * than leaving the last values on screen.
 */

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

let current = null;
let currentLang = "en";

/* ------------------------------------------------------------------ strings */

/*
 * The panel's own vocabulary. Status words ("Protected", "Degraded") are NOT here: those come from
 * the runtime in the panel document, because the tray, the panel and the CLI must never disagree
 * about what a state is called.
 */
const STRINGS = {
  en: {
    title: "Workstation Guardian",
    connecting: "Starting…",
    subtitle: (version, when) => `Version ${version} · updated ${when}`,
    starting: "Starting — protection is being applied",
    unreachable: "The protection runtime has not reported yet. Protection state is unknown.",
    protection: "Protection",
    update_protection: "Update protection",
    restart_protection: "Restart protection",
    mode: "Mode",
    uptime: "Uptime",
    degraded: "Degraded",
    pending_reboot: "Pending reboot",
    update_detail: "Why this verdict",
    network: "Network",
    internet: "Internet",
    pppoe: "PPPoE entry",
    reconnect: "Reconnect Internet",
    reconnect_note:
      "The network guardian dials on its own when the link is down. This only records that you asked for it now.",
    reconnected: "Reconnect requested.",
    active_work: "Active work",
    nothing_detected: "Nothing detected.",
    agent: "Agent",
    confidence: "Confidence",
    sessions: "Sessions",
    project: "Project",
    protected_builds: "Protected builds",
    candidates: "Unconfirmed candidates",
    candidates_note:
      "These matched some agent evidence but not enough to be trusted. They are reported for information and never block a shutdown.",
    incidents: "Incidents",
    no_incidents: "No incidents recorded.",
    refresh: "Refresh",
    hide: "Hide to tray",
    exit_app: "Exit Guardian",
    exit_note:
      'Closing this window hides it to the tray; protection continues. Only "Exit Guardian" stops it.',
    guarantee_note:
      "Guardian reduces the risk of an unexpected restart. It cannot make Windows unable to reboot.",
    not_elevated:
      "Not running as administrator: the Windows Update policy cannot be applied. Restart Guardian as administrator for full protection.",
    recovered: "The previous session ended unexpectedly. State was recovered; no work was discarded.",
    confirm: "Confirm",
    cancel: "Cancel",
    confirm_exit_title: "Exit Workstation Guardian?",
    confirm_exit_body:
      "This stops protection and removes the tray icon. Windows Update will be unlocked, and a restart could then proceed without Guardian noticing. Reopen Guardian to protect the machine again.",
    confirm_reconnect_title: "Reconnect now?",
    confirm_reconnect_body:
      "The network guardian already reconnects on its own. This asks it to check immediately.",
    no_policy_values: "No policy values could be read.",
    unknown_project: "unknown",
    boot: "Boot",
  },
  zh: {
    title: "Workstation Guardian",
    connecting: "正在启动…",
    subtitle: (version, when) => `版本 ${version} · 更新于 ${when}`,
    starting: "正在启动 — 正在应用保护",
    unreachable: "保护运行时尚未上报。当前保护状态未知。",
    protection: "保护",
    update_protection: "更新保护",
    restart_protection: "重启保护",
    mode: "模式",
    uptime: "运行时长",
    degraded: "降级组件",
    pending_reboot: "待重启",
    update_detail: "判定原因",
    network: "网络",
    internet: "互联网",
    pppoe: "PPPoE 宽带",
    reconnect: "重新连接网络",
    reconnect_note: "链路中断时网络守护会自动重拨。此按钮仅表示你希望立即检查。",
    reconnected: "已请求重连。",
    active_work: "进行中的工作",
    nothing_detected: "未检测到。",
    agent: "Agent",
    confidence: "置信度",
    sessions: "会话数",
    project: "项目",
    protected_builds: "受保护的构建",
    candidates: "未确认的候选",
    candidates_note:
      "这些进程命中部分特征但证据不足，仅供参考，不会阻止关机。",
    incidents: "事件记录",
    no_incidents: "暂无事件记录。",
    refresh: "刷新",
    hide: "隐藏到托盘",
    exit_app: "退出 Guardian",
    exit_note: "关闭此窗口只会隐藏到托盘，保护将继续。只有“退出 Guardian”才会停止保护。",
    guarantee_note: "Guardian 可降低意外重启的风险，但无法让 Windows 完全无法重启。",
    not_elevated:
      "未以管理员身份运行：无法应用 Windows Update 策略。请以管理员身份重新启动 Guardian 以获得完整保护。",
    recovered: "上一次会话非正常结束。状态已恢复；未丢弃任何工作。",
    confirm: "确认",
    cancel: "取消",
    confirm_exit_title: "退出 Workstation Guardian？",
    confirm_exit_body:
      "这将停止保护并移除托盘图标。Windows Update 将被解锁，此后重启可能在 Guardian 不知情的情况下进行。重新打开 Guardian 可再次保护本机。",
    confirm_reconnect_title: "立即重连？",
    confirm_reconnect_body: "网络守护已会自动重连。此操作只是让它立即检查一次。",
    no_policy_values: "未能读取任何策略值。",
    unknown_project: "未知",
    boot: "启动标识",
  },
};

/* Look up a string, falling back to English so a missing key can never render as blank. */
function t(key, ...args) {
  const table = STRINGS[currentLang] || STRINGS.en;
  const entry = table[key] !== undefined ? table[key] : STRINGS.en[key];
  if (entry === undefined) return key;
  return typeof entry === "function" ? entry(...args) : entry;
}

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
  if (!list) return;
  const li = document.createElement("li");
  li.textContent = text;
  if (className) li.className = className;
  list.appendChild(li);
}

/* Apply the static translations to the markup. */
function applyStaticStrings() {
  for (const node of document.querySelectorAll("[data-i18n]")) {
    const key = node.dataset.i18n;
    const value = t(key);
    if (typeof value === "string") node.textContent = value;
  }
  document.documentElement.lang = currentLang === "zh" ? "zh-CN" : "en";
}

/* Render a protection level. The text is the authority; the class only colours it. */
function setLevel(id, level, label) {
  const node = el(id);
  if (!node) return;
  node.textContent = label || level || "—";
  node.dataset.level = String(level || "unknown").toLowerCase();
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
  return new Date(ms).toLocaleString();
}

/* ------------------------------------------------------------------ rendering */

function renderPanel(payload) {
  const panel = payload.panel;
  current = panel;
  currentLang = panel.lang === "zh-CN" || panel.lang === "zh" ? "zh" : "en";
  applyStaticStrings();

  // A machine that is not elevated cannot have its policy applied. Saying that plainly is the
  // difference between an operator fixing it and an operator believing they are covered.
  const warnings = [];
  if (!payload.elevated) warnings.push(t("not_elevated"));
  if (panel.unclean_previous_exit) warnings.push(t("recovered"));
  const warning = el("warning");
  if (warnings.length) {
    warning.textContent = warnings.join(" ");
    warning.hidden = false;
  } else {
    warning.hidden = true;
  }

  setLevel("update-level", panel.update.level, panel.update.label);
  setLevel("restart-level", panel.restart_protection.level, panel.restart_protection.label);
  el("mode").textContent = panel.mode.label;
  el("uptime").textContent = formatDuration(panel.uptime_ms);
  el("pending").textContent = panel.pending_reboot.label;

  const degraded = panel.degraded_components || [];
  show(el("degraded-row"), degraded.length > 0);
  if (degraded.length) el("degraded").textContent = degraded.join(", ");

  renderUpdateDetail(panel.update);
  renderNetwork(panel.network);
  renderAgents(panel);

  el("subtitle").textContent = t("subtitle", panel.version, formatTime(panel.generated_at_ms));
}

function renderUpdateDetail(update) {
  const list = el("update-findings");
  clear(list);

  const findings = update.findings || [];
  if (findings.length === 0) {
    // No findings means the policy is exactly as intended. Saying so is better than an empty list,
    // which reads like a failure to load.
    addItem(list, `${t("update_protection")}: ${update.label}`);
  } else {
    for (const f of findings) addItem(list, f, "warn");
  }

  if (update.backend_error) addItem(list, update.backend_error, "warn");
}

function renderNetwork(network) {
  el("internet").textContent = network.internet_label;
  el("entry").textContent = network.entry_name || "—";
}

function renderAgents(panel) {
  const body = el("agents-body");
  clear(body);

  const agents = panel.agents || [];
  show(el("agents-empty"), agents.length === 0);
  show(el("agents-table"), agents.length > 0);

  for (const group of agents) {
    const tr = document.createElement("tr");
    for (const text of [
      group.display_name,
      group.confidence_label,
      String(group.instance_count),
      group.project || t("unknown_project"),
    ]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
}

async function renderIncidents() {
  const list = el("incidents-list");
  clear(list);

  const res = await invoke("get_incidents", { limit: 50 });
  if (!res.ok) {
    show(el("incidents-empty"), true);
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
  } else {
    banner.hidden = true;
    banner.textContent = "";
  }
}

async function refresh() {
  const res = await invoke("get_panel");

  if (res && res.ok) {
    setError(null);
    renderPanel(res);
    await renderIncidents();
  } else {
    // The runtime is the authority. If it has not reported, the panel says so rather than
    // continuing to show the last document as though it were current.
    setError(res && res.message ? res.message : t("unreachable"));
    if (res) {
      currentLang = res.lang === "zh-CN" ? "zh" : currentLang;
      applyStaticStrings();
    }
  }
}

/*
 * Ask for confirmation before an action that stops or weakens protection.
 *
 * That is deliberately more friction than a second button: the design rests on protection being
 * stopped only by an explicit, deliberate act.
 */
function confirmAction({ title, body }) {
  return new Promise((resolve) => {
    const dialog = el("confirm-dialog");
    el("confirm-title").textContent = title;
    el("confirm-body").textContent = body;

    const done = (value) => {
      dialog.close();
      el("confirm-ok").onclick = null;
      el("confirm-cancel").onclick = null;
      resolve(value);
    };

    el("confirm-ok").onclick = () => done(true);
    el("confirm-cancel").onclick = () => done(false);
    dialog.showModal();
  });
}

async function exitApp() {
  const answer = await confirmAction({
    title: t("confirm_exit_title"),
    body: t("confirm_exit_body"),
  });
  if (!answer) return;
  await invoke("exit_app");
}

async function reconnect() {
  const answer = await confirmAction({
    title: t("confirm_reconnect_title"),
    body: t("confirm_reconnect_body"),
  });
  if (!answer) return;

  const res = await invoke("reconnect");
  if (res && res.ok) {
    setError(null);
  } else if (res) {
    setError(res.message);
  }
  await refresh();
}

/* ------------------------------------------------------------------ wiring */

window.addEventListener("DOMContentLoaded", async () => {
  el("refresh").addEventListener("click", refresh);
  el("reconnect").addEventListener("click", reconnect);
  el("exit-app").addEventListener("click", exitApp);
  // Hiding is the window manager's job; closing the window already hides it, so this just makes
  // the behaviour discoverable.
  el("hide").addEventListener("click", () => window.close());

  // The runtime pushes on a timer from the Rust side; the panel only re-renders. There is no
  // polling timer here, so a hidden panel costs nothing.
  await listen("guardian://panel", (event) => {
    const payload = event.payload;
    if (payload && payload.ok) {
      setError(null);
      renderPanel(payload);
    }
  });

  await refresh();
});

window.addEventListener("beforeunload", () => {
  current = null;
});
