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
      "Not running as administrator, so the Windows Update policy cannot be applied. Updates are not currently held back.",
    restart_elevated: "Restart as administrator",
    restarting_elevated: "Restarting with administrator rights…",
    elevation_declined:
      "Administrator rights were not granted. Guardian is still running and protecting what it can.",
    elevation_failed: "Could not restart as administrator.",
    settings: "Settings",
    start_at_logon: "Start Guardian at logon",
    start_at_logon_note:
      "Adds Guardian to your own startup (HKCU). It also starts the session helper, which is what lets Guardian hold a shutdown while work is running. Nothing machine-wide is changed, and turning this off removes both entries.",
    start_at_logon_unavailable:
      "guardian-session.exe was not found beside Guardian, so startup cannot be registered. Keep both files in the same folder.",
    autostart_failed: "Could not change the startup setting.",
    autostart_on: "Guardian will now start at logon, along with the session helper.",
    autostart_off: "Guardian will no longer start at logon. Both startup entries were removed.",
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
      "未以管理员身份运行，因此无法应用 Windows Update 策略。目前更新未被抑制。",
    restart_elevated: "以管理员身份重新启动",
    restarting_elevated: "正在以管理员权限重启…",
    elevation_declined: "未获得管理员权限。Guardian 仍在运行，并保护其能够保护的部分。",
    elevation_failed: "无法以管理员身份重启。",
    settings: "设置",
    start_at_logon: "登录时启动 Guardian",
    start_at_logon_note:
      "将 Guardian 加入你的启动项（HKCU）。同时会启动会话助手，它让 Guardian 在有任务运行时能够阻止关机。不会修改任何全局设置，关闭此项会移除这两项。",
    start_at_logon_unavailable:
      "在 Guardian 旁边未找到 guardian-session.exe，无法注册启动项。请将两个文件放在同一目录。",
    autostart_failed: "无法修改启动设置。",
    autostart_on: "Guardian 将在登录时启动，会话助手也会一并启动。",
    autostart_off: "Guardian 将不再随登录启动。两项启动项均已移除。",
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
  //
  // The relayed flag is cross-checked against what the runtime actually achieved. Update
  // protection reading "Protected" is proof that the policy was written, which is only possible
  // with administrator rights. If the two disagree, the runtime's own report wins: offering a
  // UAC prompt to a process that is already elevated is a pointless interruption, and showing it
  // beside a green "Protected" row is a contradiction the operator is right not to trust.
  const protectionProvesElevation =
    panel.update && String(panel.update.level).toLowerCase() === "protected";
  const elevated = Boolean(payload.elevated) || protectionProvesElevation;

  const warnings = [];
  if (!elevated) warnings.push(t("not_elevated"));
  if (panel.unclean_previous_exit) warnings.push(t("recovered"));
  const warning = el("warning");
  if (warnings.length) {
    el("warning-text").textContent = warnings.join(" ");
    warning.hidden = false;
  } else {
    warning.hidden = true;
  }

  // The restart button is offered only when it would actually change something.
  show(el("restart-elevated"), !elevated);

  setLevel("update-level", panel.update.level, panel.update.label);
  setLevel("restart-level", panel.restart_protection.level, panel.restart_protection.label);
  el("mode").textContent = panel.mode.label;
  el("uptime").textContent = formatDuration(panel.uptime_ms);
  el("pending").textContent = panel.pending_reboot.label;

  const degraded = panel.degraded_components || [];
  show(el("degraded-row"), degraded.length > 0);
  if (degraded.length) el("degraded").textContent = degraded.join(", ");

  renderAutostart();
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

/*
 * A one-off message about something the user just did, as opposed to a condition the runtime is
 * reporting. It has its own element so that a periodic panel refresh, which owns the protection
 * warnings, cannot leave a stale notice on screen or wipe a real warning away.
 */
function setNotice(message) {
  const banner = el("notice");
  if (!banner) return;
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
    setNotice(null);
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

/*
 * The logon-startup toggle.
 *
 * Read from the registry rather than from the panel document, because it describes the machine's
 * configuration rather than the runtime's state. It is refreshed on each panel update so a change
 * made in Task Manager shows up here too.
 */
async function renderAutostart() {
  const box = el("start-at-logon");
  if (!box) return;
  try {
    const res = await invoke("get_autostart");
    if (res && res.ok) {
      box.checked = Boolean(res.enabled);
      // Offering the toggle when the helper binary is missing would register an entry that fails
      // silently at every logon, so it is disabled and explained instead.
      box.disabled = !res.helper_available;
      show(el("autostart-unavailable"), !res.helper_available);
    }
  } catch (e) {
    box.disabled = true;
  }
}

async function toggleAutostart() {
  const box = el("start-at-logon");
  const wanted = box.checked;
  box.disabled = true;

  let res = null;
  try {
    res = await invoke("set_autostart", { enabled: wanted });
  } catch (e) {
    res = { ok: false, error: String(e) };
  }

  if (res && res.ok) {
    box.checked = Boolean(res.enabled);
    box.disabled = !res.helper_available;
    setNotice(res.enabled ? t("autostart_on") : t("autostart_off"));
  } else {
    // Put the checkbox back where it was: it must reflect the registry, not the click.
    box.checked = !wanted;
    box.disabled = false;
    setError(res && res.error ? res.error : t("autostart_failed"));
  }
}

/*
 * Ask Windows for administrator rights and restart there.
 *
 * The main process starts the elevated copy before this one exits, so declining the prompt leaves
 * the user exactly where they were: still protected, still informed. That ordering is why a
 * declined prompt is reported as a message rather than an error.
 */
async function restartElevated() {
  const button = el("restart-elevated");
  button.disabled = true;

  let res = null;
  try {
    res = await invoke("restart_elevated");
  } catch (e) {
    res = { ok: false, error: String(e) };
  }

  // On success the process exits within a moment and this page goes with it. Anything written to
  // the banner now would be discarded anyway, and writing it risks leaving the text behind if the
  // exit is slower than the next refresh.
  if (res && res.ok) return;

  // The process is still alive, so nothing changed: the user declined, or it failed. Re-enable the
  // button and let the next refresh redraw the *true* state from the runtime, rather than leaving
  // a message that describes an attempt instead of a condition.
  button.disabled = false;

  if (res && res.declined) {
    setError(null);
    // A declined prompt is a choice, not a fault. Say what it means for protection and stop.
    setNotice(t("elevation_declined"));
    await refresh();
    return;
  }

  const detail = res && res.error ? ` ${res.error}` : "";
  setError(`${t("elevation_failed")}${detail}`);
}

/* ------------------------------------------------------------------ wiring */

window.addEventListener("DOMContentLoaded", async () => {
  // Start from a known state. The markup ships with the elevation banner hidden, and this makes
  // that explicit rather than relying on the `hidden` attribute surviving every code path: an
  // elevated session must never show the banner, not even for the moment before the first panel
  // document arrives.
  show(el("warning"), false);
  show(el("restart-elevated"), false);

  el("refresh").addEventListener("click", refresh);
  el("reconnect").addEventListener("click", reconnect);
  el("exit-app").addEventListener("click", exitApp);
  el("restart-elevated").addEventListener("click", restartElevated);
  el("start-at-logon").addEventListener("change", toggleAutostart);
  // Hiding is the window manager's job; closing the window already hides it, so this just makes
  // the behaviour discoverable.
  el("hide").addEventListener("click", () => window.close());

  // The runtime pushes on a timer from the Rust side; the panel only re-renders. There is no
  // polling timer here, so a hidden panel costs nothing.
  await listen("guardian://panel", (event) => {
    const payload = event.payload;
    if (payload && payload.ok) {
      setError(null);
      // Anything the user was told about an earlier action is superseded by this fresh reading.
      setNotice(null);
      renderPanel(payload);
    }
  });

  await refresh();
});

window.addEventListener("beforeunload", () => {
  current = null;
});
