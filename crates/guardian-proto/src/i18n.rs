//! Bilingual user-facing text.
//!
//! # Why this lives in the protocol crate
//!
//! Three separate processes render text to a person: `guardianctl`, the tray UI, and — through
//! the status snapshot — the service. If each carried its own copy of a string, they would drift,
//! and an operator reading the CLI and then the panel would see two different explanations for the
//! same state. One table, one wording.
//!
//! # How it works
//!
//! Every user-facing string is a [`Text`]: the same sentence in both languages, chosen at render
//! time by a [`Lang`]. Nothing branches on language in the logic; only the final formatting step
//! does.
//!
//! # Why both languages are embedded rather than loaded
//!
//! The strings are part of what the tool *means* — "Protected" is a claim about the machine, not
//! decoration. Shipping them in the binary means a missing or corrupt locale file cannot turn a
//! warning into a blank line.

use serde::{Deserialize, Serialize};

/// The language a message is rendered in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Lang {
    /// English.
    En,
    /// Simplified Chinese.
    ZhCn,
    /// Follow the operating system, falling back to English.
    #[default]
    Auto,
}

impl Lang {
    /// Resolve `Auto` against the system locale.
    pub fn resolve(self) -> Lang {
        match self {
            Lang::Auto => {
                if system_prefers_chinese() {
                    Lang::ZhCn
                } else {
                    Lang::En
                }
            }
            other => other,
        }
    }

    /// Parse a configuration value.
    ///
    /// Accepts the spellings a user is likely to type, and falls back to `Auto` rather than
    /// failing: a typo in a language setting must not stop the service from starting.
    pub fn parse(s: &str) -> Lang {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "en" | "en-us" | "en-gb" | "english" => Lang::En,
            "zh" | "zh-cn" | "zh-hans" | "cn" | "chinese" | "simplified-chinese" => Lang::ZhCn,
            _ => Lang::Auto,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Lang::Auto => "auto",
            Lang::En => "en",
            Lang::ZhCn => "zh-CN",
        }
    }

    /// All selectable values, for the settings UI.
    pub fn choices() -> [Lang; 3] {
        [Lang::Auto, Lang::En, Lang::ZhCn]
    }
}

/// Whether the system UI language is Chinese.
///
/// Reads `GetUserDefaultUILanguage`. Falls back to English when it cannot be determined, which is
/// the safer default for a diagnostic tool whose output is often pasted into a bug report.
#[cfg(target_os = "windows")]
fn system_prefers_chinese() -> bool {
    // The primary language id is in the low 10 bits. Chinese primary language ids are 0x04
    // (zh, including all sub-languages such as zh-CN 0x0804 and zh-TW 0x0404).
    const LANG_CHINESE: u16 = 0x04;
    let lang_id = unsafe { windows_sys_lang_id() };
    (lang_id & 0x3FF) as u16 == LANG_CHINESE
}

#[cfg(target_os = "windows")]
unsafe fn windows_sys_lang_id() -> u32 {
    // `GetUserDefaultUILanguage` is a kernel32 export with no preconditions and cannot fail.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    unsafe { GetUserDefaultUILanguage() as u32 }
}

#[cfg(not(target_os = "windows"))]
fn system_prefers_chinese() -> bool {
    false
}

/// A sentence in both languages.
///
/// Construct with [`Text::new`]; render with [`Text::get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Text {
    en: &'static str,
    zh: &'static str,
}

impl Text {
    pub const fn new(en: &'static str, zh: &'static str) -> Self {
        Text { en, zh }
    }

    /// Render in the given language.
    pub fn get(&self, lang: Lang) -> &'static str {
        match lang.resolve() {
            Lang::ZhCn => self.zh,
            _ => self.en,
        }
    }

    pub fn en(&self) -> &'static str {
        self.en
    }

    pub fn zh(&self) -> &'static str {
        self.zh
    }
}

/// Messages the whole product shares.
///
/// Kept as a module of constants rather than a lookup table so a typo is a compile error and an
/// unused string is visible.
pub mod msg {
    use super::Text;

    // ---- protection levels ----
    pub const PROTECTED: Text = Text::new("Protected", "已保护");
    pub const DEGRADED: Text = Text::new("Degraded", "保护降级");
    pub const MAINTENANCE: Text = Text::new("Maintenance", "维护模式");
    pub const UNKNOWN: Text = Text::new("Unknown", "未知");
    pub const UNPROTECTED: Text = Text::new("NOT PROTECTED", "未受保护");

    // ---- modes ----
    pub const MODE_NORMAL: Text = Text::new("NORMAL", "正常");
    pub const MODE_WORKING: Text = Text::new("WORKING", "工作保护中");
    pub const MODE_MAINTENANCE: Text = Text::new("MAINTENANCE", "维护模式");

    // ---- confidence ----
    pub const CONFIDENCE_CONFIRMED: Text = Text::new("Confirmed", "已确认");
    pub const CONFIDENCE_HIGH: Text = Text::new("High", "高置信");
    pub const CONFIDENCE_POSSIBLE: Text = Text::new("Possible", "可能");
    pub const CONFIDENCE_UNKNOWN: Text = Text::new("Unknown", "未知");

    // ---- network ----
    pub const HEALTHY: Text = Text::new("Healthy", "正常");
    pub const DOWN: Text = Text::new("Down", "中断");

    // ---- labels used by both the CLI and the panel ----
    pub const UPDATE_PROTECTION: Text = Text::new("Update Protection", "更新保护");
    pub const RESTART_PROTECTION: Text = Text::new("Restart Protection", "重启保护");
    pub const SERVICE: Text = Text::new("Guardian", "Guardian");
    pub const MODE: Text = Text::new("Mode", "模式");
    pub const UPTIME: Text = Text::new("Uptime", "运行时长");
    pub const RUNNING: Text = Text::new("Running", "运行中");
    pub const STOPPED: Text = Text::new("Stopped", "已停止");
    pub const DEGRADED_COMPONENTS: Text = Text::new("Degraded", "降级组件");

    pub const NETWORK: Text = Text::new("Network", "网络");
    pub const INTERNET: Text = Text::new("Internet", "互联网");
    pub const PPPOE: Text = Text::new("PPPoE", "PPPoE 宽带");
    pub const RAS_STATE: Text = Text::new("RAS state", "RAS 状态");
    pub const CONNECTION_UPTIME: Text = Text::new("Connection uptime", "连接时长");
    pub const LAST_RECONNECT: Text = Text::new("Last reconnect", "上次重连");
    pub const OUTAGE: Text = Text::new("Outage", "故障");
    pub const NOT_CONFIGURED: Text = Text::new("(not configured)", "（未配置）");

    pub const ACTIVE_WORK: Text = Text::new("Active Work", "进行中的工作");
    pub const NOTHING_DETECTED: Text = Text::new("Nothing detected.", "未检测到。");
    pub const BUILD: Text = Text::new("Build", "构建");
    pub const PROJECT: Text = Text::new("Project", "项目");
    pub const AGENT: Text = Text::new("Agent", "Agent");
    pub const PID: Text = Text::new("PID", "进程号");
    pub const RESUME: Text = Text::new("Resumable", "可恢复");

    pub const PENDING_REBOOT: Text = Text::new("Pending reboot", "待重启");
    pub const NOT_PENDING: Text = Text::new("NotPending", "无需重启");
    pub const PROBABLY_PENDING: Text = Text::new("ProbablyPending", "可能待重启");
    pub const PENDING: Text = Text::new("Pending", "待重启");

    pub const INCIDENTS: Text = Text::new("Incidents", "事件记录");
    pub const NO_INCIDENTS: Text = Text::new("No incidents recorded.", "暂无事件记录。");

    // ---- maintenance ----
    pub const ENTER_MAINTENANCE: Text = Text::new("Enter Maintenance Mode…", "进入维护模式…");
    pub const EXIT_MAINTENANCE: Text = Text::new(
        "Exit Maintenance and Lock Updates",
        "退出维护并重新锁定更新",
    );
    // ---- panel-only labels ----
    //
    // These are shared between the tray and the control panel, so they belong here rather than in
    // the frontend: the panel and the CLI must never disagree about what a state is called.
    pub const ACTIVE_AGENTS: Text = Text::new("Active agents", "活动 Agent");
    pub const ALLOW_ONE_REBOOT: Text = Text::new("Allow One Reboot", "允许一次重启");
    pub const REVOKE_REBOOT: Text = Text::new("Revoke Reboot Authorization", "撤销重启授权");
    pub const REBOOT_NONE: Text = Text::new("none", "无");

    // ---- shared warnings ----
    pub const PROTECTED_WORK_RUNNING: Text =
        Text::new("Protected work is running:", "有受保护的工作正在运行：");
    pub const UPDATES_UNLOCKED: Text = Text::new(
        "Updates are unlocked. Windows Update may install while you are in this mode.",
        "更新已解锁。在此模式下 Windows Update 可能进行安装。",
    );
    pub const EXIT_UI_SAFE: Text = Text::new(
        "Exiting the UI does not stop protection. The service keeps running.",
        "关闭界面不会停止保护。服务仍在运行。",
    );

    // ---- control panel ----
    //
    // The panel is the one place an operator looks when something is wrong, so every line it can
    // show has to exist in both languages. These are shared with the tray rather than living in the
    // frontend, so the tray, the panel and the CLI cannot drift apart.
    pub const STARTING: Text = Text::new(
        "Starting — protection is being applied",
        "正在启动 — 正在应用保护",
    );
    pub const RECONNECT_REQUESTED: Text = Text::new(
        "Reconnect requested; the network guardian will act on its next check.",
        "已请求重连；网络守护将在下次检查时执行。",
    );
    pub const NOT_ELEVATED: Text = Text::new(
        "Not running as administrator: the Windows Update policy cannot be applied.",
        "未以管理员身份运行：无法应用 Windows Update 策略。",
    );
    pub const RECOVERY_AFTER_CRASH: Text = Text::new(
        "The previous session ended unexpectedly. State was recovered; no work was discarded.",
        "上一次会话非正常结束。状态已恢复；未丢弃任何工作。",
    );
    pub const PENDING_REBOOT_ALREADY: Text =
        Text::new("A restart is already pending.", "系统已存在待处理的重启。");
    pub const PENDING_REBOOT_PROBABLY: Text = Text::new(
        "A restart is probably pending.",
        "系统可能存在待处理的重启。",
    );
    pub const PENDING_REBOOT_NONE: Text = Text::new("No restart is pending.", "没有待处理的重启。");
    pub const PENDING_REBOOT_UNKNOWN: Text = Text::new(
        "The pending-restart state could not be determined.",
        "无法确定待重启状态。",
    );
    pub const MODE_ENTER: Text = Text::new("Enter maintenance", "进入维护模式");
    pub const MODE_EXIT: Text = Text::new("Exit maintenance", "退出维护模式");
    // ---- logon startup ----
    pub const START_AT_LOGON: Text = Text::new("Start Guardian at logon", "登录时启动 Guardian");
    pub const START_AT_LOGON_NOTE: Text = Text::new(
        "Adds Guardian to your own startup (HKCU). It also starts the session helper, which is          what lets Guardian hold a shutdown while work is running. Nothing machine-wide is          changed, and turning this off removes both entries.",
        "将 Guardian 加入你的启动项（HKCU）。同时会启动会话助手，它让 Guardian 在有任务运行时能够阻止关机。不会修改任何全局设置，关闭此项会移除这两项。",
    );
    pub const START_AT_LOGON_UNAVAILABLE: Text = Text::new(
        "guardian-session.exe was not found beside Guardian, so startup cannot be registered.          Keep both files in the same folder.",
        "在 Guardian 旁边未找到 guardian-session.exe，无法注册启动项。请将两个文件放在同一目录。",
    );
    pub const AUTOSTART_FAILED: Text =
        Text::new("Could not change the startup setting", "无法修改启动设置");

    // ---- elevation ----
    pub const RESTART_ELEVATED: Text =
        Text::new("Restart as administrator", "以管理员身份重新启动");
    pub const ALREADY_ELEVATED: Text =
        Text::new("Already running as administrator.", "已以管理员身份运行。");
    pub const ELEVATION_DECLINED: Text = Text::new(
        "Administrator rights were not granted, so the Windows Update policy could not be          applied. Guardian is still running and protecting what it can.",
        "未获得管理员权限，因此无法应用 Windows Update 策略。Guardian 仍在运行，并保护其能够保护的部分。",
    );
    pub const ELEVATION_FAILED: Text =
        Text::new("Could not restart as administrator", "无法以管理员身份重启");
    pub const RESTARTING_ELEVATED: Text = Text::new(
        "Restarting with administrator rights…",
        "正在以管理员权限重启…",
    );
    pub const REMINDER_ONLY: Text = Text::new(
        "Workstation Guardian reduces the risk of an unexpected restart. It cannot make Windows \
         unable to reboot.",
        "Workstation Guardian 可降低意外重启的风险，但无法让 Windows 完全无法重启。",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_has_both_languages_and_neither_is_empty() {
        // The whole point of embedding both is that a rendered message is never blank. A missing
        // translation would otherwise turn a warning into an empty line.
        let all = [
            msg::PROTECTED,
            msg::DEGRADED,
            msg::MAINTENANCE,
            msg::UNKNOWN,
            msg::UNPROTECTED,
            msg::MODE_NORMAL,
            msg::MODE_WORKING,
            msg::MODE_MAINTENANCE,
            msg::CONFIDENCE_CONFIRMED,
            msg::CONFIDENCE_HIGH,
            msg::CONFIDENCE_POSSIBLE,
            msg::CONFIDENCE_UNKNOWN,
            msg::HEALTHY,
            msg::DOWN,
            msg::UPDATE_PROTECTION,
            msg::RESTART_PROTECTION,
            msg::SERVICE,
            msg::MODE,
            msg::UPTIME,
            msg::RUNNING,
            msg::STOPPED,
            msg::DEGRADED_COMPONENTS,
            msg::NETWORK,
            msg::INTERNET,
            msg::PPPOE,
            msg::RAS_STATE,
            msg::CONNECTION_UPTIME,
            msg::LAST_RECONNECT,
            msg::OUTAGE,
            msg::NOT_CONFIGURED,
            msg::ACTIVE_WORK,
            msg::NOTHING_DETECTED,
            msg::BUILD,
            msg::PROJECT,
            msg::AGENT,
            msg::PID,
            msg::RESUME,
            msg::PENDING_REBOOT,
            msg::NOT_PENDING,
            msg::PROBABLY_PENDING,
            msg::PENDING,
            msg::INCIDENTS,
            msg::NO_INCIDENTS,
            msg::ENTER_MAINTENANCE,
            msg::EXIT_MAINTENANCE,
            msg::ALLOW_ONE_REBOOT,
            msg::REVOKE_REBOOT,
            msg::REBOOT_NONE,
            msg::PROTECTED_WORK_RUNNING,
            msg::UPDATES_UNLOCKED,
            msg::EXIT_UI_SAFE,
        ];

        for t in all {
            assert!(!t.en().trim().is_empty(), "missing English text in {t:?}");
            assert!(!t.zh().trim().is_empty(), "missing Chinese text in {t:?}");
        }
    }

    #[test]
    fn rendering_selects_the_requested_language() {
        assert_eq!(msg::PROTECTED.get(Lang::En), "Protected");
        assert_eq!(msg::PROTECTED.get(Lang::ZhCn), "已保护");
    }

    #[test]
    fn auto_resolves_to_a_concrete_language() {
        // Whatever the machine is set to, `Auto` must not stay abstract at render time.
        assert_ne!(Lang::Auto.resolve(), Lang::Auto);
    }

    #[test]
    fn parsing_accepts_the_spellings_a_user_would_type() {
        for s in ["en", "EN", "en-US", "english"] {
            assert_eq!(Lang::parse(s), Lang::En, "{s}");
        }
        for s in ["zh", "zh-CN", "zh_cn", "cn", "chinese", "Chinese"] {
            assert_eq!(Lang::parse(s), Lang::ZhCn, "{s}");
        }
        // An unrecognised value must not fail; it follows the system.
        for s in ["", "klingon", "xx"] {
            assert_eq!(Lang::parse(s), Lang::Auto, "{s}");
        }
    }

    #[test]
    fn language_round_trips_through_its_string_form() {
        for lang in Lang::choices() {
            assert_eq!(Lang::parse(lang.as_str()), lang, "{lang:?}");
        }
    }

    #[test]
    fn protection_claims_are_translated_not_passed_through() {
        // "Protected" is a claim about the machine. If a translation were ever left as the English
        // word, the Chinese UI would mix languages at exactly the point where precision matters.
        assert_ne!(msg::PROTECTED.zh(), msg::PROTECTED.en());
        assert_ne!(msg::UNPROTECTED.zh(), msg::UNPROTECTED.en());
        assert_ne!(msg::DEGRADED.zh(), msg::DEGRADED.en());
    }
}
