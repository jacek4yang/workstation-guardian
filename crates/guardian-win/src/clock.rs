//! Time sources.
//!
//! Two clocks are exposed for a reason. `now_ms` is wall-clock and can jump backwards when
//! NTP corrects a machine that has been asleep. `monotonic_ms` is derived from
//! `QueryUnbiasedInterruptTime`, which does not jump. All elapsed-time decisions
//! (backoff, stabilization, uptime, token expiry measured locally) use the monotonic clock;
//! only audit timestamps shown to a human use wall-clock.

use std::time::Duration;

use windows::Win32::System::SystemInformation::{GetSystemTimeAsFileTime, GetTickCount64};
use windows::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;

use crate::WinError;

/// Wall-clock milliseconds since the Unix epoch.
pub fn unix_now_ms() -> i64 {
    // Safety: GetSystemTimeAsFileTime takes no arguments, cannot fail, and returns the
    // current system time directly.
    let ft = unsafe { GetSystemTimeAsFileTime() };
    filetime_to_unix_ms(filetime_to_u64(ft))
}

/// Milliseconds since the machine booted.
///
/// Uses `GetTickCount64`, which is stated to be unaffected by adjustments to the system
/// clock. It wraps after ~584 million years, so overflow is not a practical concern.
pub fn uptime_ms() -> i64 {
    // Safety: GetTickCount64 takes no arguments and cannot fail.
    unsafe { GetTickCount64() as i64 }
}

/// A monotonic millisecond counter with no relation to wall-clock time.
///
/// Derived from `QueryUnbiasedInterruptTime`, which excludes time the system spent in
/// sleep/hibernation. That makes it the right basis for "has this link been stable for
/// 20 seconds" — if the machine was suspended, the link was not stable during that period
/// in any meaningful sense.
pub fn monotonic_ms() -> i64 {
    // Safety: QueryUnbiasedInterruptTime writes a 100-nanosecond count to the out-parameter.
    unsafe {
        let mut value: u64 = 0;
        // The BOOL return indicates success; a failure leaves `value` at 0, which is a
        // valid monotonic reading at boot, so there is nothing useful to do with it.
        let _ = QueryUnbiasedInterruptTime(&mut value);
        // 100ns units to milliseconds.
        (value / 10_000) as i64
    }
}

/// Convert a `FILETIME` (100 ns ticks since 1601) to Unix milliseconds.
pub fn filetime_to_unix_ms(filetime: u64) -> i64 {
    /// 100 ns ticks between 1601-01-01 and 1970-01-01.
    const EPOCH_DIFFERENCE_100NS: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DIFFERENCE_100NS {
        // A time before the Unix epoch. Clamp rather than produce a huge negative number;
        // such a value can only come from a corrupted record.
        return 0;
    }
    ((filetime - EPOCH_DIFFERENCE_100NS) / 10_000) as i64
}

/// Pack a `FILETIME` into a `u64`.
pub fn filetime_to_u64(ft: windows::Win32::Foundation::FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// Convert a `Duration` to milliseconds, saturating rather than wrapping.
pub fn duration_to_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A [`guardian_core::Clock`] backed by the real system.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl guardian_core::ports::Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        unix_now_ms()
    }
    fn monotonic_ms(&self) -> i64 {
        monotonic_ms()
    }
    fn uptime_ms(&self) -> i64 {
        uptime_ms()
    }
}

/// Identity of the current boot.
///
/// Derived from the system boot time, which changes on every start. This is what binds a
/// single-use reboot authorization to exactly one boot: after a restart the id differs, so
/// a capability issued for the previous boot can never match.
#[derive(Debug, Clone)]
pub struct SystemBootIdentity;

impl SystemBootIdentity {
    /// Compute the current boot id.
    ///
    /// `boot_ms = now - uptime`. Both inputs are inexpensive and neither requires
    /// elevation. The result is rounded to the nearest second because the two clocks are
    /// sampled at slightly different instants, and a boot id that changed between two calls
    /// in the same session would be a bug.
    pub fn read() -> String {
        let now = unix_now_ms();
        let up = uptime_ms();
        let boot_ms = now.saturating_sub(up);
        let rounded = boot_ms.div_euclid(1000) * 1000;
        format!("boot-{rounded}")
    }
}

impl guardian_core::ports::BootIdentity for SystemBootIdentity {
    fn boot_id(&self) -> String {
        Self::read()
    }
}

/// Check that the monotonic clock is actually monotonic.
///
/// Called once at service start. If this fails the machine's time facilities are so broken
/// that every timing decision Guardian makes would be unreliable, which the caller must
/// surface rather than silently tolerate.
pub fn verify_clock_sanity() -> Result<(), WinError> {
    let a = monotonic_ms();
    let b = monotonic_ms();
    if b < a {
        return Err(WinError::Invalid {
            context: "clock sanity",
            detail: format!("monotonic clock went backwards: {a} -> {b}"),
        });
    }
    let wall = unix_now_ms();
    if wall <= 0 {
        return Err(WinError::Invalid {
            context: "clock sanity",
            detail: "system clock reports a time before the Unix epoch".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::ports::{BootIdentity, Clock};

    #[test]
    fn filetime_epoch_conversion_is_correct() {
        // Exactly the Unix epoch.
        assert_eq!(filetime_to_unix_ms(116_444_736_000_000_000), 0);
        // One second later.
        assert_eq!(
            filetime_to_unix_ms(116_444_736_000_000_000 + 10_000_000),
            1000
        );
        // A known value: 2026-01-01T00:00:00Z is 1767225600.
        let ft = 116_444_736_000_000_000u64 + 1_767_225_600 * 10_000_000;
        assert_eq!(filetime_to_unix_ms(ft), 1_767_225_600_000);
    }

    #[test]
    fn filetime_before_the_epoch_clamps_instead_of_wrapping() {
        // A corrupt or zeroed FILETIME must not produce a wild negative timestamp.
        assert_eq!(filetime_to_unix_ms(0), 0);
        assert_eq!(filetime_to_unix_ms(1), 0);
    }

    #[test]
    fn wall_clock_is_plausible() {
        // Well after 2020 and well before 2200.
        let now = unix_now_ms();
        assert!(now > 1_577_836_800_000, "wall clock looks wrong: {now}");
        assert!(now < 7_258_118_400_000, "wall clock looks wrong: {now}");
    }

    #[test]
    fn uptime_is_positive_and_plausible() {
        let up = uptime_ms();
        assert!(up > 0, "a running machine has a positive uptime");
        // Less than 10 years of uninterrupted uptime; anything more means the call failed.
        assert!(up < 10 * 365 * 24 * 3600 * 1000);
    }

    #[test]
    fn monotonic_clock_never_goes_backwards() {
        let a = monotonic_ms();
        std::thread::sleep(Duration::from_millis(2));
        let b = monotonic_ms();
        assert!(b >= a, "monotonic clock went backwards: {a} -> {b}");
    }

    #[test]
    fn clock_sanity_check_passes_on_a_healthy_machine() {
        assert!(verify_clock_sanity().is_ok());
    }

    #[test]
    fn boot_id_is_stable_within_a_session() {
        // The rounded computation exists so two calls in the same session agree; a boot id
        // that flickered would invalidate a live reboot authorization for no reason.
        let a = SystemBootIdentity::read();
        std::thread::sleep(Duration::from_millis(5));
        let b = SystemBootIdentity::read();
        assert_eq!(a, b, "boot id must not change within a session");
    }

    #[test]
    fn boot_id_lands_in_the_past_and_is_formatted_predictably() {
        let id = SystemBootIdentity::read();
        assert!(id.starts_with("boot-"), "unexpected format: {id}");
        let ms: i64 = id
            .trim_start_matches("boot-")
            .parse()
            .expect("numeric suffix");
        let now = unix_now_ms();
        assert!(ms <= now, "boot time cannot be in the future");
        assert!(
            now - ms < 10 * 365 * 24 * 3600 * 1000,
            "boot time is implausibly far in the past"
        );
        assert_eq!(ms % 1000, 0, "boot id is rounded to the second");
    }

    #[test]
    fn boot_identity_trait_matches_the_inherent_call() {
        let b = SystemBootIdentity;
        assert_eq!(b.boot_id(), SystemBootIdentity::read());
    }

    #[test]
    fn system_clock_implements_the_port_consistently() {
        let c = SystemClock;
        let wall = c.now_ms();
        let mono = c.monotonic_ms();
        let up = c.uptime_ms();
        assert!(wall > 0);
        assert!(mono > 0);
        assert!(up > 0);
        // Uptime cannot exceed wall-clock time since the epoch.
        assert!(up < wall);
    }

    #[test]
    fn duration_conversion_saturates_rather_than_wrapping() {
        assert_eq!(duration_to_ms(Duration::from_millis(1500)), 1500);
        assert_eq!(duration_to_ms(Duration::from_secs(0)), 0);
        assert_eq!(duration_to_ms(Duration::from_secs(u64::MAX / 2)), u64::MAX);
    }

    #[test]
    fn filetime_packing_combines_both_halves() {
        use windows::Win32::Foundation::FILETIME;
        let ft = FILETIME {
            dwLowDateTime: 0xAAAA_AAAA,
            dwHighDateTime: 0xBBBB_BBBB,
        };
        assert_eq!(filetime_to_u64(ft), 0xBBBB_BBBB_AAAA_AAAA);
    }
}
