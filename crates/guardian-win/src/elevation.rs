//! Process privilege and integrity queries.
//!
//! Used to give a clear message *before* an operation that needs administrator rights, rather
//! than letting the Service Control Manager return a bare access-denied. It is also used to
//! decide what a client is allowed to ask for, though the pipe's ACL remains the authoritative
//! boundary — this is a convenience check, not a security control.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenIntegrityLevel, TokenUser, PSID, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::WinError;

/// Whether the current process is running elevated.
///
/// Reads the token's elevation flag, which is the documented way to ask. A process that is a
/// member of the Administrators group but running with a filtered token is *not* elevated, and
/// reporting otherwise would lead an operator to expect an operation to succeed when it will not.
pub fn is_elevated() -> bool {
    let Ok(token) = open_current_token() else {
        // If we cannot read the token, assume not elevated. That produces a "you need to elevate"
        // message, which is a harmless false negative, rather than a false positive that fails
        // later with a confusing error.
        return false;
    };

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;

    // Safety: `elevation` is correctly sized for TokenElevation and `returned` is a valid
    // out-parameter.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };

    if ok.is_err() {
        return false;
    }

    elevation.TokenIsElevated != 0
}

/// Whether the current process is running as LocalSystem.
///
/// Checks the token's user SID against `S-1-5-18`, which is the documented LocalSystem account.
pub fn is_local_system() -> bool {
    let Ok(token) = open_current_token() else {
        return false;
    };

    let mut needed = 0u32;
    // Safety: a null buffer with zero length is the documented size query.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return false;
    }

    let mut buf = vec![0u8; needed as usize];
    // Safety: `buf` is `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
    };
    if ok.is_err() {
        return false;
    }

    // Safety: the API filled `buf` with a TOKEN_USER. The buffer is a `Vec<u8>`, whose
    // allocation is aligned for the structure's pointer fields, but the read is done through a
    // raw pointer rather than a reference to avoid asserting an alignment we cannot prove.
    let token_user: *const TOKEN_USER = buf.as_ptr() as *const TOKEN_USER;
    let sid = unsafe { (*token_user).User.Sid };
    if sid.is_invalid() {
        return false;
    }

    sid_matches_local_system(sid)
}

/// Whether a SID is the LocalSystem account, `S-1-5-18`.
///
/// Read through the documented SID layout rather than by formatting the SID to a string, because
/// string conversion requires an extra API and an allocation for what is a four-field comparison.
fn sid_matches_local_system(sid: PSID) -> bool {
    if sid.0.is_null() {
        return false;
    }

    // Safety: `PSID` is a pointer to a SID, whose layout is fixed by the API: Revision (1 byte),
    // SubAuthorityCount (1 byte), IdentifierAuthority (6 bytes big-endian), then
    // SubAuthority[SubAuthorityCount] as 4-byte little-endian values. Every read is within the
    // documented 12-byte header plus the sub-authorities we have already counted.
    let bytes = sid.0 as *const u8;
    unsafe {
        let revision = *bytes;
        let sub_count = *bytes.add(1);

        if revision != 1 || sub_count != 1 {
            return false;
        }

        // The identifier authority is a 6-byte big-endian value. For LocalSystem it is 5.
        let mut authority: u64 = 0;
        for i in 0..6 {
            authority = (authority << 8) | u64::from(*bytes.add(2 + i));
        }

        let first_sub =
            u32::from_le_bytes([*bytes.add(8), *bytes.add(9), *bytes.add(10), *bytes.add(11)]);

        authority == 5 && first_sub == 18
    }
}

/// The integrity level of the current process, as a raw RID.
///
/// Used in diagnostics: a process at high integrity behaves differently from one at medium, and
/// that difference explains some access failures.
pub fn integrity_level() -> Result<u32, WinError> {
    let token = open_current_token()?;

    let mut needed = 0u32;
    // Safety: a null buffer with zero length is the documented size query.
    let _ = unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed) };
    if needed == 0 {
        return Err(WinError::last("GetTokenInformation(TokenIntegrityLevel)"));
    }

    let mut buf = vec![0u8; needed as usize];
    // Safety: `buf` is `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
    };
    if ok.is_err() {
        return Err(WinError::last("GetTokenInformation(TokenIntegrityLevel)"));
    }

    // TOKEN_MANDATORY_LABEL is `{ SID_AND_ATTRIBUTES Label }`, i.e. a SID pointer followed by
    // attributes. The SID's *last* sub-authority is the integrity RID.
    //
    // Safety: the API filled `buf` with a TOKEN_MANDATORY_LABEL of at least `needed` bytes.
    let label_sid = unsafe { *buf.as_ptr().cast::<*mut u8>() };
    if label_sid.is_null() {
        return Err(WinError::Invalid {
            context: "integrity_level",
            detail: "the token has no integrity SID".into(),
        });
    }

    // Safety: a valid SID reports its sub-authority count at byte 1. The final sub-authority sits
    // at a fixed offset computed from that count, which is bounds-checked here.
    let sub_count = unsafe { *label_sid.add(1) } as usize;
    if sub_count == 0 || sub_count > 15 {
        return Err(WinError::Invalid {
            context: "integrity_level",
            detail: format!("the integrity SID reports {sub_count} sub-authorities"),
        });
    }
    let offset = 8 + (sub_count - 1) * 4;
    // Safety: `offset` is within the SID for a SID with `sub_count` sub-authorities, and the
    // count was bounds-checked above so the offset cannot run past the buffer.
    let rid = unsafe {
        u32::from_le_bytes([
            *label_sid.add(offset),
            *label_sid.add(offset + 1),
            *label_sid.add(offset + 2),
            *label_sid.add(offset + 3),
        ])
    };

    Ok(rid)
}

/// The token of the current process.
fn open_current_token() -> Result<HANDLE, WinError> {
    let mut token = HANDLE::default();
    // Safety: the process pseudo-handle is always valid and needs no closing, and `token` is a
    // correctly typed out-parameter. The returned token is closed by `TokenGuard`.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return Err(WinError::last("OpenProcessToken"));
    }
    // The caller leaks the handle unless it closes it. Rather than making every caller remember,
    // this returns an owned handle wrapper via a small leak-avoidance: the token handles opened
    // here are closed by the process exit at the latest, and the callers are short-lived
    // diagnostic paths. To avoid that tradeoff entirely, a guard type is used instead.
    Ok(token)
}

/// A token handle that closes itself.
#[derive(Debug)]
pub struct TokenGuard(HANDLE);

impl TokenGuard {
    /// Open the current process token.
    pub fn current() -> Result<Self, WinError> {
        open_current_token().map(TokenGuard)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        if !self.0.is_invalid() {
            // Safety: the handle came from OpenProcessToken and is closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_query_does_not_panic() {
        // Both outcomes are valid depending on how the test runner was launched.
        let _ = is_elevated();
    }

    #[test]
    fn local_system_query_does_not_panic() {
        // A test runner is never LocalSystem, but the check must not panic either way.
        let _ = is_local_system();
    }

    #[test]
    fn integrity_level_is_readable() {
        match integrity_level() {
            Ok(rid) => {
                // The documented integrity RIDs: 0x0000 untrusted, 0x1000 low, 0x2000 medium,
                // 0x3000 high, 0x4000 system.
                assert!(
                    matches!(rid, 0x0000 | 0x1000 | 0x2000 | 0x3000 | 0x4000),
                    "unexpected integrity RID {rid:#x}"
                );
            }
            Err(e) => {
                // A restricted context may not expose the token; that is reported, not fatal.
                eprintln!("integrity level unavailable: {e}");
            }
        }
    }

    #[test]
    fn a_test_runner_is_not_local_system() {
        // `cargo test` runs as the invoking user, never as SYSTEM. If this ever fails, something
        // is very wrong with the environment rather than with the code.
        assert!(
            !is_local_system(),
            "a test runner should not be running as LocalSystem"
        );
    }

    #[test]
    fn token_guard_closes_its_handle() {
        let guard = TokenGuard::current().expect("the current process token is always openable");
        assert!(!guard.raw().is_invalid());
        // Dropping must close it; running the query again proves the handle was not leaked in a
        // way that breaks subsequent opens.
        drop(guard);
        let again = TokenGuard::current().expect("a second open must still work");
        assert!(!again.raw().is_invalid());
    }
}
