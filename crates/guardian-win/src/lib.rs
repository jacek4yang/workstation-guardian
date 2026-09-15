//! Safe wrappers over the Win32 APIs Workstation Guardian needs.
//!
//! This is the **only** crate in the workspace that contains `unsafe`. Everything else is
//! safe Rust that talks to the small typed interfaces here.
//!
//! # Rules for this crate
//!
//! * `#![deny(unsafe_op_in_unsafe_fn)]` — every unsafe operation is individually justified
//!   inside an explicit `unsafe { }` block, so a reviewer can see exactly what is being
//!   assumed.
//! * Every public function is safe and returns a typed `Result`. No raw handles,
//!   `PCWSTR`, or pointers cross the boundary.
//! * All handles are owned by RAII wrappers that close them on drop, including on the
//!   unwind path.
//! * Buffer sizes are always checked against the length the API reported, never assumed.
//! * Nothing here decides policy. These are mechanisms: read a value, write a value, dial a
//!   link, enumerate processes. The decisions live in `guardian-core`, where they are
//!   testable.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod boot;
pub mod clock;
pub mod elevation;
pub mod eventlog;
pub mod pipe;
pub mod policy;
pub mod process;
pub mod ras;
pub mod registry;
pub mod service;
pub mod service_host;
pub mod session;
pub mod wifi;

/// The service description used at install time.
///
/// Defined here rather than in the installer so the module that writes it and the constant
/// that describes it cannot drift.
pub const SERVICE_DESCRIPTION_TEXT: &str =
    "Protects long-running development work from unexpected Windows Update restarts, and keeps      the network connection available.";

/// Errors from the Win32 layer.
///
/// The distinction that matters to callers is [`WinError::NotFound`] versus everything
/// else: "the value is absent" is a normal, expected state, while "access denied" is a
/// problem that must be reported rather than silently treated as absence.
#[derive(Debug, thiserror::Error)]
pub enum WinError {
    #[error("{operation} failed with Windows error {code}: {message}")]
    Api {
        operation: &'static str,
        code: u32,
        message: String,
    },

    #[error("{operation}: the requested item does not exist")]
    NotFound { operation: &'static str },

    #[error("{operation}: access denied")]
    AccessDenied { operation: &'static str },

    #[error("{operation}: buffer too small (needed {needed}, had {had})")]
    BufferTooSmall {
        operation: &'static str,
        needed: usize,
        had: usize,
    },

    #[error("{operation}: the operation timed out")]
    Timeout { operation: &'static str },

    #[error("{context}: {detail}")]
    Invalid {
        context: &'static str,
        detail: String,
    },
}

impl WinError {
    /// Build an error from a failing call's `GetLastError` value.
    pub(crate) fn last(operation: &'static str) -> Self {
        // Safety: GetLastError takes no arguments and has no preconditions. It must be
        // called immediately after the failing call, which is what every caller here does.
        let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
        Self::from_code(operation, code)
    }

    pub(crate) fn from_code(operation: &'static str, code: u32) -> Self {
        use windows::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
            ERROR_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        };
        match code {
            c if c == ERROR_FILE_NOT_FOUND.0 => WinError::NotFound { operation },
            c if c == ERROR_PATH_NOT_FOUND.0 => WinError::NotFound { operation },
            c if c == ERROR_NOT_FOUND.0 => WinError::NotFound { operation },
            c if c == ERROR_ACCESS_DENIED.0 => WinError::AccessDenied { operation },
            c if c == ERROR_INSUFFICIENT_BUFFER.0 || c == ERROR_MORE_DATA.0 => {
                WinError::BufferTooSmall {
                    operation,
                    needed: 0,
                    had: 0,
                }
            }
            _ => WinError::Api {
                operation,
                code,
                message: format_win_error(code),
            },
        }
    }

    /// Whether this error means "the thing is not there", as opposed to a real failure.
    ///
    /// Callers use this to distinguish an absent registry value (normal) from a denied read
    /// (must be reported, because it makes protection state unknown).
    pub fn is_not_found(&self) -> bool {
        matches!(self, WinError::NotFound { .. })
    }

    /// Whether the failure was a permission problem.
    pub fn is_access_denied(&self) -> bool {
        matches!(self, WinError::AccessDenied { .. })
    }
}

/// Render a Win32 error code through `FormatMessageW`.
pub fn format_win_error(code: u32) -> String {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows::Win32::System::Diagnostics::Debug::{
        FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
        FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    if code == ERROR_SUCCESS.0 {
        return "the operation completed successfully".into();
    }

    unsafe {
        let mut buf = PWSTR::null();
        let len = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code,
            0,
            // FormatMessageW writes a pointer to the allocated buffer through the
            // lpBuffer argument when ALLOCATE_BUFFER is set, which is why this is a cast.
            PWSTR(&mut buf as *mut PWSTR as *mut u16),
            0,
            None,
        );

        if len == 0 || buf.is_null() {
            return format!("unknown Windows error {code}");
        }

        let slice = std::slice::from_raw_parts(buf.0, len as usize);
        let text = String::from_utf16_lossy(slice);
        let _ = LocalFree(Some(HLOCAL(buf.0 as *mut core::ffi::c_void)));

        // FormatMessage output ends with CRLF; strip it so log lines stay single-line.
        text.trim_end_matches(['\r', '\n']).to_string()
    }
}

/// Read a wide string out of a fixed-size buffer, stopping at the first NUL.
///
/// Returns the string and the number of `u16` units occupied *excluding* the terminator.
pub(crate) fn wide_from_buf(buf: &[u16]) -> (String, usize) {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    (String::from_utf16_lossy(&buf[..end]), end)
}

/// Convert a NUL-terminated wide buffer to a `String`.
pub(crate) fn wide_to_string(buf: &[u16]) -> String {
    wide_from_buf(buf).0
}

/// A `Vec<u16>` holding a NUL-terminated wide string, suitable for passing as `PCWSTR`.
#[derive(Debug, Clone)]
pub struct WideString(Vec<u16>);

impl WideString {
    pub fn new(s: &str) -> Self {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        WideString(v)
    }

    /// Pointer for a `PCWSTR` argument. Valid for as long as `self` lives.
    pub fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    /// Length in `u16` units, excluding the terminator.
    pub fn len_units(&self) -> usize {
        self.0.len().saturating_sub(1)
    }

    /// The backing slice, including the terminator.
    pub fn as_slice_with_nul(&self) -> &[u16] {
        &self.0
    }

    /// Build from a fixed-size buffer that has already been validated as NUL-terminated.
    pub fn from_units(mut v: Vec<u16>) -> Self {
        if v.last() != Some(&0) {
            v.push(0);
        }
        WideString(v)
    }
}

/// Take a fixed-size array of `u16` and read it as a wide string.
pub fn wide_array_to_string(buf: &[u16]) -> String {
    wide_to_string(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_string_round_trips() {
        let w = WideString::new("hello");
        assert_eq!(w.len_units(), 5);
        assert_eq!(w.as_slice_with_nul().len(), 6);
        assert_eq!(w.as_slice_with_nul()[5], 0);
        assert_eq!(wide_to_string(w.as_slice_with_nul()), "hello");
    }

    #[test]
    fn wide_string_handles_unicode() {
        let w = WideString::new("工作区");
        // Three characters, three UTF-16 units, plus the terminator.
        assert_eq!(w.len_units(), 3);
        assert_eq!(wide_to_string(w.as_slice_with_nul()), "工作区");
    }

    #[test]
    fn wide_string_handles_empty() {
        let w = WideString::new("");
        assert_eq!(w.len_units(), 0);
        assert_eq!(wide_to_string(w.as_slice_with_nul()), "");
    }

    #[test]
    fn wide_from_buf_stops_at_nul() {
        let buf = [b'a' as u16, b'b' as u16, 0, b'c' as u16, 0];
        let (s, used) = wide_from_buf(&buf);
        assert_eq!(s, "ab");
        assert_eq!(used, 2);
    }

    #[test]
    fn wide_from_buf_handles_no_terminator() {
        let buf = [b'a' as u16, b'b' as u16];
        let (s, used) = wide_from_buf(&buf);
        assert_eq!(s, "ab");
        assert_eq!(used, 2);
    }

    #[test]
    fn from_units_adds_a_terminator_when_missing() {
        let w = WideString::from_units(vec![b'x' as u16]);
        assert_eq!(w.as_slice_with_nul(), &[b'x' as u16, 0]);

        let w2 = WideString::from_units(vec![b'y' as u16, 0]);
        assert_eq!(w2.as_slice_with_nul(), &[b'y' as u16, 0]);
    }

    #[test]
    fn error_classification_maps_the_important_codes() {
        use windows::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        };
        assert!(WinError::from_code("test", ERROR_FILE_NOT_FOUND.0).is_not_found());
        assert!(WinError::from_code("test", ERROR_PATH_NOT_FOUND.0).is_not_found());
        assert!(WinError::from_code("test", ERROR_ACCESS_DENIED.0).is_access_denied());
        let other = WinError::from_code("test", 1234);
        assert!(!other.is_not_found());
        assert!(!other.is_access_denied());
    }

    #[test]
    fn error_messages_are_rendered_and_single_line() {
        use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
        let msg = format_win_error(ERROR_ACCESS_DENIED.0);
        assert!(!msg.is_empty());
        assert!(!msg.contains('\n'), "log lines must not contain newlines");
        assert!(!msg.contains('\r'));
    }

    #[test]
    fn unknown_error_code_still_produces_text() {
        let msg = format_win_error(0xDEAD_BEEF);
        assert!(!msg.is_empty());
    }

    #[test]
    fn success_code_is_described_not_rendered() {
        assert_eq!(format_win_error(0), "the operation completed successfully");
    }
}
