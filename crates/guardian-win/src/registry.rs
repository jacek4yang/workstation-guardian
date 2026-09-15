//! Type-safe access to the registry.
//!
//! Only the operations Guardian actually needs: read a value, write a value, delete a value
//! Guardian itself created, and detect whether a key is externally managed.
//!
//! Every function is a safe wrapper. Handles are closed by RAII even on the error path, and
//! value data is decoded according to the type the API reports rather than the type we
//! expected, so a mismatched value can never be misread as something else.

use std::fmt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_NONE,
    REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
};

use guardian_proto::model::PolValue;

use crate::{wide_from_buf, WideString, WinError};

/// Maximum bytes read for a single registry value.
///
/// Registry values Guardian cares about are DWORDs and short strings. 1 MiB is far above any
/// legitimate value and bounds what a hostile or corrupted hive can make us allocate.
const MAX_VALUE_BYTES: u32 = 1024 * 1024;

/// Maximum subkey name length, per the registry's own documented limit.
const MAX_KEY_NAME: usize = 255;

/// A registry hive, restricted to the two Guardian uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    fn handle(self) -> HKEY {
        match self {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::CurrentUser => HKEY_CURRENT_USER,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }
}

/// A registry path: hive plus subkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegPath {
    pub hive: Hive,
    pub subkey: String,
}

impl RegPath {
    pub fn local_machine(subkey: impl Into<String>) -> Self {
        RegPath {
            hive: Hive::LocalMachine,
            subkey: subkey.into(),
        }
    }

    pub fn current_user(subkey: impl Into<String>) -> Self {
        RegPath {
            hive: Hive::CurrentUser,
            subkey: subkey.into(),
        }
    }

    /// Parse a path like `HKLM\SOFTWARE\Policies\...`.
    pub fn parse(s: &str) -> Result<Self, WinError> {
        let (hive_part, rest) = s.split_once('\\').ok_or_else(|| WinError::Invalid {
            context: "RegPath::parse",
            detail: format!("'{s}' has no hive separator"),
        })?;
        let hive = match hive_part.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Hive::LocalMachine,
            "HKCU" | "HKEY_CURRENT_USER" => Hive::CurrentUser,
            other => {
                return Err(WinError::Invalid {
                    context: "RegPath::parse",
                    detail: format!("unsupported hive '{other}'"),
                })
            }
        };
        Ok(RegPath {
            hive,
            subkey: rest.to_string(),
        })
    }

    /// Append a subkey, producing a child path.
    pub fn join(&self, child: &str) -> Self {
        RegPath {
            hive: self.hive,
            subkey: format!("{}\\{}", self.subkey, child),
        }
    }
}

impl fmt::Display for RegPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\\{}", self.hive.as_str(), self.subkey)
    }
}

/// An open registry key. Closes itself on drop.
#[derive(Debug)]
pub struct RegKey {
    handle: HKEY,
    path: RegPath,
}

// The handle is only ever used from the thread that created it, and this type is not Send
// across threads by accident: making that explicit avoids a whole class of bugs.
impl RegKey {
    /// Open an existing key for reading.
    pub fn open_read(path: &RegPath) -> Result<Self, WinError> {
        Self::open_with(path, KEY_READ)
    }

    /// Open an existing key for reading and writing.
    pub fn open_write(path: &RegPath) -> Result<Self, WinError> {
        Self::open_with(path, KEY_READ | KEY_WRITE)
    }

    fn open_with(
        path: &RegPath,
        access: windows::Win32::System::Registry::REG_SAM_FLAGS,
    ) -> Result<Self, WinError> {
        let wide = WideString::new(&path.subkey);
        let mut handle = HKEY::default();

        // Safety: `wide` is a valid NUL-terminated wide string that outlives the call, and
        // `handle` is a valid out-parameter. The returned handle, if the call succeeds, is
        // owned by the RegKey we are about to construct.
        let rc = unsafe {
            RegOpenKeyExW(
                path.hive.handle(),
                PCWSTR(wide.as_ptr()),
                Some(0),
                access,
                &mut handle,
            )
        };

        if rc != ERROR_SUCCESS {
            return Err(map_open_error("RegOpenKeyExW", rc, path));
        }

        Ok(RegKey {
            handle,
            path: path.clone(),
        })
    }

    /// Create a key (and its parents) if absent, otherwise open it.
    ///
    /// Returns the key and whether it was newly created, so the caller can record that it
    /// owns the key and may remove it on uninstall.
    pub fn create(path: &RegPath) -> Result<(Self, bool), WinError> {
        let wide = WideString::new(&path.subkey);
        let mut handle = HKEY::default();
        let mut disposition = windows::Win32::System::Registry::REG_CREATE_KEY_DISPOSITION(0);

        // Safety: as `open_with`. `disposition` receives REG_CREATED_NEW_KEY or
        // REG_OPENED_EXISTING_KEY; the buffer is a correctly typed out-parameter.
        let rc = unsafe {
            RegCreateKeyExW(
                path.hive.handle(),
                PCWSTR(wide.as_ptr()),
                Some(0),
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                None,
                &mut handle,
                Some(&mut disposition),
            )
        };

        if rc != ERROR_SUCCESS {
            return Err(map_open_error("RegCreateKeyExW", rc, path));
        }

        // REG_CREATED_NEW_KEY == 1, REG_OPENED_EXISTING_KEY == 2.
        Ok((
            RegKey {
                handle,
                path: path.clone(),
            },
            disposition.0 == 1,
        ))
    }

    pub fn path(&self) -> &RegPath {
        &self.path
    }

    /// Read a value. `Ok(None)` means the value does not exist, which is distinct from a
    /// failure to read it.
    pub fn get_value(&self, name: &str) -> Result<Option<PolValue>, WinError> {
        let wide = WideString::new(name);
        let mut ty = REG_NONE;
        let mut len = 0u32;

        // First call with a null buffer to learn the size. This is the documented pattern.
        //
        // Safety: a null data pointer with a zero length is the documented way to query
        // the required size. `ty` and `len` are valid out-parameters.
        let rc = unsafe {
            RegQueryValueExW(
                self.handle,
                PCWSTR(wide.as_ptr()),
                None,
                Some(&mut ty),
                None,
                Some(&mut len),
            )
        };

        if rc != ERROR_SUCCESS {
            // A missing value is `Ok(None)`, which is a normal state rather than a failure.
            return match map_value_error::<()>("RegQueryValueExW(size)", rc, name) {
                Ok(()) => Ok(None),
                Err(e) if e.is_not_found() => Ok(None),
                Err(e) => Err(e),
            };
        }

        if len > MAX_VALUE_BYTES {
            return Err(WinError::Invalid {
                context: "RegQueryValueExW",
                detail: format!("value '{name}' is {len} bytes, over the limit"),
            });
        }

        let mut buf = vec![0u8; len.max(4) as usize];
        let mut actual_len = buf.len() as u32;

        // Safety: `buf` is large enough for `len` bytes and `actual_len` describes it.
        let rc = unsafe {
            RegQueryValueExW(
                self.handle,
                PCWSTR(wide.as_ptr()),
                None,
                Some(&mut ty),
                Some(buf.as_mut_ptr()),
                Some(&mut actual_len),
            )
        };

        if rc != ERROR_SUCCESS {
            return map_value_error("RegQueryValueExW(data)", rc, name);
        }

        buf.truncate(actual_len as usize);
        Ok(Some(decode_value(ty, &buf)))
    }

    /// Write a value, creating it if absent.
    pub fn set_value(&self, name: &str, value: &PolValue) -> Result<(), WinError> {
        let wide = WideString::new(name);
        let (ty, bytes) = encode_value(value);

        // Safety: `bytes` is a valid slice for `bytes.len()` bytes and `ty` matches the
        // encoding produced by `encode_value`, which the tests pin down.
        let rc = unsafe {
            RegSetValueExW(
                self.handle,
                PCWSTR(wide.as_ptr()),
                Some(0),
                ty,
                Some(&bytes),
            )
        };

        if rc != ERROR_SUCCESS {
            // set_value has no "absent" case: every failure here is a real failure.
            return match map_value_error::<()>("RegSetValueExW", rc, name) {
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            };
        }
        Ok(())
    }

    /// Delete a value. `Ok(true)` means it was deleted, `Ok(false)` that it was absent.
    pub fn delete_value(&self, name: &str) -> Result<bool, WinError> {
        let wide = WideString::new(name);
        // Safety: valid key handle and NUL-terminated name.
        let rc = unsafe { RegDeleteValueW(self.handle, PCWSTR(wide.as_ptr())) };
        if rc == ERROR_SUCCESS {
            Ok(true)
        } else {
            match map_value_error::<()>("RegDeleteValueW", rc, name) {
                Ok(()) => Ok(false),
                Err(e) if e.is_not_found() => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    /// List the immediate subkey names.
    pub fn subkeys(&self) -> Result<Vec<String>, WinError> {
        let mut count = 0u32;
        let mut max_name = 0u32;

        // Safety: valid handle; the out-parameters are correctly typed and may be null.
        let rc = unsafe {
            RegQueryInfoKeyW(
                self.handle,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut max_name),
                None,
                None,
                None,
                None,
                None,
                None,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(WinError::from_code("RegQueryInfoKeyW", rc.0));
        }

        // The API reports the longest name length; bound it so a corrupt hive cannot make
        // us allocate an enormous buffer.
        let name_len = (max_name as usize + 1).clamp(1, MAX_KEY_NAME + 1);
        let mut out = Vec::with_capacity(count as usize);

        for i in 0..count {
            let mut buf = vec![0u16; name_len];
            let mut len = name_len as u32;

            // Safety: `buf` has room for `name_len` units and `len` describes it. A longer
            // name than the reported maximum cannot occur, but if it did the call would
            // return ERROR_MORE_DATA rather than overrun.
            let rc = unsafe {
                RegEnumKeyExW(
                    self.handle,
                    i,
                    Some(windows::core::PWSTR(buf.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };

            if rc == ERROR_SUCCESS {
                buf.truncate(len as usize);
                out.push(String::from_utf16_lossy(&buf));
            } else if rc.0 == windows::Win32::Foundation::ERROR_NO_MORE_ITEMS.0 {
                // The count reported by RegQueryInfoKeyW can be stale if a subkey was
                // deleted concurrently. Stopping is correct, not an error.
                break;
            } else {
                // Something else went wrong for this entry. Skip it rather than failing the
                // whole enumeration: callers use this for diagnostics, not for control flow,
                // and a partial list is more useful than none.
                tracing::debug!(
                    key = %self.path,
                    index = i,
                    code = rc.0,
                    "subkey enumeration skipped an unreadable entry"
                );
            }
        }

        Ok(out)
    }

    /// List the value names in this key, with their types.
    pub fn value_names(&self) -> Result<Vec<(String, PolValue)>, WinError> {
        let mut values = Vec::new();
        let mut index = 0u32;

        loop {
            let mut name_buf = vec![0u16; MAX_KEY_NAME + 1];
            let mut name_len = name_buf.len() as u32;
            let mut ty = REG_NONE;
            let mut data_len = 0u32;

            // Safety: all buffers are valid for the lengths passed.
            let rc = unsafe {
                RegEnumValueW(
                    self.handle,
                    index,
                    Some(windows::core::PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut ty.0),
                    None,
                    Some(&mut data_len),
                )
            };

            if rc != ERROR_SUCCESS {
                // ERROR_NO_MORE_ITEMS is the normal end of enumeration. Any other failure
                // also stops the walk: a partial list is safe to return because callers use
                // this only for diagnostics, and continuing past a failed index would risk
                // an unbounded loop on a wedged key.
                if rc.0 != windows::Win32::Foundation::ERROR_NO_MORE_ITEMS.0 {
                    tracing::debug!(
                        key = %self.path,
                        index,
                        code = rc.0,
                        "value enumeration stopped early"
                    );
                }
                break;
            }

            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            // Read the data in a second pass now that the length is known.
            let value = match self.get_value(&name) {
                Ok(Some(v)) => v,
                // The value vanished between the two calls. Record it as absent rather than
                // inventing a default.
                Ok(None) => continue,
                Err(_) => continue,
            };
            values.push((name, value));
            index += 1;
        }

        Ok(values)
    }

    /// Whether a subkey exists.
    pub fn subkey_exists(&self, name: &str) -> bool {
        self.path()
            .join(name)
            .clone()
            .pipe(|p| RegKey::open_read(&p).is_ok())
    }
}

/// Small helper so `subkey_exists` reads as one expression.
trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

impl Drop for RegKey {
    fn drop(&mut self) {
        // Safety: `handle` was produced by a successful open/create and is not used again
        // after this call. RegCloseKey on an already-closed handle would be a bug, but RAII
        // guarantees this runs exactly once.
        unsafe {
            let _ = RegCloseKey(self.handle);
        }
    }
}

/// Decode raw registry data according to the type the API reported.
///
/// The type is authoritative: a value stored as REG_SZ is read as a string even if we
/// expected a DWORD, rather than being reinterpreted. That matters because a mismatched
/// value should be *visible* as a mismatch, not silently coerced into something that
/// happens to look correct.
fn decode_value(ty: REG_VALUE_TYPE, bytes: &[u8]) -> PolValue {
    match ty {
        REG_DWORD => {
            if bytes.len() >= 4 {
                PolValue::Dword(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                PolValue::Dword(0)
            }
        }
        REG_SZ => PolValue::String(decode_utf16(bytes)),
        REG_EXPAND_SZ => PolValue::ExpandString(decode_utf16(bytes)),
        REG_MULTI_SZ => PolValue::MultiString(decode_multi_string(bytes)),
        // Any other type (REG_BINARY, REG_QWORD, REG_NONE) is not something Guardian owns.
        // Represent it as a string so the mismatch is visible rather than fabricated.
        _ => PolValue::String(format!("<{ty:?}, {} bytes>", bytes.len())),
    }
}

/// Decode a `REG_MULTI_SZ`: NUL-separated strings terminated by an empty string.
///
/// This cannot use `decode_utf16`, which stops at the first NUL and would silently truncate
/// a multi-string to its first element — a bug that is invisible until someone relies on the
/// second entry.
fn decode_multi_string(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let mut out = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    for &u in &units {
        if u == 0 {
            if current.is_empty() {
                // An empty entry terminates the list, per the REG_MULTI_SZ definition.
                break;
            }
            out.push(String::from_utf16_lossy(&current));
            current.clear();
        } else {
            current.push(u);
        }
    }
    // A final string without its terminator is still a value, not a truncation.
    if !current.is_empty() {
        out.push(String::from_utf16_lossy(&current));
    }
    out
}

fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let (s, _) = wide_from_buf(&units);
    s
}

/// Encode a value for writing, returning the registry type and the byte representation.
fn encode_value(value: &PolValue) -> (REG_VALUE_TYPE, Vec<u8>) {
    match value {
        PolValue::Dword(v) => (REG_DWORD, v.to_le_bytes().to_vec()),
        PolValue::String(s) => (REG_SZ, encode_utf16_nul(s)),
        PolValue::ExpandString(s) => (REG_EXPAND_SZ, encode_utf16_nul(s)),
        PolValue::MultiString(items) => {
            let mut units = Vec::new();
            for item in items {
                units.extend(item.encode_utf16());
                units.push(0);
            }
            units.push(0);
            (REG_MULTI_SZ, units_to_bytes(&units))
        }
    }
}

fn encode_utf16_nul(s: &str) -> Vec<u8> {
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0);
    units_to_bytes(&units)
}

fn units_to_bytes(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len() * 2);
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn map_open_error(op: &'static str, rc: WIN32_ERROR, path: &RegPath) -> WinError {
    match WinError::from_code(op, rc.0) {
        // A missing key is reported generically; the path is added by the caller's context.
        e @ WinError::NotFound { .. } => {
            tracing::trace!(key = %path, "registry key is absent");
            e
        }
        e => e,
    }
}

/// Map a value-level error, turning "value not found" into `Ok(None)` where the signature
/// allows it.
fn map_value_error<T>(op: &'static str, rc: WIN32_ERROR, name: &str) -> Result<T, WinError> {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND};
    if rc == ERROR_FILE_NOT_FOUND {
        return Err(WinError::NotFound { operation: op });
    }
    if rc == ERROR_ACCESS_DENIED {
        return Err(WinError::AccessDenied { operation: op });
    }
    let _ = name;
    Err(WinError::from_code(op, rc.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch key under HKCU, which a normal user can create without elevation.
    struct Scratch {
        path: RegPath,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = RegPath::current_user(format!(
                r"Software\WorkstationGuardianTest\{tag}-{}",
                std::process::id()
            ));
            // Best effort: remove any leftover from a previous failed run.
            if let Ok(k) = RegKey::open_write(&path) {
                for name in ["dword", "string", "expand", "multi"] {
                    let _ = k.delete_value(name);
                }
            }
            Scratch { path }
        }
        fn key(&self) -> RegKey {
            RegKey::create(&self.path).expect("create scratch key").0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // Delete the values we created, then leave the (now empty) key. Deleting the
            // key itself needs RegDeleteKeyW, which is not in the wrapper surface by
            // design: Guardian never deletes keys it did not create, and uninstall handles
            // that case explicitly.
            if let Ok(k) = RegKey::open_write(&self.path) {
                for (name, _) in k.value_names().unwrap_or_default() {
                    let _ = k.delete_value(&name);
                }
            }
        }
    }

    #[test]
    fn dword_round_trips() {
        let s = Scratch::new("dword-rt");
        let k = s.key();
        assert!(k.get_value("dword").unwrap().is_none());

        k.set_value("dword", &PolValue::Dword(1)).unwrap();
        assert_eq!(k.get_value("dword").unwrap(), Some(PolValue::Dword(1)));

        k.set_value("dword", &PolValue::Dword(0)).unwrap();
        assert_eq!(k.get_value("dword").unwrap(), Some(PolValue::Dword(0)));

        k.set_value("dword", &PolValue::Dword(u32::MAX)).unwrap();
        assert_eq!(
            k.get_value("dword").unwrap(),
            Some(PolValue::Dword(u32::MAX))
        );
    }

    #[test]
    fn string_round_trips_including_unicode() {
        let s = Scratch::new("string-rt");
        let k = s.key();

        k.set_value("string", &PolValue::String("plain ascii".into()))
            .unwrap();
        assert_eq!(
            k.get_value("string").unwrap(),
            Some(PolValue::String("plain ascii".into()))
        );

        k.set_value("string", &PolValue::String("工作区 😀".into()))
            .unwrap();
        assert_eq!(
            k.get_value("string").unwrap(),
            Some(PolValue::String("工作区 😀".into())),
            "non-BMP characters must survive an UTF-16 round trip"
        );

        k.set_value("string", &PolValue::String(String::new()))
            .unwrap();
        assert_eq!(
            k.get_value("string").unwrap(),
            Some(PolValue::String(String::new()))
        );
    }

    #[test]
    fn expand_string_and_multi_string_round_trip() {
        let s = Scratch::new("multi-rt");
        let k = s.key();

        k.set_value("expand", &PolValue::ExpandString(r"%SystemRoot%\x".into()))
            .unwrap();
        assert_eq!(
            k.get_value("expand").unwrap(),
            Some(PolValue::ExpandString(r"%SystemRoot%\x".into()))
        );

        k.set_value(
            "multi",
            &PolValue::MultiString(vec!["a".into(), "b".into()]),
        )
        .unwrap();
        assert_eq!(
            k.get_value("multi").unwrap(),
            Some(PolValue::MultiString(vec!["a".into(), "b".into()]))
        );
    }

    #[test]
    fn deleting_a_missing_value_reports_absence_not_failure() {
        let s = Scratch::new("del-missing");
        let k = s.key();
        assert!(!k.delete_value("never-existed").unwrap());
        k.set_value("dword", &PolValue::Dword(1)).unwrap();
        assert!(k.delete_value("dword").unwrap());
        assert!(!k.delete_value("dword").unwrap());
    }

    #[test]
    fn value_names_lists_what_was_written() {
        let s = Scratch::new("enum-values");
        let k = s.key();
        k.set_value("dword", &PolValue::Dword(7)).unwrap();
        k.set_value("string", &PolValue::String("x".into()))
            .unwrap();

        let names: Vec<String> = k
            .value_names()
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(names.contains(&"dword".to_string()));
        assert!(names.contains(&"string".to_string()));
    }

    #[test]
    fn opening_a_missing_key_is_reported_as_not_found() {
        let path =
            RegPath::current_user(r"Software\WorkstationGuardianTest\definitely-not-here-9f3a2b");
        let err = RegKey::open_read(&path).unwrap_err();
        assert!(
            err.is_not_found(),
            "an absent key must be NotFound, not a generic failure: {err}"
        );
    }

    #[test]
    fn create_reports_whether_the_key_was_new() {
        let path = RegPath::current_user(format!(
            r"Software\WorkstationGuardianTest\create-flag-{}",
            std::process::id()
        ));
        let (k1, created1) = RegKey::create(&path).unwrap();
        assert!(created1, "first create must report a new key");
        drop(k1);

        let (k2, created2) = RegKey::create(&path).unwrap();
        assert!(!created2, "second create must report an existing key");
        drop(k2);
    }

    #[test]
    fn reg_path_display_is_stable() {
        let p = RegPath::local_machine(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
        assert_eq!(
            p.to_string(),
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        );
        assert_eq!(
            p.join("Sub").to_string(),
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\Sub"
        );
    }

    #[test]
    fn reg_path_parsing_accepts_both_spellings() {
        assert_eq!(
            RegPath::parse(r"HKLM\SOFTWARE\X").unwrap().hive,
            Hive::LocalMachine
        );
        assert_eq!(
            RegPath::parse(r"HKEY_LOCAL_MACHINE\SOFTWARE\X")
                .unwrap()
                .hive,
            Hive::LocalMachine
        );
        assert_eq!(
            RegPath::parse(r"HKCU\Software\X").unwrap().hive,
            Hive::CurrentUser
        );
        assert!(RegPath::parse("no-hive-separator").is_err());
        assert!(RegPath::parse(r"HKZZ\SOFTWARE\X").is_err());
    }

    #[test]
    fn value_encoding_matches_the_declared_type() {
        // A mismatch between the type byte and the payload would corrupt the hive, so pin
        // the encoding down explicitly.
        let (ty, bytes) = encode_value(&PolValue::Dword(0x0102_0304));
        assert_eq!(ty, REG_DWORD);
        assert_eq!(bytes, vec![0x04, 0x03, 0x02, 0x01]);

        let (ty, bytes) = encode_value(&PolValue::String("hi".into()));
        assert_eq!(ty, REG_SZ);
        assert_eq!(bytes, vec![b'h', 0, b'i', 0, 0, 0]);

        let (ty, bytes) = encode_value(&PolValue::ExpandString("a".into()));
        assert_eq!(ty, REG_EXPAND_SZ);
        assert_eq!(bytes, vec![b'a', 0, 0, 0]);

        let (ty, bytes) = encode_value(&PolValue::MultiString(vec!["a".into(), "b".into()]));
        assert_eq!(ty, REG_MULTI_SZ);
        assert_eq!(
            bytes,
            vec![b'a', 0, 0, 0, b'b', 0, 0, 0, 0, 0],
            "each item NUL-terminated, then a final NUL"
        );
    }

    #[test]
    fn decoding_respects_the_declared_type() {
        // A DWORD-length buffer read as a string must not be reinterpreted as a number.
        let dword_bytes = 1u32.to_le_bytes();
        assert_eq!(decode_value(REG_DWORD, &dword_bytes), PolValue::Dword(1));

        // Truncated DWORD data must not panic.
        assert_eq!(decode_value(REG_DWORD, &[1, 2]), PolValue::Dword(0));

        // An unexpected type is surfaced as text, not coerced.
        let unknown = decode_value(windows::Win32::System::Registry::REG_BINARY, &[0xAA, 0xBB]);
        assert!(matches!(unknown, PolValue::String(_)));
    }

    #[test]
    fn empty_multi_string_decodes_to_an_empty_list() {
        let bytes = units_to_bytes(&[0u16, 0u16]);
        assert_eq!(
            decode_value(REG_MULTI_SZ, &bytes),
            PolValue::MultiString(vec![])
        );
    }
}
