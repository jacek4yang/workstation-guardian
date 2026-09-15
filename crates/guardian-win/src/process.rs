//! Process enumeration, inspection and process-graph construction.
//!
//! # Why `CreateToolhelp32Snapshot` and not WMI
//!
//! WMI's `Win32_Process` queries are comparatively expensive — a full WMI query can take
//! tens to hundreds of milliseconds and involves COM marshalling and the WMI service. A
//! toolhelp snapshot of a machine with a few hundred processes is sub-millisecond, needs no
//! service, and cannot deadlock on a wedged WMI provider. For a component that runs every
//! few seconds forever, that difference is the whole design.
//!
//! WMI would only become necessary for push-based process start/stop events. Guardian
//! instead uses `WTS`-style session enumeration plus periodic snapshots, which is simple,
//! robust, and gives the detector everything it needs.
//!
//! # Access and failure modes
//!
//! Reading another process's command line requires opening it with `PROCESS_QUERY_LIMITED_
//! INFORMATION`, which succeeds for a normal user for most processes but is denied for
//! protected and higher-integrity processes. A denied read is recorded as
//! `cmdline_denied` rather than as "no command line", because the detector's confidence
//! must reflect what it actually knows. Treating denied as empty would silently downgrade
//! a real agent detection to a miss.

use std::collections::HashMap;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use guardian_proto::model::ProcessSnapshot;

use crate::clock::filetime_to_u64;
use crate::{WideString, WinError};

/// Maximum length of an image path or command line we will accept.
///
/// The documented maximum path is 32 767 characters; command lines can exceed that but
/// nothing Guardian needs to identify would. Bounding this prevents a hostile process from
/// making us allocate an enormous buffer.
const MAX_PATH_UNITS: usize = 32_768;

/// A handle that closes itself.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Whether this is the pseudo-handle value that must not be closed.
    pub fn is_null(&self) -> bool {
        self.0.is_invalid()
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // Safety: the handle came from a successful open and is not used afterwards.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Enumerate every process on the system.
///
/// Returns snapshots in an unspecified order; callers that care build a graph.
pub fn enumerate_processes() -> Result<Vec<ProcessSnapshot>, WinError> {
    // Safety: TH32CS_SNAPPROCESS with a null pid snapshots all processes. The returned
    // handle is owned by OwnedHandle and closed on drop.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|_| WinError::last("CreateToolhelp32Snapshot"))?;
    let snapshot = OwnedHandle(snapshot);

    // dwSize must be set on the structure before the call, as the API validates it.
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // Safety: `entry` is correctly sized per dwSize, as the API requires.
    let mut ok = unsafe { Process32FirstW(snapshot.raw(), &mut entry) }.is_ok();
    if !ok {
        let err = WinError::last("Process32FirstW");
        // An empty snapshot is a legitimate (if surprising) result on a system with no
        // processes; anything else is a real failure.
        return if err.is_not_found() {
            Ok(Vec::new())
        } else {
            Err(err)
        };
    }

    let mut out = Vec::with_capacity(256);
    let self_pid = current_pid();

    while ok {
        let name = crate::wide_array_to_string(&entry.szExeFile);
        let pid = entry.th32ProcessID;
        let parent_pid = entry.th32ParentProcessID;

        // Skip the idle process, which has no image, and ourselves, which we never need to
        // detect as an agent.
        if pid != 0 && pid != self_pid {
            out.push(build_snapshot(pid, parent_pid, name));
        }

        // Safety: as above; `entry` is reused across iterations as documented.
        ok = unsafe { Process32NextW(snapshot.raw(), &mut entry) }.is_ok();
    }

    Ok(out)
}

/// Gather the details for a single process.
///
/// Never fails: a process that exits mid-enumeration, or that we cannot open, still yields a
/// usable snapshot with the fields we could read marked as absent.
fn build_snapshot(pid: u32, parent_pid: u32, name: String) -> ProcessSnapshot {
    let handle = open_for_query(pid);

    let (image_path, cmdline, cmdline_denied) = match &handle {
        Some(h) => {
            let path = query_image_path(h).ok();
            let (cmd, denied) = match query_command_line(h) {
                Ok(c) => (c, false),
                Err(e) if e.is_access_denied() => (None, true),
                Err(_) => (None, false),
            };
            (path, cmd, denied)
        }
        None => (None, None, true),
    };

    let created_filetime = query_creation_time(pid);

    ProcessSnapshot {
        pid,
        parent_pid,
        name,
        image_path,
        cmdline,
        created_filetime,
        session_id: query_session_id(pid),
        user_sid: None,
        cmdline_denied,
    }
}

/// Open a process with the minimum access needed to read its image path and command line.
pub fn open_for_query(pid: u32) -> Option<OwnedHandle> {
    // Safety: OpenProcess with limited-information access is the documented minimum for
    // QueryFullProcessImageNameW. A failure (accessed denied, or the process exited) is
    // returned as None rather than being treated as fatal.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    match h {
        Ok(h) if !h.is_invalid() => Some(OwnedHandle(h)),
        _ => None,
    }
}

/// Read a process's full image path.
pub fn query_image_path(handle: &OwnedHandle) -> Result<String, WinError> {
    let mut buf = vec![0u16; MAX_PATH_UNITS];
    let mut len = buf.len() as u32;

    // Safety: `buf` has room for `len` UTF-16 units and `len` describes it. The API writes
    // at most `len` units and updates `len` to the count written, excluding the terminator.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            handle.raw(),
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };

    if ok.is_err() {
        return Err(WinError::last("QueryFullProcessImageNameW"));
    }

    buf.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buf))
}

/// Read a process's creation time as a `FILETIME` value, or 0 when unavailable.
///
/// Used together with the pid to form an identity that survives pid reuse.
fn query_creation_time(pid: u32) -> u64 {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetProcessTimes, PROCESS_QUERY_LIMITED_INFORMATION};

    // Safety: opening for limited information and querying times needs no more access than
    // that. Every failure path returns 0, which the identity type treats as "unknown".
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return 0;
        };
        let handle = OwnedHandle(h);
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if GetProcessTimes(
            handle.raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
        .is_err()
        {
            return 0;
        }
        filetime_to_u64(creation)
    }
}

/// Read a process's command line, parsed from the PEB.
///
/// Uses `NtQueryInformationProcess` with `ProcessCommandLineInformation`, which is the
/// documented NT-level route to another process's command line and requires only
/// `PROCESS_QUERY_LIMITED_INFORMATION`.
///
/// # Why this is acceptable here
///
/// Reading the *command line* through this API is a supported query class; it is not
/// arbitrary memory scraping, and it does not read the process's working directory or
/// environment. Guardian deliberately does **not** read another process's current directory
/// (that would require PEB parameter parsing, which is undocumented and version-fragile);
/// project directories come from each agent's own local state files instead, where the agent
/// itself recorded them.
pub fn query_command_line(handle: &OwnedHandle) -> Result<Option<String>, WinError> {
    // Pseudo-class index for ProcessCommandLineInformation, a documented NT information
    // class. It is a plain u32 at the ABI level; the `windows` crate does not surface this
    // particular class, so it is declared here with its real signature.
    const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;

    let proc = {
        // Safety: loading an already-loaded system module returns its handle. ntdll.dll is
        // mapped into every process, so this cannot fail in practice.
        let module = unsafe {
            windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!("ntdll.dll"))
        };
        match module {
            Ok(m) => {
                // Safety: the symbol name is NUL-terminated and the module handle is valid.
                unsafe {
                    windows::Win32::System::LibraryLoader::GetProcAddress(
                        m,
                        windows::core::s!("NtQueryInformationProcess"),
                    )
                }
            }
            Err(_) => None,
        }
    };

    let Some(proc) = proc else {
        return Ok(None);
    };
    // Safety: the symbol, if present, has this signature by definition.
    let query: NtQueryInformationProcessFn = unsafe { std::mem::transmute(proc) };

    // First call sizes the buffer.
    let mut needed: u32 = 0;
    // Safety: a null buffer with size 0 is the documented way to query the required size.
    let status = unsafe {
        query(
            handle.raw(),
            PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };

    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) indicates the size query worked.
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
    const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;

    if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
        if status == 0 && needed == 0 {
            return Ok(None);
        }
        if status < 0 {
            // Access denied and friends: report as a denial so the detector can tell the
            // difference between "no command line" and "not allowed to look".
            return Err(WinError::AccessDenied {
                operation: "NtQueryInformationProcess",
            });
        }
    }

    if needed == 0 {
        return Ok(None);
    }
    if needed as usize > MAX_PATH_UNITS * 2 {
        return Err(WinError::Invalid {
            context: "NtQueryInformationProcess",
            detail: format!("command line buffer of {needed} bytes exceeds the limit"),
        });
    }

    // UNICODE_STRING is {u16 length, u16 max_length, *mut u16 buffer} and is followed
    // in-place by the string data.
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    // Allocate with a little slack: the size can grow between the two calls.
    let mut buf = vec![0u8; needed as usize + 64];
    let mut returned: u32 = 0;

    // Safety: `buf` is at least `needed` bytes, which is what the previous call asked for.
    let status = unsafe {
        query(
            handle.raw(),
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            buf.len() as u32,
            &mut returned,
        )
    };

    if status < 0 {
        return Err(WinError::AccessDenied {
            operation: "NtQueryInformationProcess",
        });
    }

    if buf.len() < std::mem::size_of::<UnicodeString>() {
        return Ok(None);
    }

    // Safety: `buf` is at least the size of a UNICODE_STRING and is properly aligned
    // because Vec<u8> allocations are at least 8-byte aligned for sizes this large.
    let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
    if us.buffer.is_null() || us.length == 0 {
        return Ok(None);
    }

    let units = us.length as usize / 2;
    if units == 0 {
        return Ok(None);
    }

    // The buffer pointer points into `buf` (the API writes the string immediately after the
    // structure), so validate that before dereferencing rather than assuming.
    let base = buf.as_ptr() as usize;
    let ptr = us.buffer as usize;
    if ptr < base || ptr + us.length as usize > base + buf.len() || (ptr - base) % 2 != 0 {
        return Err(WinError::Invalid {
            context: "NtQueryInformationProcess",
            detail: "returned command-line pointer is outside the supplied buffer".into(),
        });
    }

    // Safety: bounds were validated immediately above.
    let slice = unsafe { std::slice::from_raw_parts(us.buffer, units) };
    let text = String::from_utf16_lossy(slice);
    let trimmed = text.trim_end_matches('\0');

    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// The current process id.
pub fn current_pid() -> u32 {
    // Safety: GetCurrentProcessId takes no arguments and always succeeds.
    unsafe { GetCurrentProcessId() }
}

/// Best-effort Windows session id for a process, or 0 when unknown.
fn query_session_id(pid: u32) -> u32 {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // Safety: `session` is a valid out-parameter.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut session) };
    if ok.is_ok() {
        session
    } else {
        0
    }
}

/// Whether a process is still running.
pub fn process_alive(pid: u32, expected_created: u64) -> bool {
    let Some(h) = open_for_query(pid) else {
        return false;
    };
    if expected_created == 0 {
        return true;
    }
    // Verify creation time so a reused pid is not mistaken for the original process.
    let actual = query_creation_time(pid);
    let _ = &h;
    actual == expected_created
}

/// Build a parent -> children index from a snapshot list.
///
/// Returned as a map so the detector can walk ancestry without rescanning the whole list for
/// every candidate.
pub fn child_index(processes: &[ProcessSnapshot]) -> HashMap<u32, Vec<u32>> {
    let mut index: HashMap<u32, Vec<u32>> = HashMap::with_capacity(processes.len());
    for p in processes {
        if p.parent_pid != 0 && p.parent_pid != p.pid {
            index.entry(p.parent_pid).or_default().push(p.pid);
        }
    }
    index
}

/// Build a pid -> snapshot index.
pub fn pid_index(processes: &[ProcessSnapshot]) -> HashMap<u32, usize> {
    processes
        .iter()
        .enumerate()
        .map(|(i, p)| (p.pid, i))
        .collect()
}

/// The executable path of the running Guardian binary, used for self-exclusion.
pub fn current_image_path() -> Result<String, WinError> {
    let pid = current_pid();
    let handle = open_for_query(pid).ok_or(WinError::AccessDenied {
        operation: "open self",
    })?;
    query_image_path(&handle)
}

/// Resolve the long form of a path, following reparse points.
///
/// Used when validating operator-supplied paths: a config value that points at a symlink
/// must be resolved before it is trusted for a privileged write.
pub fn canonicalize_path(path: &str) -> Result<String, WinError> {
    use windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let wide = WideString::new(path);
    // Safety: `wide` is a valid NUL-terminated string. Opening with no access rights and
    // FILE_FLAG_BACKUP_SEMANTICS permits directories without requiring read permission.
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    let handle = match handle {
        Ok(h) if !h.is_invalid() => OwnedHandle(h),
        _ => return Err(WinError::last("CreateFileW")),
    };

    let mut buf = vec![0u16; MAX_PATH_UNITS];
    // Safety: `buf` has room for the requested number of units; flags 0 is the documented
    // "return the normalized path without a \?\ prefix" request handled by the caller.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            handle.raw(),
            &mut buf,
            windows::Win32::Storage::FileSystem::GETFINALPATHNAMEBYHANDLE_FLAGS(0),
        )
    };
    if len == 0 {
        return Err(WinError::last("GetFinalPathNameByHandleW"));
    }
    if len as usize > buf.len() {
        // The call needed more room than the maximum we accept.
        return Err(WinError::BufferTooSmall {
            operation: "GetFinalPathNameByHandleW",
            needed: len as usize,
            had: buf.len(),
        });
    }

    let text = String::from_utf16_lossy(&buf[..len as usize]);
    // The API returns a \\?\ prefixed path; strip it for display consistency while keeping
    // the fact that resolution happened.
    Ok(text.strip_prefix(r"\\?\").unwrap_or(&text).to_string())
}

/// A `MAX_PATH`-sized wide buffer, for APIs that take one directly.
pub fn max_path_buffer() -> Vec<u16> {
    vec![0u16; MAX_PATH as usize + 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_returns_our_own_processes_and_excludes_self() {
        let list = enumerate_processes().expect("enumeration must work without elevation");
        assert!(!list.is_empty(), "a running system has processes");

        let self_pid = current_pid();
        assert!(
            !list.iter().any(|p| p.pid == self_pid),
            "the enumerator must exclude itself"
        );

        // The test harness is running, so its image should appear somewhere in the tree.
        let has_test_harness = list.iter().any(|p| {
            p.name.to_ascii_lowercase().contains("guardian_win")
                || p.name.to_ascii_lowercase().contains("cargo")
                || p.name.to_ascii_lowercase().ends_with(".exe")
        });
        assert!(
            has_test_harness,
            "expected at least one exe in the process list"
        );
    }

    #[test]
    fn every_snapshot_has_a_namespaced_identity() {
        let list = enumerate_processes().unwrap();
        for p in &list {
            assert!(p.pid != 0, "idle process must be excluded");
            assert!(!p.name.is_empty(), "pid {} has no image name", p.pid);
            // Identity must be derivable even when creation time is unavailable.
            let id = p.identity();
            assert_eq!(id.pid, p.pid);
        }
    }

    #[test]
    fn own_image_path_is_readable_and_exists() {
        let path = current_image_path().expect("we can always read our own image path");
        assert!(path.to_ascii_lowercase().ends_with(".exe"), "got: {path}");
        assert!(
            std::path::Path::new(&path).exists(),
            "our own image path must exist on disk: {path}"
        );
    }

    #[test]
    fn own_command_line_is_readable() {
        let handle = open_for_query(current_pid()).expect("can open self");
        let cmd = query_command_line(&handle).expect("can read our own command line");
        // The test binary is invoked by cargo, so there should be something here. Absence
        // is not a failure (some harnesses spawn with an empty command line), but if a
        // value is present it must be non-empty.
        if let Some(c) = cmd {
            assert!(!c.is_empty());
        }
    }

    #[test]
    fn opening_a_nonexistent_pid_fails_cleanly() {
        // pid 0xFFFF_FFF0 is not a real process; this must not panic or hang.
        assert!(open_for_query(0xFFFF_FFF0).is_none());
        assert!(!process_alive(0xFFFF_FFF0, 0));
    }

    #[test]
    fn pid_reuse_is_detected_via_creation_time() {
        // Our own process is alive with its real creation time, but not with a different
        // one. This is the check that stops a recycled pid from being treated as the
        // original agent process.
        let pid = current_pid();
        let real = query_creation_time(pid);
        assert!(
            real > 0,
            "creation time must be readable for our own process"
        );
        assert!(
            process_alive(pid, real),
            "we are alive with our real creation time"
        );
        assert!(
            !process_alive(pid, real.wrapping_add(1)),
            "a mismatched creation time must read as not alive"
        );
        // A zero creation time means "unknown", so liveness falls back to open success.
        assert!(process_alive(pid, 0));
    }

    #[test]
    fn child_index_groups_children_under_parents() {
        let procs = vec![
            snapshot(1, 0, "a.exe"),
            snapshot(2, 1, "b.exe"),
            snapshot(3, 1, "c.exe"),
            snapshot(4, 2, "d.exe"),
        ];
        let idx = child_index(&procs);
        let mut kids = idx.get(&1).cloned().unwrap_or_default();
        kids.sort_unstable();
        assert_eq!(kids, vec![2, 3]);
        assert_eq!(idx.get(&2).cloned().unwrap_or_default(), vec![4]);
        assert!(!idx.contains_key(&4), "a leaf has no children");
    }

    #[test]
    fn child_index_ignores_self_parenting_and_pid_zero() {
        // A malformed parent relationship must not create a cycle in the graph.
        let procs = vec![snapshot(1, 1, "self.exe"), snapshot(2, 0, "orphan.exe")];
        let idx = child_index(&procs);
        assert!(idx.is_empty(), "neither entry may produce a child edge");
    }

    #[test]
    fn pid_index_maps_every_process() {
        let procs = vec![snapshot(10, 1, "a.exe"), snapshot(20, 1, "b.exe")];
        let idx = pid_index(&procs);
        assert_eq!(idx.get(&10), Some(&0));
        assert_eq!(idx.get(&20), Some(&1));
        assert_eq!(idx.get(&30), None);
    }

    #[test]
    fn canonicalize_resolves_a_real_path() {
        let exe = current_image_path().unwrap();
        let resolved = canonicalize_path(&exe).expect("our own path must resolve");
        assert!(
            !resolved.starts_with(r"\\?\"),
            "the prefix should be stripped"
        );
        assert!(resolved.to_ascii_lowercase().ends_with(".exe"));
    }

    #[test]
    fn canonicalize_reports_missing_paths_cleanly() {
        let err =
            canonicalize_path(r"C:\definitely-not-a-real-path-8f3a2b9c\file.txt").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    fn snapshot(pid: u32, parent: u32, name: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            parent_pid: parent,
            name: name.into(),
            image_path: None,
            cmdline: None,
            created_filetime: 0,
            session_id: 1,
            user_sid: None,
            cmdline_denied: false,
        }
    }
}
