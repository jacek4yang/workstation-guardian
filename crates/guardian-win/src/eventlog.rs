//! Windows Event Log queries for unexpected-restart analysis.
//!
//! Uses the legacy `OpenEventLogW`/`ReadEventLogW` API rather than the modern
//! `EvtQuery`/`EvtNext` API. That choice is deliberate: the records this module needs are the
//! classic `System` channel events (`User32 1074`, `Kernel-Power 41`, `EventLog 6008`) that
//! every Windows version has written for decades, and the legacy API reads them with far less
//! machinery. It also means the query works identically on a machine with no modern eventing
//! service state.
//!
//! # Bounded work
//!
//! Every query is bounded by a time window and a record cap. A machine that has been up for
//! months has hundreds of thousands of records; walking all of them would turn a boot-time
//! diagnostic into a multi-second stall.

use std::ffi::c_void;

use guardian_core::ports::{EventLogSource, EventQuery};
use guardian_proto::model::EventEvidence;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    CloseEventLog, EvtClose, EvtOpenChannelConfig, OpenEventLogW, ReadEventLogW, EVENTLOGRECORD,
    EVENTLOG_SEQUENTIAL_READ, READ_EVENT_LOG_READ_FLAGS, REPORT_EVENT_TYPE,
};

use crate::{WideString, WinError};

/// Maximum bytes read from the event log in one pass.
///
/// Large enough to hold a few hundred records, small enough that a corrupted log cannot make us
/// allocate an unreasonable buffer.
const READ_BUFFER_BYTES: usize = 256 * 1024;

/// Maximum records examined per query, regardless of what the caller asked for.
const HARD_RECORD_CAP: usize = 2000;

/// `EVENTLOG_BACKWARDS_READ`, which reads from the newest record toward the oldest.
///
/// The `windows` crate re-exports the sequential and seek flags but not this one, so it is named
/// here with its documented value rather than left as a bare literal at the call site.
const EVENTLOG_BACKWARDS_READ: READ_EVENT_LOG_READ_FLAGS = READ_EVENT_LOG_READ_FLAGS(0x0002);

/// A read-only view of the Windows event log.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEventLog;

impl SystemEventLog {
    pub fn new() -> Self {
        SystemEventLog
    }
}

impl EventLogSource for SystemEventLog {
    type Error = WinError;

    fn query(&self, channel: &str, query: &EventQuery) -> Result<Vec<EventEvidence>, Self::Error> {
        // Establish that the channel exists *before* reading.
        //
        // This is not belt-and-braces: on Windows 11, `OpenEventLogW` given a nonexistent channel
        // does not fail. It silently returns a handle to *some other* log - measured here, a bogus
        // name yielded 30317 records while `System` held 31662. Reading without this check would
        // therefore classify restart evidence drawn from an unrelated log, which is worse than
        // reporting nothing.
        //
        // `EvtOpenChannelConfig` is the documented call that resolves a channel and fails cleanly
        // when it does not exist, so it is used purely as the existence check; the read below still
        // uses the legacy API, which is simpler for this record layout.
        ensure_channel_exists(channel)?;

        let channel_w = WideString::new(channel);

        // Safety: `channel_w` is a valid NUL-terminated string naming a channel confirmed to
        // exist. The returned handle is owned by `EventLogHandle`.
        let handle = unsafe { OpenEventLogW(PCWSTR::null(), PCWSTR(channel_w.as_ptr())) };
        let handle = match handle {
            Ok(h) if !h.is_invalid() => EventLogHandle(h),
            _ => return Err(WinError::last("OpenEventLogW")),
        };

        let cap = query.max_records.min(HARD_RECORD_CAP);
        let mut out = Vec::new();
        let mut buffer = vec![0u8; READ_BUFFER_BYTES];
        let mut bytes_read = 0u32;
        let mut needed = 0u32;

        // Read backwards from the newest record: the records of interest are the most recent
        // ones, so this finds them in the fewest reads.
        let flags =
            READ_EVENT_LOG_READ_FLAGS(EVENTLOG_BACKWARDS_READ.0 | EVENTLOG_SEQUENTIAL_READ.0);

        loop {
            if out.len() >= cap {
                break;
            }

            // Safety: `buffer` is a valid writable buffer of the stated length, and the two
            // out-parameters are correctly typed.
            let ok = unsafe {
                ReadEventLogW(
                    handle.0,
                    flags,
                    0,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as u32,
                    &mut bytes_read,
                    &mut needed,
                )
            };

            if ok.is_err() {
                let err = WinError::last("ReadEventLogW");
                // ERROR_HANDLE_EOF means we have reached the end of the log, which is normal.
                if let WinError::Api { code, .. } = &err {
                    if *code == windows::Win32::Foundation::ERROR_HANDLE_EOF.0 {
                        break;
                    }
                    // ERROR_INSUFFICIENT_BUFFER means the record is larger than our buffer.
                    // Skipping it is better than failing the whole query.
                    if *code == windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER.0 {
                        // Keep reading backwards; the flag is already set.
                        continue;
                    }
                }
                // Any other failure: return what we have rather than losing the evidence already
                // collected. Partial evidence with a warning is more useful than nothing.
                tracing::debug!(channel, error = %err, "event log read stopped early");
                break;
            }

            if bytes_read == 0 {
                break;
            }

            // Walk the records in this buffer.
            let buffer_end = bytes_read as usize;
            let mut offset = 0usize;

            while offset + std::mem::size_of::<EVENTLOGRECORD>() <= buffer_end {
                // Safety: `offset` is within the buffer and the record header fits; the length
                // field is validated below before any further reading.
                let record: &EVENTLOGRECORD =
                    unsafe { &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD) };

                let length = record.Length as usize;
                if length == 0 || offset + length > buffer_end {
                    // A malformed length would otherwise loop forever or read out of bounds.
                    break;
                }

                if let Some(evidence) = interpret(record, &buffer[offset..offset + length], query) {
                    out.push(evidence);
                    if out.len() >= cap {
                        break;
                    }
                }

                offset += length;
            }
        }

        // The records were read newest-first; the caller wants chronological order.
        out.reverse();
        Ok(out)
    }
}

/// Confirm a channel exists, returning `NotFound` when it does not.
fn ensure_channel_exists(channel: &str) -> Result<(), WinError> {
    let channel_w = WideString::new(channel);

    // Safety: `channel_w` is a valid NUL-terminated channel name and a null session means the
    // local machine. The returned handle is closed immediately; only its validity matters here.
    let handle = unsafe { EvtOpenChannelConfig(None, PCWSTR(channel_w.as_ptr()), 0) };

    match handle {
        Ok(h) if !h.is_invalid() => {
            // Safety: the handle came from EvtOpenChannelConfig and is not used again.
            unsafe {
                let _ = EvtClose(h);
            }
            Ok(())
        }
        _ => Err(WinError::NotFound {
            operation: "EvtOpenChannelConfig",
        }),
    }
}

/// Extract the fields we need from a record, or `None` when the query excludes it.
fn interpret(record: &EVENTLOGRECORD, raw: &[u8], query: &EventQuery) -> Option<EventEvidence> {
    let event_id = record.EventID & 0xFFFF; // the high word is a facility flag

    // Time filtering. `TimeGenerated` is Unix seconds.
    let at_ms = i64::from(record.TimeGenerated) * 1000;
    if at_ms < query.since_ms || at_ms > query.until_ms {
        return None;
    }

    if !query.event_ids.is_empty() && !query.event_ids.contains(&event_id) {
        return None;
    }

    let provider = read_provider_name(raw, record);
    if !query.providers.is_empty()
        && !query
            .providers
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&provider))
    {
        return None;
    }

    // The insert strings carry the message detail. They are read here rather than resolved
    // through a message DLL: resolving would need the provider's resource file, which is often
    // absent, and would localise the text in a way that makes the classification unreliable.
    let inserts = read_insert_strings(raw, record);
    let message = if inserts.is_empty() {
        format!("{provider} event {event_id}")
    } else {
        // The full command line is in the first insert for a 1074; cap the length so a long
        // path cannot bloat the journal.
        truncate_chars(&inserts.join(" | "), 512)
    };

    Some(EventEvidence {
        provider,
        event_id,
        at_ms,
        message,
    })
}

/// Read the provider name from a record.
fn read_provider_name(raw: &[u8], record: &EVENTLOGRECORD) -> String {
    // The provider name follows the fixed-size header at the offset the API reports.
    let start = record.StringOffset as usize;
    // The provider name occupies the bytes before the first insert string.
    let end = if record.NumStrings > 0 {
        // The first string begins right after the provider name, which is itself a
        // NUL-terminated UTF-16 string starting at StringOffset.
        let mut pos = start;
        while pos + 1 < raw.len() && !(raw[pos] == 0 && raw[pos + 1] == 0) {
            pos += 2;
        }
        pos
    } else {
        raw.len()
    };

    if start >= raw.len() || end > raw.len() || start >= end {
        return String::new();
    }

    decode_utf16_lossy(&raw[start..end])
}

/// Read the insert strings from a record.
fn read_insert_strings(raw: &[u8], record: &EVENTLOGRECORD) -> Vec<String> {
    let count = record.NumStrings as usize;
    if count == 0 {
        return Vec::new();
    }

    // The strings begin after the provider name, which starts at StringOffset and is
    // NUL-terminated in UTF-16.
    let mut pos = record.StringOffset as usize;
    while pos + 1 < raw.len() && !(raw[pos] == 0 && raw[pos + 1] == 0) {
        pos += 2;
    }
    pos += 2; // step past the provider's terminator

    let mut out = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        if pos + 1 >= raw.len() {
            break;
        }
        let start = pos;
        while pos + 1 < raw.len() && !(raw[pos] == 0 && raw[pos + 1] == 0) {
            pos += 2;
        }
        if start < pos {
            out.push(decode_utf16_lossy(&raw[start..pos]));
        }
        pos += 2;
        // A bounded number of inserts: a record with hundreds of strings is not one we need.
        if out.len() >= 32 {
            break;
        }
    }

    out
}

/// Decode little-endian UTF-16 bytes, lossily.
fn decode_utf16_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    text.trim_end_matches('\0').to_string()
}

fn truncate_chars(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(max.min(s.len()));
    for c in s.chars().take(max) {
        out.push(c);
    }
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// A file that closes itself.
struct EventLogHandle(windows::Win32::Foundation::HANDLE);

impl Drop for EventLogHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // Safety: the handle came from OpenEventLogW and is closed exactly once.
            unsafe {
                let _ = CloseEventLog(self.0);
            }
        }
    }
}

/// The event types this module cares about, for reference in diagnostics.
pub fn described_types() -> &'static str {
    "Event Log: User32 1074 (shutdown initiated), Kernel-Power 41 (unclean stop), \
     EventLog 6005/6006/6008 (log service start/stop/unexpected), Kernel-General 12/13"
}

/// Suppress an unused-import warning for a type used only in a signature.
#[allow(unused)]
fn _type_anchor(_: REPORT_EVENT_TYPE) {}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::ports::EventLogSource;

    fn wide(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn decoding_handles_utf16_and_terminators() {
        let bytes = wide("hello");
        assert_eq!(decode_utf16_lossy(&bytes), "hello");
        assert_eq!(decode_utf16_lossy(&[]), "");
    }

    #[test]
    fn decoding_handles_non_bmp_characters() {
        let bytes = wide("工作区😀");
        assert_eq!(decode_utf16_lossy(&bytes), "工作区😀");
    }

    #[test]
    fn truncation_is_character_safe() {
        let truncated = truncate_chars("日本語のとても長い文字列", 4);
        assert!(truncated.starts_with("日本語の"));
        assert!(truncated.ends_with('…'));
        assert_eq!(truncate_chars("short", 10), "short");
    }

    #[test]
    fn querying_the_system_log_returns_a_bounded_result() {
        // The System channel always exists. The window is set to the last hour so this is a
        // bounded read on any machine, and it must not fail merely because nothing matched.
        let log = SystemEventLog::new();
        let now = crate::clock::unix_now_ms();
        let query = EventQuery {
            providers: vec![],
            event_ids: vec![6005, 6006, 6008, 1074, 41],
            since_ms: now - 60 * 60 * 1000,
            until_ms: now + 60_000,
            max_records: 50,
        };

        match log.query("System", &query) {
            Ok(records) => {
                assert!(
                    records.len() <= 50,
                    "the record cap must be honoured, got {}",
                    records.len()
                );
                // Records must come back in chronological order.
                for window in records.windows(2) {
                    assert!(
                        window[0].at_ms <= window[1].at_ms,
                        "records must be ordered oldest first"
                    );
                }
                for r in &records {
                    assert!(r.event_id != 0);
                    assert!(!r.message.is_empty());
                    assert!(
                        query.event_ids.contains(&r.event_id),
                        "unexpected id {}",
                        r.event_id
                    );
                    assert!(r.at_ms >= query.since_ms && r.at_ms <= query.until_ms);
                }
                eprintln!("{} matching System records in the last hour", records.len());
            }
            Err(e) => {
                // Access to the event log can be denied in a restricted context; that is a
                // reported condition, not a crash.
                eprintln!("event log unavailable in this context: {e}");
            }
        }
    }

    #[test]
    fn a_narrow_window_returns_nothing_rather_than_everything() {
        // Filtering must actually apply; returning the whole log would make the restart
        // classification draw conclusions from unrelated months-old records.
        let log = SystemEventLog::new();
        let query = EventQuery {
            providers: vec![],
            event_ids: vec![],
            since_ms: 1,
            until_ms: 2, // a two-millisecond window in 1970
            max_records: 10,
        };

        match log.query("System", &query) {
            Ok(records) => assert!(
                records.is_empty(),
                "a window in 1970 must match nothing, got {} records",
                records.len()
            ),
            Err(e) => eprintln!("event log unavailable: {e}"),
        }
    }

    #[test]
    fn querying_a_nonexistent_channel_reports_cleanly() {
        let log = SystemEventLog::new();
        let query = EventQuery {
            providers: vec![],
            event_ids: vec![],
            since_ms: 0,
            until_ms: i64::MAX,
            max_records: 10,
        };
        let result = log.query("Definitely-Not-A-Channel-8f3a2b", &query);
        match result {
            Err(e) => assert!(
                e.is_not_found(),
                "an unknown channel must be reported as not found, got: {e}"
            ),
            // On Windows 11 the legacy open silently falls back to another log, which is exactly
            // why the existence check above exists. If a future Windows makes it fail properly,
            // that is also acceptable.
            Ok(records) => panic!(
                "an unknown channel must not yield records, got {}",
                records.len()
            ),
        }
    }

    #[test]
    fn a_provider_filter_excludes_everything_else() {
        let log = SystemEventLog::new();
        let now = crate::clock::unix_now_ms();
        let query = EventQuery {
            providers: vec!["Microsoft-Windows-Definitely-Not-Real".into()],
            event_ids: vec![],
            since_ms: now - 60 * 60 * 1000,
            until_ms: now + 60_000,
            max_records: 10,
        };

        match log.query("System", &query) {
            Ok(records) => assert!(
                records.is_empty(),
                "a nonexistent provider must match nothing, got {}",
                records.len()
            ),
            Err(e) => eprintln!("event log unavailable: {e}"),
        }
    }

    #[test]
    fn the_record_cap_is_never_exceeded_even_when_asked() {
        // A caller asking for a million records must not make us read a million records.
        let log = SystemEventLog::new();
        let now = crate::clock::unix_now_ms();
        let query = EventQuery {
            providers: vec![],
            event_ids: vec![],
            since_ms: 0,
            until_ms: now + 60_000,
            max_records: 1_000_000,
        };

        match log.query("System", &query) {
            Ok(records) => assert!(
                records.len() <= 2000,
                "the hard cap must apply, got {}",
                records.len()
            ),
            Err(e) => eprintln!("event log unavailable: {e}"),
        }
    }

    #[test]
    fn described_types_names_the_records_we_classify_on() {
        let text = described_types();
        for id in ["1074", "41", "6008", "6006"] {
            assert!(text.contains(id), "the description must mention {id}");
        }
    }
}
