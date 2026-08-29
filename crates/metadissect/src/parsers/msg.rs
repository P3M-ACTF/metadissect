//! Outlook .msg (OLE CFBF / MAPI). Extracts common properties; not full MAPI parity.

use crate::types::{Field, Section};
use cfb::CompoundFile;
use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Well-known MAPI property IDs we surface when present as `__substg1.0_*` streams.
const PROP_SUBJECT: u16 = 0x0037;
const PROP_SENDER_NAME: u16 = 0x0C1A;
const PROP_SENDER_EMAIL: u16 = 0x0C1F;
const PROP_SENT_REPR_NAME: u16 = 0x0042;
const PROP_SENT_REPR_EMAIL: u16 = 0x0065;
const PROP_DISPLAY_TO: u16 = 0x0E04;
const PROP_DISPLAY_CC: u16 = 0x0E03;
const PROP_DISPLAY_BCC: u16 = 0x0E02;
const PROP_MESSAGE_CLASS: u16 = 0x001A;
const PROP_CLIENT_SUBMIT: u16 = 0x0039;
const PROP_DELIVERY_TIME: u16 = 0x0E06;
const PROP_INTERNET_MSG_ID: u16 = 0x1035;
const PROP_CONVERSATION_TOPIC: u16 = 0x0070;
const PROP_TRANSPORT_HEADERS: u16 = 0x007D;
const PROP_BODY: u16 = 0x1000;
const PROP_ATTACH_FILENAME: u16 = 0x3704;
const PROP_ATTACH_LONG_FILENAME: u16 = 0x3707;
const PROP_ATTACH_MIME: u16 = 0x370E;
const PROP_ATTACH_CONTENT_ID: u16 = 0x3712;

const PT_STRING8: u16 = 0x001E;
const PT_UNICODE: u16 = 0x001F;
const PT_SYSTIME: u16 = 0x0040;
const PT_BINARY: u16 = 0x0102;

pub fn looks_like_msg(data: &[u8]) -> bool {
    if !data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return false;
    }
    let Ok(cfb) = CompoundFile::open(Cursor::new(data)) else {
        return false;
    };
    stream_names(&cfb).iter().any(|n| {
        n.contains("__properties_version1.0")
            || n.contains("__substg1.0_")
            || n.eq_ignore_ascii_case("Message") // rare alternate layout
    })
}

pub fn parse_msg(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut cfb = match CompoundFile::open(Cursor::new(data)) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(format!("MSG/OLE open failed: {e}"));
            return (Vec::new(), warnings);
        }
    };

    let names = stream_names(&cfb);
    if !names
        .iter()
        .any(|n| n.contains("__substg1.0_") || n.contains("__properties_version1.0"))
    {
        warnings.push(
            "OLE Compound File opened but no MSG/MAPI streams (__substg1.0_ / __properties) found."
                .into(),
        );
        return (Vec::new(), warnings);
    }

    warnings.push(
        "MSG: only a common MAPI property subset is decoded (Subject/From/To/Cc/dates/Message-ID/attachments). Full property set and named properties are not fully decoded."
            .into(),
    );

    let mut summary = Section::new("msg", "Outlook MSG (MAPI)");
    summary.add("Size", data.len().to_string(), Some("MSG"));
    summary.add("StreamCount", names.len().to_string(), Some("MSG"));

    let mut headers = Section::new("msg-headers", "MSG message properties");
    let mut body_preview: Option<String> = None;
    let mut transport: Option<String> = None;

    // Root-level substg streams (not under __attach_ / __recip_ / __nameid_)
    for path in names.iter().filter(|n| is_root_substg(n)) {
        if let Some((prop_id, prop_type)) = parse_substg_name(path) {
            let bytes = read_stream(&mut cfb, path);
            if let Some(value) = decode_property(prop_id, prop_type, &bytes) {
                match prop_id {
                    PROP_BODY => {
                        body_preview = Some(value.chars().take(400).collect());
                    }
                    PROP_TRANSPORT_HEADERS => {
                        transport = Some(value);
                    }
                    _ => {
                        if let Some(key) = known_prop_name(prop_id) {
                            headers.fields.push(
                                Field::new(key, value).with_namespace("MSG").with_raw(
                                    serde_json::json!({
                                        "prop_id": format!("0x{prop_id:04X}"),
                                        "prop_type": format!("0x{prop_type:04X}"),
                                        "stream": path,
                                    }),
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    let mut sections = vec![summary];
    if !headers.is_empty() {
        sections.push(headers);
    }

    if let Some(th) = transport {
        let mut sec = Section::new("msg-transport-headers", "MSG transport headers");
        // Parse a few RFC822-like lines when present
        for (k, v) in parse_simple_headers(&th) {
            if matches!(
                k.as_str(),
                "From" | "To" | "Cc" | "Subject" | "Date" | "Message-ID" | "MIME-Version"
            ) {
                sec.fields
                    .push(Field::new(format!("Transport-{k}"), v).with_namespace("MSG:Transport"));
            }
        }
        sec.add(
            "Preview",
            th.chars().take(500).collect::<String>(),
            Some("MSG:Transport"),
        );
        sections.push(sec);
    }

    if let Some(preview) = body_preview {
        let mut b = Section::new("msg-body", "MSG body");
        b.add("Preview", preview, Some("MSG"));
        sections.push(b);
    }

    // Attachments
    let attach_dirs: Vec<String> = names
        .iter()
        .filter_map(|n| {
            // paths like "/__attach_version1.0_#00000000/__substg1.0_..."
            let trim = n.trim_start_matches('/');
            if let Some(rest) = trim.strip_prefix("__attach_version1.0_") {
                let folder = rest.split('/').next().unwrap_or("");
                Some(format!("/__attach_version1.0_{folder}"))
            } else {
                None
            }
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    if !attach_dirs.is_empty() {
        let mut att = Section::new("msg-attachments", "MSG attachments");
        att.add("Count", attach_dirs.len().to_string(), Some("MSG"));
        for (i, dir) in attach_dirs.iter().enumerate() {
            let mut name = None;
            let mut mime = None;
            let mut cid = None;
            for path in names
                .iter()
                .filter(|n| n.starts_with(dir.as_str()) || n.starts_with(&format!("{dir}/")))
            {
                if let Some((prop_id, prop_type)) = parse_substg_name(path) {
                    let bytes = read_stream(&mut cfb, path);
                    if let Some(value) = decode_property(prop_id, prop_type, &bytes) {
                        match prop_id {
                            PROP_ATTACH_LONG_FILENAME | PROP_ATTACH_FILENAME => {
                                if name.is_none() || prop_id == PROP_ATTACH_LONG_FILENAME {
                                    name = Some(value);
                                }
                            }
                            PROP_ATTACH_MIME => mime = Some(value),
                            PROP_ATTACH_CONTENT_ID => cid = Some(value),
                            _ => {}
                        }
                    }
                }
            }
            let label = name.unwrap_or_else(|| format!("attachment-{i}"));
            att.fields.push(
                Field::new(format!("Attachment{i}"), label.clone())
                    .with_namespace("MSG")
                    .with_raw(serde_json::json!({
                        "filename": label,
                        "mime": mime,
                        "content_id": cid,
                        "storage": dir,
                    })),
            );
        }
        sections.push(att);
    }

    (sections, warnings)
}

fn stream_names<T: Read + std::io::Seek>(cfb: &CompoundFile<T>) -> Vec<String> {
    let mut out = Vec::new();
    walk_storage(cfb, "/", &mut out);
    out
}

fn walk_storage<T: Read + std::io::Seek>(cfb: &CompoundFile<T>, path: &str, out: &mut Vec<String>) {
    let entries: Vec<_> = match cfb.read_storage(path) {
        Ok(iter) => iter
            .map(|e| (e.name().to_string(), e.is_stream(), e.is_storage()))
            .collect(),
        Err(_) => return,
    };
    for (name, is_stream, is_storage) in entries {
        let child = if path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        };
        if is_stream {
            out.push(child);
        } else if is_storage {
            walk_storage(cfb, &child, out);
        }
    }
}

fn is_root_substg(path: &str) -> bool {
    let trim = path.trim_start_matches('/');
    trim.starts_with("__substg1.0_")
        && !trim.contains("__attach_")
        && !trim.contains("__recip_")
        && !trim.contains("__nameid_")
}

fn parse_substg_name(path: &str) -> Option<(u16, u16)> {
    let name = path.rsplit('/').next()?;
    let rest = name.strip_prefix("__substg1.0_")?;
    if rest.len() < 8 {
        return None;
    }
    let prop_id = u16::from_str_radix(&rest[0..4], 16).ok()?;
    let prop_type = u16::from_str_radix(&rest[4..8], 16).ok()?;
    Some((prop_id, prop_type))
}

fn read_stream<T: Read + std::io::Seek>(cfb: &mut CompoundFile<T>, path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(mut s) = cfb.open_stream(path) {
        let _ = s.read_to_end(&mut buf);
    }
    buf
}

fn decode_property(prop_id: u16, prop_type: u16, bytes: &[u8]) -> Option<String> {
    match prop_type {
        PT_UNICODE => Some(decode_utf16le(bytes)),
        PT_STRING8 => Some(
            String::from_utf8_lossy(bytes)
                .trim_end_matches('\0')
                .to_string(),
        ),
        PT_SYSTIME => decode_filetime(bytes),
        PT_BINARY if prop_id == PROP_INTERNET_MSG_ID => {
            // sometimes stored as binary ascii
            Some(
                String::from_utf8_lossy(bytes)
                    .trim_end_matches('\0')
                    .to_string(),
            )
        }
        _ => {
            // Some builds store Message-ID as unicode under 0x1035
            if matches!(prop_id, PROP_SUBJECT | PROP_INTERNET_MSG_ID | PROP_BODY)
                && bytes.len() >= 2
                && bytes.len().is_multiple_of(2)
            {
                Some(decode_utf16le(bytes))
            } else {
                None
            }
        }
    }
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let v = u16::from_le_bytes([chunk[0], chunk[1]]);
        if v == 0 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

fn decode_filetime(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let ticks = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    // FILETIME: 100-ns intervals since 1601-01-01
    const EPOCH_DIFF: u64 = 11_644_473_600; // seconds 1601→1970
    let secs = ticks / 10_000_000;
    if secs < EPOCH_DIFF {
        return Some(format!("FILETIME:{ticks}"));
    }
    let unix = secs - EPOCH_DIFF;
    let t = UNIX_EPOCH + Duration::from_secs(unix);
    Some(format_system_time(t))
}

fn format_system_time(t: SystemTime) -> String {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs() as i64;
            // Format as UTC ISO without chrono dependency quirks — use chrono if available
            use chrono::{TimeZone, Utc};
            Utc.timestamp_opt(secs, 0)
                .single()
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| format!("{secs}"))
        }
        Err(_) => "invalid-time".into(),
    }
}

fn known_prop_name(prop_id: u16) -> Option<&'static str> {
    Some(match prop_id {
        PROP_SUBJECT => "Subject",
        PROP_SENDER_NAME => "From",
        PROP_SENDER_EMAIL => "SenderEmail",
        PROP_SENT_REPR_NAME => "SentRepresentingName",
        PROP_SENT_REPR_EMAIL => "SentRepresentingEmail",
        PROP_DISPLAY_TO => "To",
        PROP_DISPLAY_CC => "Cc",
        PROP_DISPLAY_BCC => "Bcc",
        PROP_MESSAGE_CLASS => "MessageClass",
        PROP_CLIENT_SUBMIT => "ClientSubmitTime",
        PROP_DELIVERY_TIME => "MessageDeliveryTime",
        PROP_INTERNET_MSG_ID => "Message-ID",
        PROP_CONVERSATION_TOPIC => "ConversationTopic",
        _ => return None,
    })
}

fn parse_simple_headers(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in block.replace("\r\n", "\n").lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, ref mut v)) = current {
                v.push(' ');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            current = Some((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if let Some(prev) = current {
        out.push(prev);
    }
    out
}

/// Build a minimal synthetic .msg (CFBF) with Subject/From/To/Message-ID/date.
pub fn minimal_msg_fixture() -> Vec<u8> {
    let mut cfb = CompoundFile::create(Cursor::new(Vec::new())).expect("create cfb");
    // Marker stream used by Outlook MSG layout
    write_utf16_stream(&mut cfb, "/__substg1.0_001A001F", "IPM.Note"); // MessageClass
    write_utf16_stream(&mut cfb, "/__substg1.0_0037001F", "Fixture subject");
    write_utf16_stream(&mut cfb, "/__substg1.0_0C1A001F", "Alice Sender");
    write_utf16_stream(&mut cfb, "/__substg1.0_0C1F001F", "alice@example.com");
    write_utf16_stream(&mut cfb, "/__substg1.0_0E04001F", "bob@example.com");
    write_utf16_stream(&mut cfb, "/__substg1.0_0E03001F", "carol@example.com");
    write_utf16_stream(
        &mut cfb,
        "/__substg1.0_1035001F",
        "<fixture@metadissect.local>",
    );
    // FILETIME for 2024-06-15 12:00:00 UTC
    // unix 1718452800 + 11644473600 = 13362926400 seconds → * 10_000_000
    let ticks: u64 = (1_718_452_800u64 + 11_644_473_600) * 10_000_000;
    write_bytes_stream(&mut cfb, "/__substg1.0_00390040", &ticks.to_le_bytes());
    write_utf16_stream(&mut cfb, "/__substg1.0_1000001F", "Hello from MSG fixture.");

    // Empty properties stream (presence helps detection)
    write_bytes_stream(&mut cfb, "/__properties_version1.0", &[0u8; 32]);

    // One attachment storage
    cfb.create_storage("/__attach_version1.0_#00000000")
        .expect("attach storage");
    write_utf16_stream(
        &mut cfb,
        "/__attach_version1.0_#00000000/__substg1.0_3707001F",
        "readme.txt",
    );
    write_utf16_stream(
        &mut cfb,
        "/__attach_version1.0_#00000000/__substg1.0_370E001F",
        "text/plain",
    );

    cfb.into_inner().into_inner()
}

fn write_utf16_stream(cfb: &mut CompoundFile<Cursor<Vec<u8>>>, path: &str, text: &str) {
    let mut bytes = Vec::new();
    for u in text.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    write_bytes_stream(cfb, path, &bytes);
}

fn write_bytes_stream(cfb: &mut CompoundFile<Cursor<Vec<u8>>>, path: &str, bytes: &[u8]) {
    // create parent storages if needed — root streams are fine
    let mut stream = cfb.create_stream(path).unwrap_or_else(|_| {
        // may already exist in retries
        cfb.open_stream(path).expect("open stream")
    });
    use std::io::Write;
    stream.write_all(bytes).expect("write stream");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_extracts_core_fields() {
        let data = minimal_msg_fixture();
        assert!(looks_like_msg(&data));
        let (secs, warns) = parse_msg(&data);
        assert!(warns
            .iter()
            .any(|w| w.contains("subset") || w.contains("not fully")));
        let blob: String = secs
            .iter()
            .flat_map(|s| s.fields.iter())
            .map(|f| format!("{}={}", f.key, f.value))
            .collect::<Vec<_>>()
            .join("|");
        assert!(blob.contains("Subject=Fixture subject"), "{blob}");
        assert!(blob.contains("From=Alice Sender"), "{blob}");
        assert!(blob.contains("To=bob@example.com"), "{blob}");
        assert!(blob.contains("Cc=carol@example.com"), "{blob}");
        assert!(blob.contains("Message-ID="), "{blob}");
        assert!(
            secs.iter().any(|s| s.id == "msg-attachments"
                && s.fields.iter().any(|f| f.value.contains("readme.txt"))),
            "attachments missing: {blob}"
        );
    }
}
