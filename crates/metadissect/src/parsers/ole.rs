//! Legacy Office OLE CFBF (.doc / .xls / .ppt) — minimal stream + SummaryInformation subset.

use crate::types::{Field, Section};
use cfb::CompoundFile;
use std::io::{Cursor, Read};

/// Property IDs in SummaryInformation (PIDSI_*).
const PID_TITLE: u32 = 0x02;
const PID_SUBJECT: u32 = 0x03;
const PID_AUTHOR: u32 = 0x04;
const PID_KEYWORDS: u32 = 0x05;
const PID_COMMENTS: u32 = 0x06;
const PID_TEMPLATE: u32 = 0x07;
const PID_LAST_AUTHOR: u32 = 0x08;
const PID_REV_NUMBER: u32 = 0x09;
const PID_APP_NAME: u32 = 0x12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyOfficeKind {
    Word,
    Excel,
    PowerPoint,
    Unknown,
}

impl LegacyOfficeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Word => "Word (.doc)",
            Self::Excel => "Excel (.xls)",
            Self::PowerPoint => "PowerPoint (.ppt)",
            Self::Unknown => "OLE/CFBF (legacy Office?)",
        }
    }
}

pub fn parse_legacy_ole(data: &[u8], depth: u8) -> (Vec<Section>, Vec<String>) {
    let mut warnings = vec![
        "Legacy OLE/CFBF: only stream inventory and SummaryInformation subset are decoded; full binary document metadata is not parsed.".into(),
    ];
    let mut cfb = match CompoundFile::open(Cursor::new(data)) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(format!("OLE open failed: {e}"));
            return (Vec::new(), warnings);
        }
    };

    let streams = stream_names(&cfb);
    let kind = detect_kind(&streams);
    let mut root = Section::new("ole-cfbf", "OLE Compound File (legacy Office)");
    root.add("Signature", "D0 CF 11 E0 A1 B1 1A E1", Some("OLE"));
    root.add("Size", data.len().to_string(), Some("OLE"));
    root.add("EmbedDepth", depth.to_string(), Some("OLE"));
    root.add("LegacyType", kind.as_str(), Some("OLE"));
    root.add("StreamCount", streams.len().to_string(), Some("OLE"));

    let mut listing = Section::new("ole-streams", "OLE streams (sample)");
    for name in streams.iter().take(32) {
        listing
            .fields
            .push(Field::new("Stream", name.clone()).with_namespace("OLE"));
    }
    if streams.len() > 32 {
        listing.add("MoreStreams", (streams.len() - 32).to_string(), Some("OLE"));
    }

    let mut sections = vec![root, listing];

    if let Some(summary_path) = streams
        .iter()
        .find(|s| s.ends_with("SummaryInformation") && !s.contains("DocumentSummary"))
        .cloned()
    {
        if let Some(summary) = read_stream(&mut cfb, &summary_path) {
            let props = parse_property_set(&summary);
            if !props.is_empty() {
                let mut sec = Section::new("ole-summary", "SummaryInformation");
                for (pid, val) in props {
                    if let Some(label) = summary_label(pid) {
                        sec.add(label, val, Some("OLE:Summary"));
                    }
                }
                if !sec.is_empty() {
                    sections.push(sec);
                }
            }
        }
    } else {
        warnings.push("SummaryInformation stream not found or unreadable.".into());
    }

    if streams
        .iter()
        .any(|s| s.contains("DocumentSummaryInformation"))
    {
        let mut sec = Section::new("ole-doc-summary", "DocumentSummaryInformation");
        sec.add("Present", "yes", Some("OLE:DocSummary"));
        sections.push(sec);
    }

    (sections, warnings)
}

fn detect_kind(streams: &[String]) -> LegacyOfficeKind {
    let lower: Vec<String> = streams.iter().map(|s| s.to_ascii_lowercase()).collect();
    if lower.iter().any(|s| s.contains("worddocument")) {
        LegacyOfficeKind::Word
    } else if lower.iter().any(|s| s.contains("workbook")) {
        LegacyOfficeKind::Excel
    } else if lower.iter().any(|s| s.contains("powerpoint document")) {
        LegacyOfficeKind::PowerPoint
    } else {
        LegacyOfficeKind::Unknown
    }
}

fn stream_names(cfb: &CompoundFile<Cursor<&[u8]>>) -> Vec<String> {
    let mut out = Vec::new();
    walk_storage(cfb, "/", &mut out);
    out
}

fn walk_storage(cfb: &CompoundFile<Cursor<&[u8]>>, path: &str, out: &mut Vec<String>) {
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

fn read_stream(cfb: &mut CompoundFile<Cursor<&[u8]>>, path: &str) -> Option<Vec<u8>> {
    let mut stream = cfb.open_stream(path).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn summary_label(pid: u32) -> Option<&'static str> {
    match pid {
        PID_TITLE => Some("Title"),
        PID_SUBJECT => Some("Subject"),
        PID_AUTHOR => Some("Author"),
        PID_KEYWORDS => Some("Keywords"),
        PID_COMMENTS => Some("Comments"),
        PID_TEMPLATE => Some("Template"),
        PID_LAST_AUTHOR => Some("LastAuthor"),
        PID_REV_NUMBER => Some("RevNumber"),
        PID_APP_NAME => Some("AppName"),
        _ => None,
    }
}

/// Minimal OLE property set reader (VT_LPSTR / VT_LPWSTR / VT_FILETIME).
fn parse_property_set(data: &[u8]) -> Vec<(u32, String)> {
    if data.len() < 48 {
        return Vec::new();
    }
    let section_count = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
    if section_count == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..section_count.min(4) {
        let base = 28 + i * 20;
        if base + 20 > data.len() {
            break;
        }
        let offset = u32::from_le_bytes([
            data[base + 16],
            data[base + 17],
            data[base + 18],
            data[base + 19],
        ]) as usize;
        out.extend(parse_section(data, offset));
    }
    out
}

fn parse_section(data: &[u8], offset: usize) -> Vec<(u32, String)> {
    if offset + 8 > data.len() {
        return Vec::new();
    }
    let _size = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let prop_count = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]) as usize;
    let mut props = Vec::new();
    for i in 0..prop_count.min(64) {
        let entry = offset + 8 + i * 8;
        if entry + 8 > data.len() {
            break;
        }
        let pid = u32::from_le_bytes([
            data[entry],
            data[entry + 1],
            data[entry + 2],
            data[entry + 3],
        ]);
        let off = u32::from_le_bytes([
            data[entry + 4],
            data[entry + 5],
            data[entry + 6],
            data[entry + 7],
        ]) as usize;
        if let Some(val) = read_typed_value(data, off) {
            props.push((pid, val));
        }
    }
    props
}

fn read_typed_value(data: &[u8], offset: usize) -> Option<String> {
    if offset + 4 > data.len() {
        return None;
    }
    let vt = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    match vt {
        0x1E => read_lpstr(data, offset + 4),            // VT_LPSTR
        0x1F => read_lpwstr(data, offset + 4),           // VT_LPWSTR
        0x0040 => read_filetime(data, offset + 4),       // VT_FILETIME
        0x0042 => read_clipdata_lpstr(data, offset + 4), // VT_CLSID — skip
        _ => None,
    }
}

fn read_lpstr(data: &[u8], offset: usize) -> Option<String> {
    if offset + 4 > data.len() {
        return None;
    }
    let len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let start = offset + 4;
    let end = start.saturating_add(len.saturating_sub(1));
    if end > data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fn read_lpwstr(data: &[u8], offset: usize) -> Option<String> {
    if offset + 4 > data.len() {
        return None;
    }
    let chars = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let byte_len = chars.saturating_mul(2);
    let start = offset + 4;
    let end = start.saturating_add(byte_len.saturating_sub(2));
    if end > data.len() || start >= end {
        return None;
    }
    let u16s: Vec<u16> = data[start..=end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&u16s))
}

fn read_clipdata_lpstr(data: &[u8], offset: usize) -> Option<String> {
    if offset + 4 > data.len() {
        return None;
    }
    let size = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    if size < 4 || offset + 4 + size > data.len() {
        return None;
    }
    read_lpstr(data, offset + 4)
}

fn read_filetime(data: &[u8], offset: usize) -> Option<String> {
    if offset + 8 > data.len() {
        return None;
    }
    let low = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as u64;
    let high = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]) as u64;
    let ticks = (high << 32) | low;
    // FILETIME = 100-ns intervals since 1601-01-01 UTC
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ticks < EPOCH_DIFF {
        return Some(ticks.to_string());
    }
    let unix = (ticks - EPOCH_DIFF) / 10_000_000;
    Some(format!("unix:{unix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfb::CompoundFile;
    use std::io::Write;

    fn write_summary_fixture(title: &str, author: &str) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut cfb = CompoundFile::create(&mut buf).expect("cfb create");
            let props = build_summary_bytes(title, author);
            let summary_name = "/\u{5}SummaryInformation".to_string();
            let mut stream = cfb.create_stream(&summary_name).expect("stream");
            stream.write_all(&props).expect("write");
        }
        buf.into_inner()
    }

    fn build_summary_bytes(title: &str, author: &str) -> Vec<u8> {
        let title_bytes = title.as_bytes();
        let author_bytes = author.as_bytes();
        let title_val_off = 96usize;
        let author_val_off = title_val_off + 4 + 4 + title_bytes.len() + 1;
        let section_off = 48usize;
        let prop_count = 2u32;
        let section_size = 8 + prop_count as usize * 8;
        let mut out = vec![0u8; author_val_off + 4 + 4 + author_bytes.len() + 1];
        out[0..2].copy_from_slice(&[0xFE, 0xFF]); // byte order
        out[24..28].copy_from_slice(&1u32.to_le_bytes()); // section count
                                                          // format id + offset for section 0
        out[28..44].fill(0);
        out[44..48].copy_from_slice(&(section_off as u32).to_le_bytes());
        out[section_off..section_off + 4].copy_from_slice(&(section_size as u32).to_le_bytes());
        out[section_off + 4..section_off + 8].copy_from_slice(&prop_count.to_le_bytes());
        out[section_off + 8..section_off + 12].copy_from_slice(&PID_TITLE.to_le_bytes());
        out[section_off + 12..section_off + 16]
            .copy_from_slice(&(title_val_off as u32).to_le_bytes());
        out[section_off + 16..section_off + 20].copy_from_slice(&PID_AUTHOR.to_le_bytes());
        out[section_off + 20..section_off + 24]
            .copy_from_slice(&(author_val_off as u32).to_le_bytes());
        out[title_val_off..title_val_off + 4].copy_from_slice(&0x1Eu32.to_le_bytes());
        out[title_val_off + 4..title_val_off + 8]
            .copy_from_slice(&((title_bytes.len() + 1) as u32).to_le_bytes());
        out[title_val_off + 8..title_val_off + 8 + title_bytes.len()].copy_from_slice(title_bytes);
        out[author_val_off..author_val_off + 4].copy_from_slice(&0x1Eu32.to_le_bytes());
        out[author_val_off + 4..author_val_off + 8]
            .copy_from_slice(&((author_bytes.len() + 1) as u32).to_le_bytes());
        out[author_val_off + 8..author_val_off + 8 + author_bytes.len()]
            .copy_from_slice(author_bytes);
        out
    }

    #[test]
    fn summary_information_roundtrip() {
        let data = write_summary_fixture("Test Doc", "Alice");
        let (sections, _) = parse_legacy_ole(&data, 0);
        let summary = sections
            .iter()
            .find(|s| s.id == "ole-summary")
            .expect("summary section");
        assert!(summary
            .fields
            .iter()
            .any(|f| f.key == "Title" && f.value == "Test Doc"));
        assert!(summary
            .fields
            .iter()
            .any(|f| f.key == "Author" && f.value == "Alice"));
    }

    #[test]
    fn detect_word_stream() {
        let streams = vec!["/WordDocument".into(), "/1Table".into()];
        assert_eq!(detect_kind(&streams), LegacyOfficeKind::Word);
    }
}
