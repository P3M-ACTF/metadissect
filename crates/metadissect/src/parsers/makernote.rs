//! MakerNote (EXIF 0x927C): vendor detect + pragmatic subset. Not ExifTool parity.

use crate::types::{Field, Section};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Canon,
    Nikon,
    Sony,
    Apple,
    Unknown,
}

impl Vendor {
    pub fn as_str(self) -> &'static str {
        match self {
            Vendor::Canon => "Canon",
            Vendor::Nikon => "Nikon",
            Vendor::Sony => "Sony",
            Vendor::Apple => "Apple",
            Vendor::Unknown => "Unknown",
        }
    }
}

pub struct MakerNoteResult {
    pub section: Section,
    pub warnings: Vec<String>,
}

/// Analyze MakerNote blob. `make` is IFD0 Make when known (helps vendor id).
pub fn analyze(data: &[u8], base_offset: u64, make: Option<&str>) -> MakerNoteResult {
    let mut warnings = Vec::new();
    let vendor = detect_vendor(data, make);
    let mut section = Section::new("makernote", "MakerNote");
    section.add("Vendor", vendor.as_str().to_string(), Some("MakerNote"));
    section.add("Length", data.len().to_string(), Some("MakerNote"));
    section.fields.push(
        Field::new("Offset", base_offset.to_string())
            .with_namespace("MakerNote")
            .with_span(base_offset, data.len() as u64),
    );
    if data.len() >= 16 {
        section.add(
            "HeaderHex",
            hex::encode(&data[..16.min(data.len())]),
            Some("MakerNote"),
        );
    }
    if let Some(sig) = ascii_prefix(data, 24) {
        section.add("HeaderAscii", sig, Some("MakerNote"));
    }

    let decoded = match vendor {
        Vendor::Nikon => decode_nikon(data, &mut section, &mut warnings),
        Vendor::Canon => decode_canon(data, &mut section),
        Vendor::Sony => decode_sony(data, &mut section),
        Vendor::Apple => decode_apple(data, &mut section),
        Vendor::Unknown => false,
    };

    if !decoded {
        warnings.push(format!(
            "MakerNote ({}): not fully decoded — vendor id / length / offset only. Not ExifTool parity.",
            vendor.as_str()
        ));
        section.add("DecodeStatus", "partial/opaque", Some("MakerNote"));
    } else {
        section.add("DecodeStatus", "subset", Some("MakerNote"));
        warnings.push(format!(
            "MakerNote ({}): only a useful subset of tags is decoded; full MakerNote maps are not claimed.",
            vendor.as_str()
        ));
    }

    MakerNoteResult { section, warnings }
}

pub fn detect_vendor(data: &[u8], make: Option<&str>) -> Vendor {
    if data.starts_with(b"Nikon") || data.starts_with(b"NIKON") {
        return Vendor::Nikon;
    }
    if data.starts_with(b"SONY") || data.starts_with(b"Sony") {
        return Vendor::Sony;
    }
    if data.starts_with(b"Apple") || data.starts_with(b"apple") {
        return Vendor::Apple;
    }
    if data.starts_with(b"Canon") {
        return Vendor::Canon;
    }
    if let Some(m) = make {
        let l = m.to_ascii_lowercase();
        if l.contains("nikon") {
            return Vendor::Nikon;
        }
        if l.contains("canon") {
            return Vendor::Canon;
        }
        if l.contains("sony") {
            return Vendor::Sony;
        }
        if l.contains("apple") {
            return Vendor::Apple;
        }
    }
    Vendor::Unknown
}

fn ascii_prefix(data: &[u8], max: usize) -> Option<String> {
    let n = data.len().min(max);
    if n == 0 {
        return None;
    }
    let ok = data[..n]
        .iter()
        .all(|&b| b == 0 || (0x20..=0x7E).contains(&b));
    if !ok {
        return None;
    }
    let s = String::from_utf8_lossy(&data[..n])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

struct IfdEntry {
    tag: u16,
    value: String,
}

/// Local TIFF/IFD reader (avoids circular dep with `tiff` parser).
fn read_tiff_ifd_entries(data: &[u8]) -> Vec<IfdEntry> {
    if data.len() < 8 {
        return Vec::new();
    }
    let le = match &data[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return Vec::new(),
    };
    let magic = u16_at(data, 2, le);
    if magic != 42 {
        return Vec::new();
    }
    let ifd0 = u32_at(data, 4, le) as usize;
    read_ifd_entries(data, ifd0, le)
}

fn read_bare_ifd_entries(data: &[u8], le: bool) -> Vec<IfdEntry> {
    let mut wrapped = Vec::with_capacity(8 + data.len());
    if le {
        wrapped.extend_from_slice(b"II");
        wrapped.extend_from_slice(&42u16.to_le_bytes());
        wrapped.extend_from_slice(&8u32.to_le_bytes());
    } else {
        wrapped.extend_from_slice(b"MM");
        wrapped.extend_from_slice(&42u16.to_be_bytes());
        wrapped.extend_from_slice(&8u32.to_be_bytes());
    }
    wrapped.extend_from_slice(data);
    read_tiff_ifd_entries(&wrapped)
}

fn read_ifd_entries(data: &[u8], offset: usize, le: bool) -> Vec<IfdEntry> {
    let mut out = Vec::new();
    if offset + 2 > data.len() {
        return out;
    }
    let count = u16_at(data, offset, le) as usize;
    let entries_start = offset + 2;
    for i in 0..count.min(64) {
        let eoff = entries_start + i * 12;
        if eoff + 12 > data.len() {
            break;
        }
        let tag = u16_at(data, eoff, le);
        let typ = u16_at(data, eoff + 2, le);
        let cnt = u32_at(data, eoff + 4, le);
        let unit = match typ {
            1 | 2 | 6 | 7 => 1u32,
            3 | 8 => 2,
            4 | 9 | 11 | 13 => 4,
            5 | 10 | 12 => 8,
            _ => 1,
        };
        let nbytes = unit.saturating_mul(cnt) as usize;
        let val_bytes = if nbytes <= 4 {
            &data[eoff + 8..eoff + 8 + nbytes.min(4)]
        } else {
            let ptr = u32_at(data, eoff + 8, le) as usize;
            if ptr >= data.len() {
                continue;
            }
            let end = (ptr + nbytes).min(data.len());
            &data[ptr..end]
        };
        let value = format_ifd_value(typ, cnt, val_bytes, le);
        out.push(IfdEntry { tag, value });
    }
    out
}

fn format_ifd_value(typ: u16, count: u32, bytes: &[u8], le: bool) -> String {
    match typ {
        2 => String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .trim()
            .to_string(),
        3 if count == 1 && bytes.len() >= 2 => u16_from(bytes, le).to_string(),
        4 | 13 if count == 1 && bytes.len() >= 4 => u32_from(bytes, le).to_string(),
        1 | 7 if count <= 16 => bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        1 | 7 => format!(
            "{} bytes: {}…",
            count,
            hex::encode(&bytes[..16.min(bytes.len())])
        ),
        _ if bytes.len() <= 32 => hex::encode(bytes),
        _ => format!("{} bytes: {}…", bytes.len(), hex::encode(&bytes[..16])),
    }
}

fn u16_at(data: &[u8], off: usize, le: bool) -> u16 {
    let Some(a) = data
        .get(off..off + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
    else {
        return 0;
    };
    if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}

fn u32_at(data: &[u8], off: usize, le: bool) -> u32 {
    let Some(a) = data
        .get(off..off + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
    else {
        return 0;
    };
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

fn u16_from(bytes: &[u8], le: bool) -> u16 {
    let Some(a) = bytes.get(..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
        return 0;
    };
    if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}

fn u32_from(bytes: &[u8], le: bool) -> u32 {
    let Some(a) = bytes.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
        return 0;
    };
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

fn apply_known(
    entries: &[IfdEntry],
    section: &mut Section,
    ns: &str,
    known: &[(u16, &str)],
) -> usize {
    let mut found = 0;
    for e in entries {
        if let Some((_, name)) = known.iter().find(|(t, _)| *t == e.tag) {
            let value = if e.value.len() > 200 {
                format!("{}… ({} chars)", &e.value[..80], e.value.len())
            } else {
                e.value.clone()
            };
            if value.contains("bytes:") && !name.contains("Version") && !name.contains("Serial") {
                section.fields.push(
                    Field::new(*name, format!("binary ({})", e.value))
                        .with_namespace(ns)
                        .with_explanation("Present; binary MakerNote sub-tag not expanded"),
                );
            } else {
                section
                    .fields
                    .push(Field::new(*name, value).with_namespace(ns));
            }
            found += 1;
        }
    }
    if found == 0 && !entries.is_empty() {
        section.add("IfdEntryCount", entries.len().to_string(), Some(ns));
        for e in entries.iter().take(8) {
            section.fields.push(
                Field::new(format!("Tag_0x{:04X}", e.tag), e.value.clone()).with_namespace(ns),
            );
            found += 1;
        }
    }
    found
}

fn decode_nikon(data: &[u8], section: &mut Section, warnings: &mut Vec<String>) -> bool {
    let tiff_start = if data.starts_with(b"Nikon") {
        if data.len() > 10 && (data[10..].starts_with(b"II") || data[10..].starts_with(b"MM")) {
            10
        } else if data.len() > 8 && (data[8..].starts_with(b"II") || data[8..].starts_with(b"MM")) {
            8
        } else {
            warnings.push("Nikon MakerNote: header recognized but no embedded TIFF found".into());
            return false;
        }
    } else if data.starts_with(b"II") || data.starts_with(b"MM") {
        0
    } else {
        return false;
    };

    section.add(
        "NikonTiffOffset",
        tiff_start.to_string(),
        Some("MakerNote:Nikon"),
    );
    let entries = read_tiff_ifd_entries(&data[tiff_start..]);
    apply_known(
        &entries,
        section,
        "MakerNote:Nikon",
        &[
            (0x0001, "NikonVersion"),
            (0x0002, "ISO"),
            (0x0004, "Quality"),
            (0x0005, "WhiteBalance"),
            (0x0006, "Sharpness"),
            (0x0007, "FocusMode"),
            (0x0008, "FlashSetting"),
            (0x000B, "Software"),
            (0x0011, "PreviewIFD"),
            (0x001D, "SerialNumber"),
            (0x0083, "LensType"),
            (0x0084, "Lens"),
            (0x00A7, "ShutterCount"),
        ],
    ) > 0
}

fn decode_canon(data: &[u8], section: &mut Section) -> bool {
    let entries = if data.starts_with(b"II") || data.starts_with(b"MM") {
        read_tiff_ifd_entries(data)
    } else if data.starts_with(b"Canon") {
        let skip = data
            .iter()
            .position(|&b| b == 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        read_bare_ifd_entries(&data[skip..], true)
    } else {
        read_bare_ifd_entries(data, true)
    };
    apply_known(
        &entries,
        section,
        "MakerNote:Canon",
        &[
            (0x0001, "CanonCameraSettings"),
            (0x0002, "CanonFocalLength"),
            (0x0004, "CanonShotInfo"),
            (0x0006, "CanonImageType"),
            (0x0007, "CanonFirmwareVersion"),
            (0x0009, "OwnerName"),
            (0x000C, "SerialNumber"),
            (0x0010, "ModelID"),
            (0x0095, "LensModel"),
        ],
    ) > 0
}

fn decode_sony(data: &[u8], section: &mut Section) -> bool {
    let payload = if data.len() > 12 && data[..4].eq_ignore_ascii_case(b"SONY") {
        &data[12..]
    } else {
        data
    };
    if payload.starts_with(b"II") || payload.starts_with(b"MM") {
        let entries = read_tiff_ifd_entries(payload);
        return apply_known(
            &entries,
            section,
            "MakerNote:Sony",
            &[
                (0x2000, "Sony_0x2000"),
                (0x2001, "PreviewImage"),
                (0x0102, "SonyISO"),
                (0x0104, "SonyQuality"),
            ],
        ) > 0;
    }
    if data.len() >= 12 && data[..4].eq_ignore_ascii_case(b"SONY") {
        section.add(
            "SonyHeader",
            String::from_utf8_lossy(&data[..12])
                .trim_end_matches('\0')
                .to_string(),
            Some("MakerNote:Sony"),
        );
    }
    false
}

fn decode_apple(data: &[u8], section: &mut Section) -> bool {
    let tiff_start = find_tiff_magic(data).unwrap_or(0);
    if tiff_start > 0 || data.starts_with(b"II") || data.starts_with(b"MM") {
        let entries = read_tiff_ifd_entries(&data[tiff_start..]);
        return apply_known(
            &entries,
            section,
            "MakerNote:Apple",
            &[
                (0x0001, "Apple_0x0001"),
                (0x0003, "RunTime"),
                (0x0008, "AccelerationVector"),
                (0x000A, "HDRImageType"),
                (0x000E, "ImageCaptureType"),
            ],
        ) > 0;
    }
    false
}

fn find_tiff_magic(data: &[u8]) -> Option<usize> {
    data.windows(2)
        .position(|w| w == b"II" || w == b"MM")
        .filter(|&i| {
            i + 4 <= data.len() && {
                let magic = u16::from_le_bytes([data[i + 2], data[i + 3]]);
                let magic_be = u16::from_be_bytes([data[i + 2], data[i + 3]]);
                magic == 42 || magic_be == 42
            }
        })
}

/// Synthetic Nikon-style MakerNote (header + mini TIFF IFD) for unit tests.
pub fn synthetic_nikon_makernote() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"Nikon\0");
    body.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    let tiff_start = body.len();
    body.extend_from_slice(b"II");
    body.extend_from_slice(&42u16.to_le_bytes());
    let ifd_offset_pos = body.len();
    body.extend_from_slice(&0u32.to_le_bytes());

    let ifd_at = body.len() - tiff_start;
    let serial = b"N123\0";
    let mut ifd = Vec::new();
    ifd.extend_from_slice(&1u16.to_le_bytes());
    ifd.extend_from_slice(&0x001Du16.to_le_bytes());
    ifd.extend_from_slice(&2u16.to_le_bytes());
    ifd.extend_from_slice(&5u32.to_le_bytes());
    let value_off = (ifd_at + 2 + 12 + 4) as u32;
    ifd.extend_from_slice(&value_off.to_le_bytes());
    ifd.extend_from_slice(&0u32.to_le_bytes());
    ifd.extend_from_slice(serial);

    body[ifd_offset_pos..ifd_offset_pos + 4].copy_from_slice(&(ifd_at as u32).to_le_bytes());
    body.extend_from_slice(&ifd);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nikon_and_extracts_serial_subset() {
        let data = synthetic_nikon_makernote();
        assert_eq!(
            detect_vendor(&data, Some("NIKON CORPORATION")),
            Vendor::Nikon
        );
        let r = analyze(&data, 100, Some("NIKON CORPORATION"));
        assert_eq!(
            r.section
                .fields
                .iter()
                .find(|f| f.key == "Vendor")
                .map(|f| f.value.as_str()),
            Some("Nikon")
        );
        assert!(
            r.section
                .fields
                .iter()
                .any(|f| f.key == "SerialNumber" && f.value.contains("N123")),
            "fields={:?}",
            r.section.fields
        );
        assert!(r.warnings.iter().any(|w| w.contains("subset")));
    }

    #[test]
    fn unknown_vendor_is_honest() {
        let data = b"\x00\x01\x02\x03XXXX opaque blob that is not a known maker note";
        let r = analyze(data, 0, Some("ACME Cameras"));
        assert_eq!(
            r.section
                .fields
                .iter()
                .find(|f| f.key == "Vendor")
                .map(|f| f.value.as_str()),
            Some("Unknown")
        );
        assert!(r.warnings.iter().any(|w| w.contains("not fully decoded")));
    }
}
