use crate::types::{Field, Section};

/// Photoshop IRB parse result including MWG IPTCDigest inputs.
pub struct PhotoshopParse {
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
    /// Raw IPTC-NAA bytes from resource 0x0404 (for digest verification).
    pub iptc_bytes: Option<Vec<u8>>,
    /// Stored Caption/IPTC digest from resource 0x0425 (16 bytes MD5).
    pub iptc_digest: Option<Vec<u8>>,
}

/// Parse IPTC-IIM records (0x1C marker).
pub fn parse_iptc_iim(data: &[u8], base_offset: u64) -> Section {
    let mut section = Section::new("iptc-iim", "IPTC/IIM");
    let mut i = 0;
    while i + 5 <= data.len() {
        if data[i] != 0x1C {
            i += 1;
            continue;
        }
        let rec = data[i + 1];
        let ds = data[i + 2];
        let mut len = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
        let mut hdr = 5;
        if data[i + 3] & 0x80 != 0 {
            // extended length
            let n = len & 0x7FFF;
            if i + 5 + n > data.len() {
                break;
            }
            len = 0;
            for b in &data[i + 5..i + 5 + n] {
                len = (len << 8) | *b as usize;
            }
            hdr = 5 + n;
        }
        if i + hdr + len > data.len() {
            break;
        }
        let payload = &data[i + hdr..i + hdr + len];
        let key = iptc_name(rec, ds);
        let value = String::from_utf8_lossy(payload).trim().to_string();
        if !value.is_empty() {
            section.fields.push(
                Field::new(key, value)
                    .with_namespace("IPTC:IIM")
                    .with_span(base_offset + i as u64, (hdr + len) as u64),
            );
        }
        i += hdr + len;
    }
    section
}

pub fn parse_photoshop_irb(data: &[u8], base_offset: u64) -> PhotoshopParse {
    let mut out = PhotoshopParse {
        sections: Vec::new(),
        warnings: Vec::new(),
        iptc_bytes: None,
        iptc_digest: None,
    };
    let mut i = 0;
    while i + 12 <= data.len() {
        if &data[i..i + 4] != b"8BIM" {
            i += 1;
            continue;
        }
        let resid = u16::from_be_bytes([data[i + 4], data[i + 5]]);
        let name_len = data[i + 6] as usize;
        let name_end = i + 7 + name_len;
        let padded = if (name_end - i) % 2 == 1 {
            name_end + 1
        } else {
            name_end
        };
        if padded + 4 > data.len() {
            break;
        }
        let size =
            u32::from_be_bytes(data[padded..padded + 4].try_into().unwrap_or([0; 4])) as usize;
        let data_start = padded + 4;
        let data_end = (data_start + size).min(data.len());
        let payload = &data[data_start..data_end];
        if resid == 0x0404 {
            out.iptc_bytes = Some(payload.to_vec());
            let iptc = parse_iptc_iim(payload, base_offset + data_start as u64);
            if !iptc.is_empty() {
                out.sections.push(iptc);
            }
        } else if resid == 0x0425 {
            // CaptionDigest / IPTCDigest — typically 16-byte MD5
            out.iptc_digest = Some(payload.to_vec());
            let mut sec = Section::new("photoshop-iptcdigest", "Photoshop IPTCDigest");
            sec.fields.push(
                Field::new("IptcDigest", hex::encode(payload))
                    .with_namespace("Photoshop:IRB")
                    .with_span(base_offset + data_start as u64, payload.len() as u64)
                    .with_raw(serde_json::json!({ "resource": "0x0425" })),
            );
            out.sections.push(sec);
        } else {
            let mut sec = Section::new(format!("photoshop-{resid:04x}"), "Photoshop IRB");
            let name = if name_len > 0 && i + 7 + name_len <= data.len() {
                String::from_utf8_lossy(&data[i + 7..i + 7 + name_len]).into_owned()
            } else {
                irb_name(resid).to_string()
            };
            sec.fields.push(
                Field::new(
                    format!("Resource_0x{resid:04X}"),
                    format!("{} ({} bytes)", name, size),
                )
                .with_namespace("Photoshop:IRB")
                .with_span(base_offset + i as u64, (data_end - i) as u64),
            );
            if !sec.is_empty() {
                out.sections.push(sec);
            }
        }
        let mut next = data_end;
        if size % 2 == 1 {
            next += 1;
        }
        if next <= i {
            out.warnings.push("Photoshop IRB parser stuck".into());
            break;
        }
        i = next;
    }
    out
}

fn iptc_name(rec: u8, ds: u8) -> String {
    let known = match (rec, ds) {
        (1, 0) => "EnvelopeRecordVersion",
        (1, 5) => "Destination",
        (1, 20) => "FileFormat",
        (1, 22) => "FileVersion",
        (1, 30) => "ServiceIdentifier",
        (1, 40) => "EnvelopeNumber",
        (1, 50) => "ProductID",
        (1, 70) => "DateSent",
        (1, 80) => "TimeSent",
        (2, 0) => "ApplicationRecordVersion",
        (2, 5) => "ObjectName",
        (2, 7) => "EditStatus",
        (2, 10) => "Urgency",
        (2, 12) => "SubjectReference",
        (2, 15) => "Category",
        (2, 20) => "SupplementalCategory",
        (2, 25) => "Keywords",
        (2, 40) => "SpecialInstructions",
        (2, 55) => "DateCreated",
        (2, 60) => "TimeCreated",
        (2, 62) => "DigitalCreationDate",
        (2, 63) => "DigitalCreationTime",
        (2, 80) => "Byline",
        (2, 85) => "BylineTitle",
        (2, 90) => "City",
        (2, 92) => "Sublocation",
        (2, 95) => "ProvinceState",
        (2, 100) => "CountryPrimaryLocationCode",
        (2, 101) => "CountryPrimaryLocationName",
        (2, 103) => "OriginalTransmissionReference",
        (2, 105) => "Headline",
        (2, 110) => "Credit",
        (2, 115) => "Source",
        (2, 116) => "CopyrightNotice",
        (2, 118) => "Contact",
        (2, 120) => "CaptionAbstract",
        (2, 122) => "WriterEditor",
        _ => return format!("IIM_{rec}:{ds}"),
    };
    known.to_string()
}

fn irb_name(id: u16) -> &'static str {
    match id {
        0x03E9 => "MacPrintManagerInfo",
        0x03ED => "ResolutionInfo",
        0x0404 => "IPTC-NAA",
        0x0406 => "JPEGQuality",
        0x0408 => "GridAndGuides",
        0x040C => "ThumbnailResource",
        0x040F => "ICCUntagged",
        0x0414 => "CopyrightFlag",
        0x0415 => "URL",
        0x0421 => "VersionInfo",
        0x0422 => "EXIFInfo",
        0x0423 => "EXIF",
        0x0424 => "XMP",
        0x0425 => "CaptionDigest",
        0x0426 => "PrintScale",
        0x0BB7 => "ClippingPathName",
        _ => "PhotoshopResource",
    }
}
