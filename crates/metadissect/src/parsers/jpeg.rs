use crate::parsers::{iptc, tiff, xmp};
use crate::types::{Field, Section};

pub struct JpegParse {
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
    pub pixel_width: Option<u32>,
    pub pixel_height: Option<u32>,
}

pub fn parse_jpeg(data: &[u8]) -> JpegParse {
    let mut out = JpegParse {
        sections: Vec::new(),
        warnings: Vec::new(),
        pixel_width: None,
        pixel_height: None,
    };
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        out.warnings.push("Not a JPEG (missing SOI)".into());
        return out;
    }

    let mut markers = Section::new("jpeg-markers", "JPEG container");
    markers.fields.push(
        Field::new("SOI", "FF D8")
            .with_namespace("JPEG")
            .with_span(0, 2),
    );

    let mut i = 2usize;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let mut marker = data[i + 1];
        let start = i;
        i += 2;
        while marker == 0xFF && i < data.len() {
            marker = data[i];
            i += 1;
        }
        if marker == 0xD9 {
            markers.fields.push(
                Field::new("EOI", "FF D9")
                    .with_namespace("JPEG")
                    .with_span(start as u64, 2),
            );
            break;
        }
        if marker == 0xDA {
            // SOS: remainder is entropy-coded until EOI
            markers.fields.push(
                Field::new("SOS", format!("entropy-coded from offset {start}"))
                    .with_namespace("JPEG")
                    .with_span(start as u64, (data.len() - start) as u64),
            );
            break;
        }
        if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) {
            markers.fields.push(
                Field::new(marker_name(marker), format!("FF {marker:02X}"))
                    .with_namespace("JPEG")
                    .with_span(start as u64, 2),
            );
            continue;
        }
        if i + 2 > data.len() {
            break;
        }
        let seglen = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        let payload_start = i + 2;
        let payload_end = (i + seglen).min(data.len());
        if payload_end < payload_start {
            out.warnings
                .push(format!("Invalid JPEG segment length at {start}"));
            break;
        }
        let payload = &data[payload_start..payload_end];
        markers.fields.push(
            Field::new(marker_name(marker), format!("{} bytes", payload.len()))
                .with_namespace("JPEG")
                .with_span(start as u64, (payload_end - start) as u64),
        );

        match marker {
            0xE1 => parse_app1(payload, payload_start as u64, &mut out),
            0xE2 => parse_app2(payload, &mut out),
            0xED => parse_app13(payload, payload_start as u64, &mut out),
            0xE0 => parse_jfif(payload, &mut out),
            0xEE => parse_app14(payload, &mut out),
            0xFE => {
                let mut com = Section::new("jpeg-comment", "JPEG comment");
                com.fields.push(
                    Field::new(
                        "Comment",
                        String::from_utf8_lossy(payload)
                            .trim_end_matches('\0')
                            .to_string(),
                    )
                    .with_namespace("JPEG:COM")
                    .with_span(payload_start as u64, payload.len() as u64),
                );
                out.sections.push(com);
            }
            0xC0..=0xCF
                if marker != 0xC4 && marker != 0xC8 && marker != 0xCC && payload.len() >= 6 =>
            {
                let bits = payload[0];
                let h = u16::from_be_bytes([payload[1], payload[2]]) as u32;
                let w = u16::from_be_bytes([payload[3], payload[4]]) as u32;
                let comps = payload[5];
                out.pixel_width = Some(w);
                out.pixel_height = Some(h);
                let mut sof = Section::new("jpeg-sof", "JPEG frame (SOF)");
                sof.add("BitsPerSample", bits.to_string(), Some("JPEG:SOF"));
                sof.add("Height", h.to_string(), Some("JPEG:SOF"));
                sof.add("Width", w.to_string(), Some("JPEG:SOF"));
                sof.add("Components", comps.to_string(), Some("JPEG:SOF"));
                sof.add("Marker", marker_name(marker), Some("JPEG:SOF"));
                out.sections.push(sof);
            }
            _ => {}
        }
        i += seglen;
    }

    out.sections.insert(0, markers);
    out
}

fn parse_app1(payload: &[u8], payload_offset: u64, out: &mut JpegParse) {
    if payload.starts_with(b"Exif\0\0") {
        let tiff = &payload[6..];
        let parsed = tiff::parse_tiff(tiff, payload_offset + 6);
        out.warnings.extend(parsed.warnings);
        out.sections.extend(parsed.sections);
        // also dump via kamadak-exif as a safety net for names
        supplement_kamadak(payload, out);
    } else if payload.starts_with(b"http://ns.adobe.com/xap/1.0/\0")
        || payload.windows(9).any(|w| w == b"<x:xmpmeta")
    {
        if let Some(xml) = xmp::extract_xmp_from_bytes(payload) {
            let sec = xmp::parse_xmp(&xml, "XMP");
            if !sec.is_empty() {
                out.sections.push(sec);
            }
        }
    }
}

fn supplement_kamadak(app1_payload: &[u8], out: &mut JpegParse) {
    let mut cur = std::io::Cursor::new(app1_payload);
    // kamadak expects the Exif\0\0 + TIFF stream as a container
    if let Ok(exif) = exif::Reader::new().read_from_container(&mut cur) {
        let mut seen = std::collections::HashSet::new();
        for sec in &out.sections {
            for f in &sec.fields {
                seen.insert(f.key.clone());
            }
        }
        let mut extra = Section::new("exif-kamadak", "EXIF (reader complement)");
        for f in exif.fields() {
            let key = f.tag.to_string();
            if key.starts_with("Tag(") || seen.contains(&key) {
                continue;
            }
            let value = f.display_value().with_unit(f).to_string();
            extra
                .fields
                .push(Field::new(key, value).with_namespace(format!("EXIF:{:?}", f.ifd_num)));
        }
        if !extra.is_empty() {
            out.sections.push(extra);
        }
    }
}

fn parse_app2(payload: &[u8], out: &mut JpegParse) {
    if payload.starts_with(b"ICC_PROFILE\0") {
        let mut sec = Section::new("icc", "ICC profile");
        sec.add(
            "Size",
            payload.len().saturating_sub(14).to_string(),
            Some("ICC"),
        );
        if payload.len() > 14 + 4 {
            if let Ok(s) = std::str::from_utf8(&payload[14 + 4..14 + 8]) {
                sec.add("CMM", s.trim().to_string(), Some("ICC"));
            }
        }
        if payload.len() > 14 + 16 {
            if let Ok(s) = std::str::from_utf8(&payload[14 + 16..14 + 20]) {
                sec.add("DeviceClass", s.trim().to_string(), Some("ICC"));
            }
        }
        if payload.len() > 14 + 20 {
            if let Ok(s) = std::str::from_utf8(&payload[14 + 20..14 + 24]) {
                sec.add("ColorSpace", s.trim().to_string(), Some("ICC"));
            }
        }
        out.sections.push(sec);
    } else if payload.starts_with(b"FPXR") {
        let mut sec = Section::new("fpxr", "FlashPix APP2");
        sec.add("Size", payload.len().to_string(), Some("JPEG:APP2"));
        out.sections.push(sec);
    }
}

fn parse_app13(payload: &[u8], payload_offset: u64, out: &mut JpegParse) {
    let rest = if payload.starts_with(b"Photoshop 3.0\0") {
        &payload[14..]
    } else {
        payload
    };
    let (secs, warns) =
        iptc::parse_photoshop_irb(rest, payload_offset + (payload.len() - rest.len()) as u64);
    out.sections.extend(secs);
    out.warnings.extend(warns);
}

fn parse_jfif(payload: &[u8], out: &mut JpegParse) {
    if payload.len() < 9 || !payload.starts_with(b"JFIF\0") {
        return;
    }
    let mut sec = Section::new("jfif", "JFIF");
    sec.add(
        "Version",
        format!("{}.{}", payload[5], payload[6]),
        Some("JPEG:JFIF"),
    );
    sec.add("Units", payload[7].to_string(), Some("JPEG:JFIF"));
    if payload.len() >= 13 {
        let x = u16::from_be_bytes([payload[8], payload[9]]);
        let y = u16::from_be_bytes([payload[10], payload[11]]);
        sec.add("XDensity", x.to_string(), Some("JPEG:JFIF"));
        sec.add("YDensity", y.to_string(), Some("JPEG:JFIF"));
    }
    out.sections.push(sec);
}

fn parse_app14(payload: &[u8], out: &mut JpegParse) {
    if payload.starts_with(b"Adobe") && payload.len() >= 12 {
        let mut sec = Section::new("adobe-app14", "Adobe APP14");
        sec.add("Transform", payload[11].to_string(), Some("JPEG:APP14"));
        out.sections.push(sec);
    }
}

fn marker_name(m: u8) -> String {
    match m {
        0xC0 => "SOF0".into(),
        0xC1 => "SOF1".into(),
        0xC2 => "SOF2".into(),
        0xC3 => "SOF3".into(),
        0xC4 => "DHT".into(),
        0xDB => "DQT".into(),
        0xDD => "DRI".into(),
        0xDA => "SOS".into(),
        0xD8 => "SOI".into(),
        0xD9 => "EOI".into(),
        0xE0 => "APP0".into(),
        0xE1 => "APP1".into(),
        0xE2 => "APP2".into(),
        0xED => "APP13".into(),
        0xEE => "APP14".into(),
        0xFE => "COM".into(),
        0xD0..=0xD7 => format!("RST{}", m - 0xD0),
        other if (0xE0..=0xEF).contains(&other) => format!("APP{}", other - 0xE0),
        other => format!("Marker_0x{other:02X}"),
    }
}
