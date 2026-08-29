use crate::parsers::{tiff, xmp};
use crate::types::{Field, Section};
use flate2::read::ZlibDecoder;
use std::io::Read;

pub struct PngParse {
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

pub fn parse_png(data: &[u8]) -> PngParse {
    let mut out = PngParse {
        sections: Vec::new(),
        warnings: Vec::new(),
        width: None,
        height: None,
    };
    if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
        out.warnings.push("Not a PNG".into());
        return out;
    }
    let mut chunks = Section::new("png-chunks", "PNG chunks");
    let mut i = 8usize;
    let mut idx = 0u32;
    while i + 12 <= data.len() {
        let len = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        let ctype = &data[i + 4..i + 8];
        let name = String::from_utf8_lossy(ctype).into_owned();
        let data_start = i + 8;
        let data_end = data_start.saturating_add(len);
        if data_end + 4 > data.len() {
            out.warnings.push(format!("Truncated PNG chunk {name}"));
            break;
        }
        let payload = &data[data_start..data_end];
        let crc = u32::from_be_bytes(data[data_end..data_end + 4].try_into().unwrap());
        chunks.fields.push(
            Field::new(
                format!("{idx}:{name}"),
                format!("{len} bytes crc={crc:08X}"),
            )
            .with_namespace("PNG")
            .with_span(i as u64, (12 + len) as u64),
        );
        match name.as_str() {
            "IHDR" if payload.len() >= 13 => {
                let w = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let h = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                out.width = Some(w);
                out.height = Some(h);
                let mut ihdr = Section::new("png-ihdr", "PNG IHDR");
                ihdr.add("Width", w.to_string(), Some("PNG:IHDR"));
                ihdr.add("Height", h.to_string(), Some("PNG:IHDR"));
                ihdr.add("BitDepth", payload[8].to_string(), Some("PNG:IHDR"));
                ihdr.add("ColorType", payload[9].to_string(), Some("PNG:IHDR"));
                ihdr.add("Compression", payload[10].to_string(), Some("PNG:IHDR"));
                ihdr.add("Filter", payload[11].to_string(), Some("PNG:IHDR"));
                ihdr.add("Interlace", payload[12].to_string(), Some("PNG:IHDR"));
                out.sections.push(ihdr);
            }
            "tEXt" => push_text(&mut out, payload, "PNG:tEXt", false),
            "zTXt" => push_text(&mut out, payload, "PNG:zTXt", true),
            "iTXt" => push_itxt(&mut out, payload),
            "eXIf" => {
                let parsed = tiff::parse_tiff(payload, data_start as u64);
                out.warnings.extend(parsed.warnings);
                out.sections.extend(parsed.sections);
            }
            "pHYs" if payload.len() >= 9 => {
                let mut s = Section::new("png-phys", "PNG pHYs");
                s.add(
                    "PixelsPerUnitX",
                    u32::from_be_bytes(payload[0..4].try_into().unwrap()).to_string(),
                    Some("PNG:pHYs"),
                );
                s.add(
                    "PixelsPerUnitY",
                    u32::from_be_bytes(payload[4..8].try_into().unwrap()).to_string(),
                    Some("PNG:pHYs"),
                );
                s.add("Unit", payload[8].to_string(), Some("PNG:pHYs"));
                out.sections.push(s);
            }
            "tIME" if payload.len() >= 7 => {
                let mut s = Section::new("png-time", "PNG tIME");
                let year = u16::from_be_bytes(payload[0..2].try_into().unwrap());
                s.add(
                    "ModificationTime",
                    format!(
                        "{year:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        payload[2], payload[3], payload[4], payload[5], payload[6]
                    ),
                    Some("PNG:tIME"),
                );
                out.sections.push(s);
            }
            "iCCP" => {
                let mut s = Section::new("png-iccp", "PNG iCCP");
                if let Some(z) = payload.iter().position(|&b| b == 0) {
                    s.add(
                        "ProfileName",
                        String::from_utf8_lossy(&payload[..z]).to_string(),
                        Some("PNG:iCCP"),
                    );
                }
                s.add("Size", payload.len().to_string(), Some("PNG:iCCP"));
                out.sections.push(s);
            }
            "bKGD" | "gAMA" | "cHRM" | "sRGB" | "sBIT" | "hIST" | "tRNS" | "sPLT" => {
                let mut s = Section::new(format!("png-{name}"), format!("PNG {name}"));
                s.add("Hex", hex::encode(payload), Some(&format!("PNG:{name}")));
                out.sections.push(s);
            }
            _ => {}
        }
        if name == "IEND" {
            break;
        }
        i = data_end + 4;
        idx += 1;
    }
    out.sections.insert(0, chunks);
    out
}

fn push_text(out: &mut PngParse, payload: &[u8], ns: &str, compressed: bool) {
    let Some(z) = payload.iter().position(|&b| b == 0) else {
        return;
    };
    let keyword = String::from_utf8_lossy(&payload[..z]).into_owned();
    let rest = &payload[z + 1..];
    let value = if compressed {
        let data = if rest.first() == Some(&0) {
            &rest[1..]
        } else {
            rest
        };
        inflate(data).unwrap_or_else(|| String::from_utf8_lossy(data).into_owned())
    } else {
        String::from_utf8_lossy(rest).into_owned()
    };
    if keyword.eq_ignore_ascii_case("XML:com.adobe.xmp") {
        if let Some(xml) = xmp::extract_xmp_from_bytes(value.as_bytes()) {
            let sec = xmp::parse_xmp(&xml, "XMP");
            if !sec.is_empty() {
                out.sections.push(sec);
            }
            return;
        }
    }
    let mut s = Section::new("png-text", "PNG text");
    s.fields.push(Field::new(keyword, value).with_namespace(ns));
    out.sections.push(s);
}

fn push_itxt(out: &mut PngParse, payload: &[u8]) {
    let mut parts = payload.splitn(2, |&b| b == 0);
    let keyword = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let rest = parts.next().unwrap_or_default();
    if rest.len() < 2 {
        return;
    }
    let compressed = rest[0] != 0;
    // skip compression method + language + translated keyword
    let mut r = &rest[2..];
    if let Some(z) = r.iter().position(|&b| b == 0) {
        r = &r[z + 1..];
    }
    if let Some(z) = r.iter().position(|&b| b == 0) {
        r = &r[z + 1..];
    }
    let value = if compressed {
        inflate(r).unwrap_or_else(|| String::from_utf8_lossy(r).into_owned())
    } else {
        String::from_utf8_lossy(r).into_owned()
    };
    if keyword.eq_ignore_ascii_case("XML:com.adobe.xmp") {
        if let Some(xml) = xmp::extract_xmp_from_bytes(value.as_bytes()) {
            let sec = xmp::parse_xmp(&xml, "XMP");
            if !sec.is_empty() {
                out.sections.push(sec);
            }
            return;
        }
    }
    let mut s = Section::new("png-itxt", "PNG iTXt");
    s.fields
        .push(Field::new(keyword, value).with_namespace("PNG:iTXt"));
    out.sections.push(s);
}

fn inflate(data: &[u8]) -> Option<String> {
    let mut d = ZlibDecoder::new(data).take(8 * 1024 * 1024);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok()?;
    Some(String::from_utf8_lossy(&out).into_owned())
}
