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

/// Compact `png-chunks` (and nested `*-png-chunks`) by aggregating IDAT.
///
/// Default CLI/lib output lists interesting chunks plus `IDATCount` / `IDATBytes`.
/// Verbose analysis skips this and keeps one field per chunk.
pub fn compact_png_chunks_in(sections: &mut [Section]) {
    for s in sections.iter_mut() {
        if is_png_chunks_section(&s.id) {
            s.fields = compact_chunk_fields(&s.fields);
        }
    }
}

fn is_png_chunks_section(id: &str) -> bool {
    id == "png-chunks" || id.ends_with("-png-chunks")
}

fn chunk_type_from_field_key(key: &str) -> &str {
    key.rsplit_once(':').map(|(_, n)| n).unwrap_or(key)
}

fn bytes_from_png_chunk_value(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn chunk_listed_by_default(name: &str) -> bool {
    if name == "IDAT" {
        return false;
    }
    matches!(
        name,
        "IHDR"
            | "PLTE"
            | "IEND"
            | "tEXt"
            | "zTXt"
            | "iTXt"
            | "eXIf"
            | "pHYs"
            | "tIME"
            | "iCCP"
            | "gAMA"
            | "cHRM"
            | "sRGB"
            | "sBIT"
            | "bKGD"
            | "tRNS"
            | "hIST"
            | "sPLT"
            | "cICP"
            | "caBX"
    ) || name.starts_with("ca")
        || (name.len() == 4 && name.as_bytes()[0].is_ascii_lowercase())
}

fn compact_chunk_fields(fields: &[Field]) -> Vec<Field> {
    let mut out = Vec::new();
    let mut idat_count = 0u32;
    let mut idat_bytes = 0u64;
    let mut idat_offset = None;
    let mut idat_len = 0u64;
    let mut idat_insert_at = None;

    for f in fields {
        let name = chunk_type_from_field_key(&f.key);
        if name == "IDAT" {
            if idat_insert_at.is_none() {
                idat_insert_at = Some(out.len());
                idat_offset = f.offset;
            }
            idat_count += 1;
            idat_bytes += bytes_from_png_chunk_value(&f.value);
            idat_len = idat_len.saturating_add(f.length.unwrap_or(0));
            continue;
        }
        if chunk_listed_by_default(name) {
            out.push(f.clone());
        }
    }

    if idat_count > 0 {
        let at = idat_insert_at.unwrap_or(out.len());
        let mut count_f = Field::new("IDATCount", idat_count.to_string()).with_namespace("PNG");
        let mut bytes_f = Field::new("IDATBytes", idat_bytes.to_string()).with_namespace("PNG");
        if let Some(off) = idat_offset {
            count_f = count_f.with_span(off, idat_len);
            bytes_f = bytes_f.with_span(off, idat_len);
        }
        out.insert(at, bytes_f);
        out.insert(at, count_f);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze_buffer;
    use crate::types::AnalyzeOptions;

    fn tiny_png() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut enc = png::Encoder::new(std::io::Cursor::new(&mut buf), 2, 2);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            enc.add_text_chunk("Comment".into(), "hello".into())
                .unwrap();
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
                .unwrap();
        }
        buf
    }

    /// Split the first IDAT payload into two IDAT chunks (dummy CRC is fine; parser does not verify).
    fn png_with_split_idat(data: &[u8]) -> Vec<u8> {
        assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"));
        let mut out = data[..8].to_vec();
        let mut i = 8usize;
        let mut split_done = false;
        while i + 12 <= data.len() {
            let len = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            let ctype = &data[i + 4..i + 8];
            let data_start = i + 8;
            let data_end = data_start + len;
            if data_end + 4 > data.len() {
                break;
            }
            let payload = &data[data_start..data_end];
            let crc = &data[data_end..data_end + 4];
            if !split_done && ctype == b"IDAT" && len >= 2 {
                let mid = len / 2;
                let (a, b) = payload.split_at(mid);
                for part in [a, b] {
                    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
                    out.extend_from_slice(b"IDAT");
                    out.extend_from_slice(part);
                    out.extend_from_slice(&[0, 0, 0, 0]);
                }
                split_done = true;
            } else {
                out.extend_from_slice(&data[i..data_end + 4]);
                let _ = crc;
            }
            if ctype == b"IEND" {
                break;
            }
            i = data_end + 4;
        }
        assert!(split_done, "expected an IDAT chunk to split");
        out
    }

    #[test]
    fn compact_mode_aggregates_multiple_idat() {
        let png = png_with_split_idat(&tiny_png());
        let parsed = parse_png(&png);
        let chunks = parsed
            .sections
            .iter()
            .find(|s| s.id == "png-chunks")
            .expect("png-chunks");
        let idat_fields: Vec<_> = chunks
            .fields
            .iter()
            .filter(|f| chunk_type_from_field_key(&f.key) == "IDAT")
            .collect();
        assert!(
            idat_fields.len() >= 2,
            "fixture should have multiple IDAT before compact, got {}",
            idat_fields.len()
        );

        let mut sections = parsed.sections.clone();
        compact_png_chunks_in(&mut sections);
        let compact = sections.iter().find(|s| s.id == "png-chunks").unwrap();
        assert!(
            compact.fields.iter().any(|f| f.key == "IDATCount"),
            "expected IDATCount, got {:?}",
            compact.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
        );
        assert!(compact.fields.iter().any(|f| f.key == "IDATBytes"));
        assert!(
            !compact
                .fields
                .iter()
                .any(|f| chunk_type_from_field_key(&f.key) == "IDAT" && f.key.contains(':')),
            "compact mode must not list per-chunk IDAT, got {:?}",
            compact.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
        );
        let count: u32 = compact
            .fields
            .iter()
            .find(|f| f.key == "IDATCount")
            .unwrap()
            .value
            .parse()
            .unwrap();
        assert!(count >= 2, "IDATCount={count}");
        assert!(
            compact.fields.iter().any(|f| f.key.contains("IHDR")),
            "IHDR should remain"
        );
        assert!(
            compact.fields.iter().any(|f| f.key.contains("tEXt") || f.key.contains("IEND")),
            "interesting chunks should remain"
        );
    }

    #[test]
    fn analyze_buffer_default_is_compact_verbose_lists_idat() {
        let png = png_with_split_idat(&tiny_png());
        let compact = analyze_buffer(&png, AnalyzeOptions::from_filename("multi.png"));
        let chunks = compact
            .sections
            .iter()
            .find(|s| s.id == "png-chunks")
            .expect("png-chunks");
        assert!(chunks.fields.iter().any(|f| f.key == "IDATCount"));
        assert_eq!(
            chunks
                .fields
                .iter()
                .filter(|f| f.key.contains("IDAT") && f.key.contains(':'))
                .count(),
            0
        );

        let verbose = analyze_buffer(
            &png,
            AnalyzeOptions::from_filename("multi.png").with_verbose(true),
        );
        let vchunks = verbose
            .sections
            .iter()
            .find(|s| s.id == "png-chunks")
            .expect("png-chunks");
        assert!(
            vchunks
                .fields
                .iter()
                .filter(|f| chunk_type_from_field_key(&f.key) == "IDAT")
                .count()
                >= 2,
            "verbose should restore per-IDAT rows, got {:?}",
            vchunks.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
        );
        assert!(!vchunks.fields.iter().any(|f| f.key == "IDATCount"));
    }
}
