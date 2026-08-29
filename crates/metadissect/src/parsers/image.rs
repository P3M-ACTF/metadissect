use crate::parsers::{jpeg, png, tiff, xmp};
use crate::types::{Field, Section};

pub fn parse_image(data: &[u8], mime: &str) -> (Vec<Section>, Vec<String>) {
    if mime.contains("jpeg") || mime.contains("jpg") || data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        let j = jpeg::parse_jpeg(data);
        let mut sections = j.sections;
        if let (Some(w), Some(h)) = (j.pixel_width, j.pixel_height) {
            let mut dim = Section::new("pixels", "Pixel dimensions");
            dim.add("PixelWidth", w.to_string(), Some("Image"));
            dim.add("PixelHeight", h.to_string(), Some("Image"));
            sections.push(dim);
        }
        return (sections, j.warnings);
    }
    if mime.contains("png") || data.starts_with(b"\x89PNG") {
        let p = png::parse_png(data);
        return (p.sections, p.warnings);
    }
    if mime.contains("tiff") || data.starts_with(b"II") || data.starts_with(b"MM") {
        let t = tiff::parse_tiff(data, 0);
        return (t.sections, t.warnings);
    }
    if mime.contains("gif") || data.starts_with(b"GIF8") {
        return parse_gif(data);
    }
    if mime.contains("webp")
        || (data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP")
    {
        return parse_webp(data);
    }
    if mime.contains("bmp") || data.starts_with(b"BM") {
        return parse_bmp(data);
    }
    if mime.contains("icon") || (data.len() >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 1) {
        return parse_ico(data);
    }
    if mime.contains("avif") || mime.contains("heic") || mime.contains("heif") {
        return parse_isobmff_image(data, mime);
    }
    (Vec::new(), vec!["No image-specific parser matched".into()])
}

fn parse_gif(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    if data.len() < 13 {
        warnings.push("GIF too short".into());
        return (sections, warnings);
    }
    let mut hdr = Section::new("gif-header", "GIF");
    hdr.add(
        "Version",
        String::from_utf8_lossy(&data[0..6]).into_owned(),
        Some("GIF"),
    );
    let w = u16::from_le_bytes([data[6], data[7]]);
    let h = u16::from_le_bytes([data[8], data[9]]);
    hdr.add("Width", w.to_string(), Some("GIF"));
    hdr.add("Height", h.to_string(), Some("GIF"));
    hdr.add("Packed", format!("0x{:02X}", data[10]), Some("GIF"));
    sections.push(hdr);

    let mut comments = Section::new("gif-comment", "GIF comments");
    let mut i = 13usize;
    // skip global color table
    let packed = data[10];
    if packed & 0x80 != 0 {
        let n = 1 << ((packed & 7) + 1);
        i += n * 3;
    }
    while i + 2 < data.len() {
        match data[i] {
            0x3B => break,
            0x2C => {
                if i + 10 > data.len() {
                    break;
                }
                let packed = data[i + 9];
                i += 10;
                if packed & 0x80 != 0 {
                    let n = 1 << ((packed & 7) + 1);
                    i += n * 3;
                }
                i += 1; // LZW min
                while i < data.len() && data[i] != 0 {
                    let sz = data[i] as usize;
                    i += 1 + sz;
                }
                i += 1;
            }
            0x21 => {
                if i + 2 >= data.len() {
                    break;
                }
                let label = data[i + 1];
                i += 2;
                let mut block = Vec::new();
                while i < data.len() && data[i] != 0 {
                    let sz = data[i] as usize;
                    i += 1;
                    if i + sz > data.len() {
                        break;
                    }
                    block.extend_from_slice(&data[i..i + sz]);
                    i += sz;
                }
                i += 1;
                if label == 0xFE {
                    comments.add(
                        "Comment",
                        String::from_utf8_lossy(&block).into_owned(),
                        Some("GIF:COM"),
                    );
                } else if label == 0xFF && block.starts_with(b"XMP DataXMP") {
                    if let Some(xml) = xmp::extract_xmp_from_bytes(&block) {
                        let sec = xmp::parse_xmp(&xml, "XMP");
                        if !sec.is_empty() {
                            sections.push(sec);
                        }
                    }
                } else {
                    let mut ext = Section::new(format!("gif-ext-{label:02x}"), "GIF extension");
                    ext.add("Label", format!("0x{label:02X}"), Some("GIF"));
                    ext.add("Bytes", block.len().to_string(), Some("GIF"));
                    sections.push(ext);
                }
            }
            _ => i += 1,
        }
    }
    if !comments.is_empty() {
        sections.push(comments);
    }
    (sections, warnings)
}

fn parse_webp(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    if data.len() < 12 {
        warnings.push("WEBP too short".into());
        return (sections, warnings);
    }
    let mut i = 12usize;
    let mut chunks = Section::new("webp-chunks", "WebP chunks");
    while i + 8 <= data.len() {
        let fourcc = String::from_utf8_lossy(&data[i..i + 4]).into_owned();
        let size = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap()) as usize;
        let start = i + 8;
        let end = (start + size).min(data.len());
        let payload = &data[start..end];
        chunks.fields.push(
            Field::new(fourcc.clone(), format!("{size} bytes"))
                .with_namespace("WebP")
                .with_span(i as u64, (8 + size) as u64),
        );
        match fourcc.as_str() {
            "VP8X" if payload.len() >= 10 => {
                let mut s = Section::new("webp-vp8x", "WebP VP8X");
                let w = 1 + u32::from_le_bytes([payload[4], payload[5], payload[6], 0]);
                let h = 1 + u32::from_le_bytes([payload[7], payload[8], payload[9], 0]);
                s.add("Width", w.to_string(), Some("WebP"));
                s.add("Height", h.to_string(), Some("WebP"));
                s.add("Flags", format!("0x{:02X}", payload[0]), Some("WebP"));
                sections.push(s);
            }
            "VP8 " if payload.len() >= 10 => {
                let mut s = Section::new("webp-vp8", "WebP VP8");
                // frame tag + start code
                if payload.len() >= 10
                    && payload[3] == 0x9D
                    && payload[4] == 0x01
                    && payload[5] == 0x2A
                {
                    let w = u16::from_le_bytes([payload[6], payload[7]]) & 0x3FFF;
                    let h = u16::from_le_bytes([payload[8], payload[9]]) & 0x3FFF;
                    s.add("Width", w.to_string(), Some("WebP"));
                    s.add("Height", h.to_string(), Some("WebP"));
                }
                sections.push(s);
            }
            "EXIF" => {
                let parsed = tiff::parse_tiff(payload, start as u64);
                warnings.extend(parsed.warnings);
                sections.extend(parsed.sections);
            }
            "XMP " => {
                if let Some(xml) = xmp::extract_xmp_from_bytes(payload)
                    .or_else(|| String::from_utf8(payload.to_vec()).ok())
                {
                    let sec = xmp::parse_xmp(&xml, "XMP");
                    if !sec.is_empty() {
                        sections.push(sec);
                    }
                }
            }
            "ICCP" => {
                let mut s = Section::new("webp-icc", "WebP ICC");
                s.add("Size", payload.len().to_string(), Some("WebP:ICC"));
                sections.push(s);
            }
            _ => {}
        }
        i = end + (size % 2);
    }
    sections.insert(0, chunks);
    (sections, warnings)
}

fn parse_bmp(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let warnings = Vec::new();
    if data.len() < 26 {
        return (sections, vec!["BMP too short".into()]);
    }
    let mut s = Section::new("bmp", "BMP");
    s.add(
        "FileSize",
        u32::from_le_bytes(data[2..6].try_into().unwrap()).to_string(),
        Some("BMP"),
    );
    let dib = u32::from_le_bytes(data[14..18].try_into().unwrap());
    s.add("DibHeaderSize", dib.to_string(), Some("BMP"));
    if data.len() >= 26 {
        let w = i32::from_le_bytes(data[18..22].try_into().unwrap());
        let h = i32::from_le_bytes(data[22..26].try_into().unwrap());
        s.add("Width", w.to_string(), Some("BMP"));
        s.add("Height", h.abs().to_string(), Some("BMP"));
    }
    if data.len() >= 28 {
        s.add(
            "Planes",
            u16::from_le_bytes(data[26..28].try_into().unwrap()).to_string(),
            Some("BMP"),
        );
    }
    if data.len() >= 30 {
        s.add(
            "BitCount",
            u16::from_le_bytes(data[28..30].try_into().unwrap()).to_string(),
            Some("BMP"),
        );
    }
    sections.push(s);
    (sections, warnings)
}

fn parse_ico(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    if data.len() < 6 {
        return (sections, vec!["ICO too short".into()]);
    }
    let count = u16::from_le_bytes([data[4], data[5]]) as usize;
    let mut s = Section::new("ico", "ICO");
    s.add("ImageCount", count.to_string(), Some("ICO"));
    for i in 0..count {
        let off = 6 + i * 16;
        if off + 16 > data.len() {
            break;
        }
        let w = if data[off] == 0 {
            256
        } else {
            data[off] as u16
        };
        let h = if data[off + 1] == 0 {
            256
        } else {
            data[off + 1] as u16
        };
        s.add(format!("Image{i}Width"), w.to_string(), Some("ICO"));
        s.add(format!("Image{i}Height"), h.to_string(), Some("ICO"));
        s.add(
            format!("Image{i}Bytes"),
            u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()).to_string(),
            Some("ICO"),
        );
    }
    sections.push(s);
    (sections, Vec::new())
}

fn parse_isobmff_image(data: &[u8], mime: &str) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    let mut info = Section::new("heif", "ISO-BMFF image");
    info.add("DeclaredMime", mime.to_string(), Some("HEIF"));
    if data.len() >= 12 {
        info.add(
            "Brand",
            String::from_utf8_lossy(&data[8..12]).into_owned(),
            Some("HEIF"),
        );
    }
    sections.push(info);
    if let Some(pos) = crate::parsers::xmp::find_subsequence(data, b"Exif\0\0") {
        let parsed = tiff::parse_tiff(&data[pos + 6..], (pos + 6) as u64);
        warnings.extend(parsed.warnings);
        sections.extend(parsed.sections);
    } else {
        warnings.push(
            "HEIC/AVIF: no item/iloc tree and no pixel decode (libheif is optional and off by default). Only brands and a raw EXIF/XMP scan are shown.".into(),
        );
    }
    if let Some(xml) = xmp::extract_xmp_from_bytes(data) {
        let sec = xmp::parse_xmp(&xml, "XMP");
        if !sec.is_empty() {
            sections.push(sec);
        }
    }
    (sections, warnings)
}
