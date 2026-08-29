use crate::parsers::xmp;
use crate::types::{Field, Section};

pub fn parse_video(data: &[u8], mime: &str) -> (Vec<Section>, Vec<String>) {
    if mime.contains("matroska")
        || mime.contains("webm")
        || data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
    {
        return parse_mkv(data);
    }
    if mime.contains("avi")
        || (data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"AVI ")
    {
        return parse_avi(data);
    }
    if data.len() >= 8 && &data[4..8] == b"ftyp"
        || mime.contains("mp4")
        || mime.contains("quicktime")
    {
        return parse_mp4(data);
    }
    (Vec::new(), vec!["No video parser matched".into()])
}

pub fn parse_mp4(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    let mut atoms = Section::new("mp4-atoms", "MP4 / QuickTime atoms");
    walk_atoms(
        data,
        0,
        data.len(),
        0,
        &mut atoms,
        &mut sections,
        &mut warnings,
    );
    if !atoms.is_empty() {
        sections.insert(0, atoms);
    }
    (sections, warnings)
}

fn walk_atoms(
    data: &[u8],
    start: usize,
    end: usize,
    depth: u8,
    atoms: &mut Section,
    sections: &mut Vec<Section>,
    warnings: &mut Vec<String>,
) {
    if depth > 12 {
        return;
    }
    let mut i = start;
    while i + 8 <= end {
        let size32 = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        let typ = &data[i + 4..i + 8];
        let name = String::from_utf8_lossy(typ).into_owned();
        let (hdr, total) = if size32 == 1 && i + 16 <= end {
            let size64 = u64::from_be_bytes(data[i + 8..i + 16].try_into().unwrap()) as usize;
            (16usize, size64)
        } else if size32 == 0 {
            (8usize, end - i)
        } else {
            (8usize, size32)
        };
        if total < hdr || i + total > data.len() {
            warnings.push(format!("Truncated atom {name} at {i}"));
            break;
        }
        let payload_s = i + hdr;
        let payload_e = i + total;
        atoms.fields.push(
            Field::new(
                format!("{}{}", "  ".repeat(depth as usize), name),
                format!("offset={i} size={total}"),
            )
            .with_namespace("MP4")
            .with_span(i as u64, total as u64),
        );
        let payload = &data[payload_s..payload_e];
        match name.as_str() {
            "ftyp" if payload.len() >= 8 => {
                let mut s = Section::new("mp4-ftyp", "MP4 ftyp");
                s.add(
                    "MajorBrand",
                    String::from_utf8_lossy(&payload[0..4]).into_owned(),
                    Some("MP4:ftyp"),
                );
                s.add(
                    "MinorVersion",
                    u32::from_be_bytes(payload[4..8].try_into().unwrap()).to_string(),
                    Some("MP4:ftyp"),
                );
                let mut brands = Vec::new();
                let mut b = 8;
                while b + 4 <= payload.len() {
                    brands.push(String::from_utf8_lossy(&payload[b..b + 4]).into_owned());
                    b += 4;
                }
                if !brands.is_empty() {
                    s.add("CompatibleBrands", brands.join(","), Some("MP4:ftyp"));
                }
                sections.push(s);
            }
            "mvhd" => sections.push(parse_mvhd(payload, i as u64)),
            "tkhd" => sections.push(parse_tkhd(payload, i as u64)),
            "mdhd" => sections.push(parse_mdhd(payload, i as u64)),
            "hdlr" if payload.len() >= 12 => {
                let mut s = Section::new("mp4-hdlr", "MP4 handler");
                if payload.len() >= 16 {
                    s.add(
                        "HandlerType",
                        String::from_utf8_lossy(&payload[8..12]).into_owned(),
                        Some("MP4:hdlr"),
                    );
                }
                if payload.len() > 16 {
                    let name = String::from_utf8_lossy(&payload[16..])
                        .trim_end_matches('\0')
                        .to_string();
                    if !name.is_empty() {
                        s.add("HandlerName", name, Some("MP4:hdlr"));
                    }
                }
                sections.push(s);
            }
            "elst" | "stsd" | "stts" | "stss" | "stsc" | "stsz" | "stco" | "co64" => {
                let mut s = Section::new(format!("mp4-{name}"), format!("MP4 {name}"));
                s.add("Size", payload.len().to_string(), Some("MP4"));
                if name == "stsd" && payload.len() >= 16 {
                    s.add(
                        "Codec",
                        String::from_utf8_lossy(&payload[12..16]).into_owned(),
                        Some("MP4:stsd"),
                    );
                }
                sections.push(s);
            }
            "udta" | "meta" | "ilst" | "moov" | "trak" | "mdia" | "minf" | "stbl" | "edts"
            | "dinf" => {
                let inner_start = if name == "meta" && payload.len() >= 4 {
                    payload_s + 4
                } else {
                    payload_s
                };
                walk_atoms(
                    data,
                    inner_start,
                    payload_e,
                    depth + 1,
                    atoms,
                    sections,
                    warnings,
                );
            }
            other
                if other.starts_with('©')
                    || other == "xyz "
                    || other == "name"
                    || other == "data" =>
            {
                let mut s = Section::new("mp4-udta-item", "MP4 user data");
                let text = String::from_utf8_lossy(payload)
                    .trim_matches('\0')
                    .trim()
                    .to_string();
                s.fields.push(
                    Field::new(name, text)
                        .with_namespace("MP4:udta")
                        .with_span(i as u64, total as u64),
                );
                sections.push(s);
            }
            _ => {}
        }
        i += total;
        if total == 0 {
            break;
        }
    }
}

fn mp4_time(v: u64) -> String {
    if v == 0 {
        return "0".into();
    }
    // seconds since 1904-01-01
    let unix = v as i64 - 2082844800;
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| v.to_string())
}

fn parse_mvhd(payload: &[u8], offset: u64) -> Section {
    let mut s = Section::new("mp4-mvhd", "MP4 movie header");
    if payload.is_empty() {
        return s;
    }
    let version = payload[0];
    s.add("Version", version.to_string(), Some("MP4:mvhd"));
    if version == 1 && payload.len() >= 32 {
        let ctime = u64::from_be_bytes(payload[4..12].try_into().unwrap());
        let mtime = u64::from_be_bytes(payload[12..20].try_into().unwrap());
        let timescale = u32::from_be_bytes(payload[20..24].try_into().unwrap());
        let duration = u64::from_be_bytes(payload[24..32].try_into().unwrap());
        s.add("CreationTime", mp4_time(ctime), Some("MP4:mvhd"));
        s.add("ModificationTime", mp4_time(mtime), Some("MP4:mvhd"));
        s.add("Timescale", timescale.to_string(), Some("MP4:mvhd"));
        if timescale > 0 {
            s.add(
                "DurationSeconds",
                format!("{:.3}", duration as f64 / timescale as f64),
                Some("MP4:mvhd"),
            );
        }
    } else if payload.len() >= 20 {
        let ctime = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as u64;
        let mtime = u32::from_be_bytes(payload[8..12].try_into().unwrap()) as u64;
        let timescale = u32::from_be_bytes(payload[12..16].try_into().unwrap());
        let duration = u32::from_be_bytes(payload[16..20].try_into().unwrap()) as u64;
        s.add("CreationTime", mp4_time(ctime), Some("MP4:mvhd"));
        s.add("ModificationTime", mp4_time(mtime), Some("MP4:mvhd"));
        s.add("Timescale", timescale.to_string(), Some("MP4:mvhd"));
        if timescale > 0 {
            s.add(
                "DurationSeconds",
                format!("{:.3}", duration as f64 / timescale as f64),
                Some("MP4:mvhd"),
            );
        }
    }
    let _ = offset;
    s
}

fn parse_tkhd(payload: &[u8], _offset: u64) -> Section {
    let mut s = Section::new("mp4-tkhd", "MP4 track header");
    if payload.len() < 4 {
        return s;
    }
    let version = payload[0];
    s.add("Version", version.to_string(), Some("MP4:tkhd"));
    let (id_off, wh_off) = if version == 1 { (20, 88) } else { (12, 76) };
    if payload.len() >= id_off + 4 {
        s.add(
            "TrackId",
            u32::from_be_bytes(payload[id_off..id_off + 4].try_into().unwrap()).to_string(),
            Some("MP4:tkhd"),
        );
    }
    if payload.len() >= wh_off + 8 {
        let w = u32::from_be_bytes(payload[wh_off..wh_off + 4].try_into().unwrap()) >> 16;
        let h = u32::from_be_bytes(payload[wh_off + 4..wh_off + 8].try_into().unwrap()) >> 16;
        if w > 0 {
            s.add("Width", w.to_string(), Some("MP4:tkhd"));
        }
        if h > 0 {
            s.add("Height", h.to_string(), Some("MP4:tkhd"));
        }
    }
    s
}

fn parse_mdhd(payload: &[u8], _offset: u64) -> Section {
    let mut s = Section::new("mp4-mdhd", "MP4 media header");
    if payload.is_empty() {
        return s;
    }
    let version = payload[0];
    if version == 1 && payload.len() >= 32 {
        let timescale = u32::from_be_bytes(payload[20..24].try_into().unwrap());
        let duration = u64::from_be_bytes(payload[24..32].try_into().unwrap());
        s.add("Timescale", timescale.to_string(), Some("MP4:mdhd"));
        if timescale > 0 {
            s.add(
                "DurationSeconds",
                format!("{:.3}", duration as f64 / timescale as f64),
                Some("MP4:mdhd"),
            );
        }
    } else if payload.len() >= 20 {
        let timescale = u32::from_be_bytes(payload[12..16].try_into().unwrap());
        let duration = u32::from_be_bytes(payload[16..20].try_into().unwrap());
        s.add("Timescale", timescale.to_string(), Some("MP4:mdhd"));
        if timescale > 0 {
            s.add(
                "DurationSeconds",
                format!("{:.3}", duration as f64 / timescale as f64),
                Some("MP4:mdhd"),
            );
        }
        if payload.len() >= 24 {
            let lang = u16::from_be_bytes(payload[20..22].try_into().unwrap());
            s.add("LanguagePacked", format!("0x{lang:04X}"), Some("MP4:mdhd"));
        }
    }
    s
}

fn parse_mkv(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let warnings = Vec::new();
    let mut hdr = Section::new("mkv-ebml", "Matroska / WebM");
    hdr.add("EBML", "1A 45 DF A3", Some("MKV"));
    let mut i = 0;
    let mut found = 0;
    while i < data.len() && found < 80 {
        let Some((id, id_len)) = read_vint_id(&data[i..]) else {
            break;
        };
        let Some((size, size_len)) = read_vint(&data[i + id_len..]) else {
            break;
        };
        let hdr_len = id_len + size_len;
        let payload_s = i + hdr_len;
        let payload_e = (payload_s + size as usize).min(data.len());
        if let Some(name) = mkv_id_name(id) {
            let payload = &data[payload_s..payload_e];
            let master = matches!(
                name,
                "EBML" | "Segment" | "Info" | "Tracks" | "TrackEntry" | "Tags" | "SeekHead"
            );
            if master {
                hdr.add(name, format!("master @0x{i:X} {size} bytes"), Some("MKV"));
                found += 1;
                i = payload_s;
                continue;
            }
            match name {
                "Title" | "MuxingApp" | "WritingApp" | "DocType" | "CodecID" => {
                    hdr.add(
                        name,
                        String::from_utf8_lossy(payload).into_owned(),
                        Some("MKV"),
                    );
                }
                "TrackNumber" | "TrackType" | "TimestampScale" => {
                    let n = match payload.len() {
                        1 => payload[0] as u64,
                        2 => u16::from_be_bytes(payload.try_into().ok().unwrap_or([0; 2])) as u64,
                        4 => u32::from_be_bytes(payload.try_into().ok().unwrap_or([0; 4])) as u64,
                        8 => u64::from_be_bytes(payload.try_into().ok().unwrap_or([0; 8])),
                        _ => payload.len() as u64,
                    };
                    hdr.add(name, n.to_string(), Some("MKV"));
                }
                "Duration" => {
                    if payload.len() == 8 {
                        let bits = u64::from_be_bytes(payload.try_into().unwrap());
                        hdr.add("Duration", f64::from_bits(bits).to_string(), Some("MKV"));
                    } else if payload.len() == 4 {
                        let bits = u32::from_be_bytes(payload.try_into().unwrap());
                        hdr.add("Duration", f32::from_bits(bits).to_string(), Some("MKV"));
                    }
                }
                "DateUTC" if payload.len() == 8 => {
                    let ns = i64::from_be_bytes(payload.try_into().unwrap());
                    let unix = 978307200 + ns / 1_000_000_000; // 2001-01-01 + ns
                    hdr.add(
                        "DateUTC",
                        chrono::DateTime::from_timestamp(unix, 0)
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_else(|| ns.to_string()),
                        Some("MKV"),
                    );
                }
                other => {
                    hdr.fields.push(
                        Field::new(other, format!("{} bytes", payload.len()))
                            .with_namespace("MKV")
                            .with_span(i as u64, (hdr_len + payload.len()) as u64),
                    );
                }
            }
            found += 1;
        }
        i = if size == 0xFFFFFFFFFFFFFF {
            i + hdr_len + 1
        } else {
            payload_e
        };
        if i <= payload_s {
            i += 1;
        }
    }
    if let Some(xml) = xmp::extract_xmp_from_bytes(data) {
        let sec = xmp::parse_xmp(&xml, "XMP");
        if !sec.is_empty() {
            sections.push(sec);
        }
    }
    sections.push(hdr);
    (sections, warnings)
}

fn read_vint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = first.leading_zeros() as usize + 1;
    if len == 0 || len > 8 || data.len() < len {
        return None;
    }
    let mut v = (first as u64) & (0xFF >> len);
    for b in &data[1..len] {
        v = (v << 8) | *b as u64;
    }
    Some((v, len))
}

fn read_vint_id(data: &[u8]) -> Option<(u32, usize)> {
    let first = *data.first()?;
    let len = first.leading_zeros() as usize + 1;
    if len == 0 || len > 4 || data.len() < len {
        return None;
    }
    let mut v = 0u32;
    for b in &data[..len] {
        v = (v << 8) | *b as u32;
    }
    Some((v, len))
}

fn mkv_id_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0x1A45DFA3 => "EBML",
        0x4282 => "DocType",
        0x4287 => "DocTypeVersion",
        0x18538067 => "Segment",
        0x114D9B74 => "SeekHead",
        0x1549A966 => "Info",
        0x2AD7B1 => "TimestampScale",
        0x4489 => "Duration",
        0x7BA9 => "Title",
        0x4D80 => "MuxingApp",
        0x5741 => "WritingApp",
        0x4461 => "DateUTC",
        0x1654AE6B => "Tracks",
        0xAE => "TrackEntry",
        0xD7 => "TrackNumber",
        0x83 => "TrackType",
        0x86 => "CodecID",
        0x1C53BB6B => "Cues",
        0x1254C367 => "Tags",
        0x1941A469 => "Attachments",
        0x1043A770 => "Chapters",
        _ => return None,
    })
}

fn parse_avi(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut s = Section::new("avi", "AVI RIFF");
    s.add("FormType", "AVI", Some("AVI"));
    let mut i = 12usize;
    while i + 8 <= data.len() && s.fields.len() < 160 {
        let id = String::from_utf8_lossy(&data[i..i + 4]).into_owned();
        let size = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap()) as usize;
        let start = i + 8;
        let end = (start + size).min(data.len());
        s.fields.push(
            Field::new(id.clone(), format!("{size} bytes"))
                .with_namespace("AVI")
                .with_span(i as u64, (8 + size) as u64),
        );
        if id == "LIST" && start + 4 <= end {
            let list_type = String::from_utf8_lossy(&data[start..start + 4]).into_owned();
            s.add("LIST", list_type, Some("AVI"));
            let mut j = start + 4;
            while j + 8 <= end && s.fields.len() < 160 {
                let cid = String::from_utf8_lossy(&data[j..j + 4]).into_owned();
                let csize = u32::from_le_bytes(data[j + 4..j + 8].try_into().unwrap()) as usize;
                let cstart = j + 8;
                let cend = (cstart + csize).min(end);
                if matches!(
                    cid.as_str(),
                    "IDIT" | "ISFT" | "INAM" | "ICMT" | "IART" | "ICOP"
                ) {
                    s.add(
                        cid,
                        String::from_utf8_lossy(&data[cstart..cend])
                            .trim_end_matches('\0')
                            .to_string(),
                        Some("AVI:INFO"),
                    );
                } else if cid == "avih" && csize >= 36 && cstart + 36 <= data.len() {
                    let usec = u32::from_le_bytes(data[cstart..cstart + 4].try_into().unwrap());
                    let frames =
                        u32::from_le_bytes(data[cstart + 16..cstart + 20].try_into().unwrap());
                    let w = u32::from_le_bytes(data[cstart + 32..cstart + 36].try_into().unwrap());
                    s.add("MicroSecPerFrame", usec.to_string(), Some("AVI:avih"));
                    s.add("TotalFrames", frames.to_string(), Some("AVI:avih"));
                    s.add("Width", w.to_string(), Some("AVI:avih"));
                } else {
                    s.fields.push(
                        Field::new(cid, format!("{csize} bytes"))
                            .with_namespace("AVI:LIST")
                            .with_span(j as u64, (8 + csize) as u64),
                    );
                }
                j = cend + (csize % 2);
            }
        }
        if matches!(id.as_str(), "IDIT" | "ISFT" | "INAM" | "ICMT") {
            s.add(
                id,
                String::from_utf8_lossy(&data[start..end])
                    .trim_end_matches('\0')
                    .to_string(),
                Some("AVI:INFO"),
            );
        }
        i = end + (size % 2);
    }
    sections.push(s);
    (sections, Vec::new())
}
