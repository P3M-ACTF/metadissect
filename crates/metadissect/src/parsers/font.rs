use crate::types::{Field, Section};

pub fn parse_font(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    if data.starts_with(b"wOFF") {
        let mut s = Section::new("woff", "WOFF font");
        if data.len() >= 12 {
            s.add(
                "Flavor",
                String::from_utf8_lossy(&data[4..8]).into_owned(),
                Some("WOFF"),
            );
            s.add(
                "Length",
                u32::from_be_bytes(data[8..12].try_into().unwrap()).to_string(),
                Some("WOFF"),
            );
        }
        sections.push(s);
        return (sections, warnings);
    }
    if data.len() < 12 {
        warnings.push("Font too short".into());
        return (sections, warnings);
    }
    let num_tables = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut tables = Section::new("font-tables", "Font tables");
    tables.add("TableCount", num_tables.to_string(), Some("Font"));
    let mut name_off = None;
    let mut name_len = 0;
    for i in 0..num_tables {
        let o = 12 + i * 16;
        if o + 16 > data.len() {
            break;
        }
        let tag = String::from_utf8_lossy(&data[o..o + 4]).into_owned();
        let offset = u32::from_be_bytes(data[o + 8..o + 12].try_into().unwrap()) as usize;
        let length = u32::from_be_bytes(data[o + 12..o + 16].try_into().unwrap()) as usize;
        tables.fields.push(
            Field::new(tag.clone(), format!("offset={offset} length={length}"))
                .with_namespace("Font")
                .with_span(offset as u64, length as u64),
        );
        if tag == "name" {
            name_off = Some(offset);
            name_len = length;
        }
    }
    sections.push(tables);
    if let Some(off) = name_off {
        if let Some(sec) = parse_name_table(data, off, name_len) {
            sections.push(sec);
        }
    }
    (sections, warnings)
}

fn parse_name_table(data: &[u8], offset: usize, length: usize) -> Option<Section> {
    if offset + 6 > data.len() {
        return None;
    }
    let table = &data[offset..(offset + length).min(data.len())];
    let count = u16::from_be_bytes(table[2..4].try_into().ok()?) as usize;
    let string_off = u16::from_be_bytes(table[4..6].try_into().ok()?) as usize;
    let mut sec = Section::new("font-name", "Font name table");
    for i in 0..count {
        let e = 6 + i * 12;
        if e + 12 > table.len() {
            break;
        }
        let platform = u16::from_be_bytes(table[e..e + 2].try_into().ok()?);
        let encoding = u16::from_be_bytes(table[e + 2..e + 4].try_into().ok()?);
        let lang = u16::from_be_bytes(table[e + 4..e + 6].try_into().ok()?);
        let name_id = u16::from_be_bytes(table[e + 6..e + 8].try_into().ok()?);
        let len = u16::from_be_bytes(table[e + 8..e + 10].try_into().ok()?) as usize;
        let so = u16::from_be_bytes(table[e + 10..e + 12].try_into().ok()?) as usize;
        let start = string_off + so;
        if start + len > table.len() {
            continue;
        }
        let raw = &table[start..start + len];
        let value = if platform == 0 || platform == 3 {
            utf16be(raw)
        } else {
            String::from_utf8_lossy(raw).into_owned()
        };
        if value.trim().is_empty() {
            continue;
        }
        sec.fields.push(
            Field::new(name_id_label(name_id), value.trim().to_string())
                .with_namespace("Font:name")
                .with_raw(serde_json::json!({
                    "nameId": name_id,
                    "platform": platform,
                    "encoding": encoding,
                    "language": lang
                })),
        );
    }
    Some(sec)
}

fn utf16be(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks(2)
        .filter_map(|c| {
            if c.len() == 2 {
                Some(u16::from_be_bytes([c[0], c[1]]))
            } else {
                None
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn name_id_label(id: u16) -> String {
    match id {
        0 => "Copyright",
        1 => "FontFamily",
        2 => "FontSubfamily",
        3 => "UniqueId",
        4 => "FullName",
        5 => "Version",
        6 => "PostScriptName",
        7 => "Trademark",
        8 => "Manufacturer",
        9 => "Designer",
        10 => "Description",
        11 => "VendorURL",
        12 => "DesignerURL",
        13 => "License",
        14 => "LicenseURL",
        16 => "TypographicFamily",
        17 => "TypographicSubfamily",
        18 => "CompatibleFull",
        19 => "SampleText",
        _ => return format!("NameId_{id}"),
    }
    .to_string()
}
