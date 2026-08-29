use crate::types::{Field, Section};
use lofty::file::AudioFile;
use lofty::prelude::{Accessor, ItemKey, TaggedFileExt};
use lofty::probe::Probe;
use lofty::tag::TagType;
use std::io::Cursor;

pub fn parse_audio(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();

    let tagged_file = Probe::new(Cursor::new(data))
        .guess_file_type()
        .map_err(|e| e.to_string())
        .and_then(|p| p.read().map_err(|e| e.to_string()));
    match tagged_file {
        Ok(tagged) => {
            let props = tagged.properties();
            let mut fmt = Section::new("audio-format", "Audio format");
            let d = props.duration().as_secs_f64();
            if d > 0.0 {
                fmt.add("DurationSeconds", format!("{d:.3}"), Some("Audio"));
            }
            if let Some(br) = props.audio_bitrate() {
                fmt.add("BitrateKbps", br.to_string(), Some("Audio"));
            }
            if let Some(sr) = props.sample_rate() {
                fmt.add("SampleRate", sr.to_string(), Some("Audio"));
            }
            if let Some(ch) = props.channels() {
                fmt.add("Channels", ch.to_string(), Some("Audio"));
            }
            if let Some(bd) = props.bit_depth() {
                fmt.add("BitDepth", bd.to_string(), Some("Audio"));
            }
            fmt.add(
                "OverallBitrate",
                props
                    .overall_bitrate()
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                Some("Audio"),
            );
            if !fmt.is_empty() {
                sections.push(fmt);
            }

            for tag in tagged.tags() {
                let ns = format!("Audio:{:?}", tag.tag_type());
                let mut sec = Section::new(
                    format!("audio-{:?}", tag.tag_type()).to_ascii_lowercase(),
                    format!("Audio tags ({:?})", tag.tag_type()),
                );
                if let Some(v) = tag.artist() {
                    sec.add("Artist", v.to_string(), Some(&ns));
                }
                if let Some(v) = tag.title() {
                    sec.add("Title", v.to_string(), Some(&ns));
                }
                if let Some(v) = tag.album() {
                    sec.add("Album", v.to_string(), Some(&ns));
                }
                if let Some(v) = tag.genre() {
                    sec.add("Genre", v.to_string(), Some(&ns));
                }
                if let Some(v) = tag.comment() {
                    sec.add("Comment", v.to_string(), Some(&ns));
                }
                if let Some(v) = tag.year() {
                    sec.add("Year", v.to_string(), Some(&ns));
                }
                if let Some(v) = tag.track() {
                    sec.add("Track", v.to_string(), Some(&ns));
                }
                for item in tag.items() {
                    let key = item_key_name(item.key());
                    let value = item_value(item);
                    if value.is_empty() {
                        continue;
                    }
                    if sec.fields.iter().any(|f| f.key == key && f.value == value) {
                        continue;
                    }
                    sec.fields.push(Field::new(key, value).with_namespace(&ns));
                }
                if tag.tag_type() == TagType::Id3v1 || tag.tag_type() == TagType::Id3v2 {
                    sec.id = match tag.tag_type() {
                        TagType::Id3v1 => "id3v1".into(),
                        _ => "id3v2".into(),
                    };
                }
                if !sec.is_empty() {
                    sections.push(sec);
                }
            }
        }
        Err(err) => {
            warnings.push(format!("Audio tag reader: {err}"));
            if data.starts_with(b"ID3") {
                sections.extend(parse_id3_fallback(data));
            }
        }
    }

    if data.starts_with(b"ID3") {
        let mut raw = Section::new("id3-header", "ID3 header");
        if data.len() >= 10 {
            raw.add("Version", format!("2.{}.{}", data[3], data[4]), Some("ID3"));
            raw.add("Flags", format!("0x{:02X}", data[5]), Some("ID3"));
            raw.add("Size", synchsafe(&data[6..10]).to_string(), Some("ID3"));
        }
        sections.insert(0, raw);
    }
    (sections, warnings)
}

fn item_key_name(key: &ItemKey) -> String {
    match key {
        ItemKey::Unknown(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

fn item_value(item: &lofty::tag::TagItem) -> String {
    use lofty::tag::ItemValue;
    match item.value() {
        ItemValue::Text(s) => s.clone(),
        ItemValue::Locator(s) => s.clone(),
        ItemValue::Binary(b) => format!("<{} bytes>", b.len()),
    }
}

fn synchsafe(b: &[u8]) -> u32 {
    if b.len() < 4 {
        return 0;
    }
    ((b[0] as u32 & 0x7F) << 21)
        | ((b[1] as u32 & 0x7F) << 14)
        | ((b[2] as u32 & 0x7F) << 7)
        | (b[3] as u32 & 0x7F)
}

fn parse_id3_fallback(data: &[u8]) -> Vec<Section> {
    let mut sec = Section::new("id3v2-raw", "ID3v2 frames");
    if data.len() < 10 {
        return vec![];
    }
    let size = synchsafe(&data[6..10]) as usize;
    let mut i = 10usize;
    let end = (10 + size).min(data.len());
    let v2 = data[3] == 2;
    while i + 8 < end {
        if data[i] == 0 {
            break;
        }
        let (id, flen, hdr) = if v2 {
            (
                String::from_utf8_lossy(&data[i..i + 3]).into_owned(),
                u32::from_be_bytes([0, data[i + 3], data[i + 4], data[i + 5]]) as usize,
                6usize,
            )
        } else {
            (
                String::from_utf8_lossy(&data[i..i + 4]).into_owned(),
                u32::from_be_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4])) as usize,
                10usize,
            )
        };
        if i + hdr + flen > data.len() {
            break;
        }
        let payload = &data[i + hdr..i + hdr + flen];
        let text = decode_id3_text(payload);
        sec.fields.push(
            Field::new(id, text)
                .with_namespace("ID3v2")
                .with_span(i as u64, (hdr + flen) as u64),
        );
        i += hdr + flen;
    }
    vec![sec]
}

fn decode_id3_text(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    match payload[0] {
        0 => String::from_utf8_lossy(&payload[1..])
            .trim_end_matches('\0')
            .to_string(),
        1 | 2 => encoding_rs::UTF_16LE
            .decode(&payload[1..])
            .0
            .trim_end_matches('\0')
            .to_string(),
        3 => String::from_utf8_lossy(&payload[1..])
            .trim_end_matches('\0')
            .to_string(),
        _ => String::from_utf8_lossy(payload).into_owned(),
    }
}
