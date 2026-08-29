use crate::parsers::xml_util::{attr_value, decode_text, general_ref_text};
use crate::types::{Field, Section};
use quick_xml::events::Event;
use quick_xml::Reader;

pub fn parse_xmp(xml: &str, namespace: &str) -> Section {
    let mut section = Section::new(
        format!("xmp-{}", namespace.to_ascii_lowercase().replace(':', "-")),
        format!("XMP ({namespace})"),
    );
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut path: Vec<String> = Vec::new();
    let mut pending = String::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                flush_text(&mut pending, &path, &mut section, namespace);
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let local = local_name(&name);
                for attr in e.attributes().flatten() {
                    let an = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                    let av = attr_value(&attr);
                    if av.trim().is_empty() {
                        continue;
                    }
                    let key = format!("{}@{}", local, local_name(&an));
                    section
                        .fields
                        .push(Field::new(key, av).with_namespace(namespace));
                }
                path.push(local);
            }
            Ok(Event::Text(t)) => pending.push_str(&decode_text(&t)),
            Ok(Event::GeneralRef(r)) => pending.push_str(&general_ref_text(&r)),
            Ok(Event::End(_)) => {
                flush_text(&mut pending, &path, &mut section, namespace);
                path.pop();
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    section
}

fn flush_text(pending: &mut String, path: &[String], section: &mut Section, namespace: &str) {
    let text = pending.trim().to_string();
    pending.clear();
    if text.is_empty() {
        return;
    }
    let key = path.last().cloned().unwrap_or_else(|| "value".into());
    if !is_noise(&key) {
        section
            .fields
            .push(Field::new(key, text).with_namespace(namespace));
    }
}

pub fn extract_xmp_from_bytes(data: &[u8]) -> Option<String> {
    let start = find_subsequence(data, b"<x:xmpmeta")
        .or_else(|| find_subsequence(data, b"<xmpmeta"))
        .or_else(|| find_subsequence(data, b"<?xpacket"))?;
    let end_tag = b"</x:xmpmeta>";
    let end = find_subsequence(&data[start..], end_tag)
        .map(|i| start + i + end_tag.len())
        .or_else(|| {
            find_subsequence(&data[start..], b"<?xpacket end")
                .map(|i| start + i + 32)
                .map(|e| e.min(data.len()))
        })?;
    String::from_utf8(data[start..end.min(data.len())].to_vec()).ok()
}

fn local_name(q: &str) -> String {
    q.rsplit(':').next().unwrap_or(q).to_string()
}

fn is_noise(key: &str) -> bool {
    matches!(
        key,
        "xmpmeta" | "RDF" | "Description" | "Seq" | "Alt" | "Bag" | "li" | "xpacket"
    )
}

pub fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
