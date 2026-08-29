use crate::embed;
use crate::parsers::xmp;
use crate::types::{Field, Section};
use lopdf::{Document, Object};

pub fn parse_pdf(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    parse_pdf_at_depth(data, 0, embed::DEFAULT_MAX_EMBED_DEPTH)
}

pub fn parse_pdf_at_depth(data: &[u8], depth: u8, max_depth: u8) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();

    let mut header = Section::new("pdf-header", "PDF header");
    if let Some(line) = data.split(|&b| b == b'\n' || b == b'\r').next() {
        header.add(
            "VersionLine",
            String::from_utf8_lossy(line).trim().to_string(),
            Some("PDF"),
        );
    }
    let eof_count = data.windows(5).filter(|w| w == b"%%EOF").count();
    header.add("EofMarkers", eof_count.to_string(), Some("PDF"));
    if eof_count > 1 {
        header.add("IncrementalUpdates", "true", Some("PDF"));
        warnings.push("PDF has multiple %%EOF markers (incremental updates)".into());
    }
    let has_js = contains_ci(data, b"/JavaScript") || contains_ci(data, b"/JS");
    header.add("EmbeddedJavaScriptHint", has_js.to_string(), Some("PDF"));
    if has_js {
        warnings.push("PDF may contain embedded JavaScript".into());
    }
    sections.push(header);

    match Document::load_mem(data) {
        Ok(doc) => {
            let mut info_sec = Section::new("pdf-info", "PDF Info dictionary");
            if let Ok(Object::Reference(id)) = doc.trailer.get(b"Info") {
                if let Ok(Object::Dictionary(dict)) = doc.get_object(*id) {
                    for (k, v) in dict.iter() {
                        let key = String::from_utf8_lossy(k).into_owned();
                        info_sec
                            .fields
                            .push(Field::new(key, object_to_string(v)).with_namespace("PDF:Info"));
                    }
                }
            }
            if !info_sec.is_empty() {
                sections.push(info_sec);
            }

            let mut xref = Section::new("pdf-xref", "PDF structure");
            xref.add("ObjectCount", doc.objects.len().to_string(), Some("PDF"));
            xref.add("MaxId", format!("{:?}", doc.max_id), Some("PDF"));
            if let Ok(root) = doc.trailer.get(b"Root") {
                xref.add("Root", format!("{root:?}"), Some("PDF"));
            }
            sections.push(xref);

            if let Some(xml) =
                extract_xmp_from_doc(&doc).or_else(|| xmp::extract_xmp_from_bytes(data))
            {
                let sec = xmp::parse_xmp(&xml, "XMP:PDF");
                if !sec.is_empty() {
                    sections.push(sec);
                }
            }
        }
        Err(err) => {
            warnings.push(format!("PDF parser: {err}"));
            if let Some(xml) = xmp::extract_xmp_from_bytes(data) {
                let sec = xmp::parse_xmp(&xml, "XMP:PDF");
                if !sec.is_empty() {
                    sections.push(sec);
                }
            }
        }
    }

    let (hits, embed_scan_warns) = embed::collect_pdf_embeds(data);
    warnings.extend(embed_scan_warns);
    if !hits.is_empty() {
        let mut emb = Section::new("pdf-embeds", "PDF embedded files");
        emb.add("EmbedCandidateCount", hits.len().to_string(), Some("Embed"));
        sections.push(emb);
        let (embed_secs, embed_warns) = embed::parse_embeds(&hits, depth, max_depth);
        warnings.extend(embed_warns);
        sections.extend(embed_secs);
    }

    (sections, warnings)
}

fn extract_xmp_from_doc(doc: &Document) -> Option<String> {
    let root = doc.trailer.get(b"Root").ok()?;
    let id = match root {
        Object::Reference(r) => *r,
        _ => return None,
    };
    let Object::Dictionary(catalog) = doc.get_object(id).ok()? else {
        return None;
    };
    let meta = catalog.get(b"Metadata").ok()?;
    let mid = match meta {
        Object::Reference(r) => *r,
        _ => return None,
    };
    match doc.get_object(mid).ok()? {
        Object::Stream(s) => String::from_utf8(s.content.clone()).ok(),
        _ => None,
    }
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String(s, _) => match String::from_utf8(s.clone()) {
            Ok(t) => t,
            Err(_) => String::from_utf8_lossy(s).into_owned(),
        },
        Object::Name(n) => String::from_utf8_lossy(n).into_owned(),
        Object::Integer(i) => i.to_string(),
        Object::Real(r) => r.to_string(),
        Object::Boolean(b) => b.to_string(),
        Object::Null => "null".into(),
        other => format!("{other:?}"),
    }
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}
