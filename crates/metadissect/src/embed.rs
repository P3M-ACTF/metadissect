//! Recursive extraction of nested embeds (OOXML media/embeddings, PDF EmbeddedFile).
//! Depth-limited; each nested analysis is anchored (path / page hint when known).

use crate::magic::inspect_magic;
use crate::parsers;
use crate::types::{Field, Section};

pub const DEFAULT_MAX_EMBED_DEPTH: u8 = 2;

pub struct EmbedHit {
    pub name: String,
    pub data: Vec<u8>,
    /// Human anchor: zip path, "page N", slide, etc.
    pub anchor: String,
}

/// Recursively parse embed bytes into labeled sections (does not recompute hashes).
pub fn parse_embeds(hits: &[EmbedHit], depth: u8, max_depth: u8) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    if depth >= max_depth {
        if !hits.is_empty() {
            warnings.push(format!(
                "Embed recursion stopped at depth {max_depth} ({} nested object(s) skipped).",
                hits.len()
            ));
        }
        return (sections, warnings);
    }

    for hit in hits {
        if hit.data.is_empty() {
            continue;
        }
        let magic = inspect_magic(&hit.data);
        let mime = magic.mime.clone();
        let (nested, warns) = parsers::parse_for_mime_at_depth(
            &hit.data,
            &mime,
            Some(&hit.name),
            depth + 1,
            max_depth,
        );
        warnings.extend(warns);

        let mut wrap = Section::new(
            format!("embed-{}", sanitize_id(&hit.name)),
            format!("Embedded: {}", hit.name),
        );
        wrap.add("EmbedName", hit.name.clone(), Some("Embed"));
        wrap.add("EmbedAnchor", hit.anchor.clone(), Some("Embed"));
        wrap.add("EmbedMime", mime, Some("Embed"));
        wrap.add("EmbedSize", hit.data.len().to_string(), Some("Embed"));
        wrap.add("EmbedDepth", (depth + 1).to_string(), Some("Embed"));
        sections.push(wrap);

        for mut sec in nested {
            sec.id = format!("embed{}-{}", depth + 1, sec.id);
            sec.label = format!("{} @ {}", sec.label, hit.anchor);
            for f in &mut sec.fields {
                let ns = f.namespace.clone().unwrap_or_default();
                f.namespace = Some(format!("Embed:{}/{}", hit.anchor, ns));
            }
            sections.push(sec);
        }
    }
    (sections, warnings)
}

fn sanitize_id(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(48)
        .collect()
}

/// Collect likely embedded binaries from an OOXML/ODF/EPUB zip listing.
pub fn collect_zip_embeds(zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>) -> Vec<EmbedHit> {
    use std::io::Read;
    let mut hits = Vec::new();
    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    for name in names {
        let lower = name.to_ascii_lowercase();
        let is_embed = lower.contains("/embeddings/")
            || lower.contains("/embed/")
            || (lower.contains("/media/")
                && (lower.ends_with(".emf")
                    || lower.ends_with(".wmf")
                    || lower.ends_with(".bin")
                    || lower.ends_with(".jpg")
                    || lower.ends_with(".jpeg")
                    || lower.ends_with(".png")
                    || lower.ends_with(".gif")
                    || lower.ends_with(".tif")
                    || lower.ends_with(".tiff")
                    || lower.ends_with(".bmp")))
            || lower.ends_with(".ole")
            || lower.contains("oleobject");
        if !is_embed {
            continue;
        }
        // Skip tiny relationship stubs
        let Ok(file) = zip.by_name(&name) else {
            continue;
        };
        if file.size() < 16 || file.size() > 8_000_000 {
            continue;
        }
        let mut buf = Vec::new();
        if file.take(8_000_000).read_to_end(&mut buf).is_err() || buf.len() < 16 {
            continue;
        }
        let anchor = zip_anchor(&name);
        hits.push(EmbedHit {
            name,
            data: buf,
            anchor,
        });
        if hits.len() >= 32 {
            break;
        }
    }
    hits
}

fn zip_anchor(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("ppt/slides/") {
        let slide = rest.split('/').next().unwrap_or(rest);
        return format!("slide:{slide}");
    }
    if lower.contains("/embeddings/") {
        return format!("embedding:{path}");
    }
    if lower.contains("/media/") {
        return format!("media:{path}");
    }
    path.to_string()
}

/// Scan PDF object streams for EmbeddedFile payloads.
pub fn collect_pdf_embeds(data: &[u8]) -> (Vec<EmbedHit>, Vec<String>) {
    use lopdf::{Document, Object};
    let mut warnings = Vec::new();
    let mut hits = Vec::new();
    let doc = match Document::load_mem(data) {
        Ok(d) => d,
        Err(err) => {
            warnings.push(format!("PDF embed scan: {err}"));
            return (hits, warnings);
        }
    };

    let mut page_for_obj: std::collections::HashMap<(u32, u16), usize> =
        std::collections::HashMap::new();
    for (num, id) in doc.get_pages() {
        page_for_obj.insert(id, num as usize);
    }

    for (id, obj) in doc.objects.iter() {
        let Object::Stream(stream) = obj else {
            continue;
        };
        let dict = &stream.dict;
        let type_name = dict.get(b"Type").ok().and_then(|t| match t {
            Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
            _ => None,
        });
        let is_embedded = type_name.as_deref() == Some("EmbeddedFile");
        if !is_embedded {
            continue;
        }
        let content = stream.content.clone();
        if content.len() < 16 || content.len() > 8_000_000 {
            continue;
        }
        // Skip self-similar empty shells
        if content.starts_with(b"%PDF") && content.len() == data.len() {
            continue;
        }
        let page_hint = page_for_obj.get(id).map(|p| format!("page:{p}"));
        let anchor = page_hint.unwrap_or_else(|| format!("obj:{}:{}", id.0, id.1));
        let name = format!("embedded-{}-{}.bin", id.0, id.1);
        hits.push(EmbedHit {
            name,
            data: content,
            anchor,
        });
        if hits.len() >= 16 {
            break;
        }
    }
    (hits, warnings)
}

/// Annotate a section with embed metadata helper.
#[allow(dead_code)]
pub fn embed_field(key: &str, value: impl Into<String>) -> Field {
    Field::new(key, value).with_namespace("Embed")
}
