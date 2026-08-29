use crate::parsers::html;
use crate::types::{Field, Section};

pub fn parse_eml(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let text = String::from_utf8_lossy(data);
    let (headers, body) = split_headers(&text);
    let mut sec = Section::new("eml-headers", "Email headers");
    for (k, v) in headers {
        sec.fields
            .push(Field::new(k, unfold(&v)).with_namespace("EML"));
    }
    let mut sections = vec![sec];
    let trimmed = body.trim();
    if trimmed.starts_with('<') {
        let (html_secs, _) = html::parse_html_str(trimmed);
        sections.extend(html_secs);
    } else if !trimmed.is_empty() {
        let mut b = Section::new("eml-body", "Email body");
        b.add(
            "Preview",
            trimmed.chars().take(400).collect::<String>(),
            Some("EML"),
        );
        b.add("Length", trimmed.len().to_string(), Some("EML"));
        sections.push(b);
    }
    (sections, Vec::new())
}

fn split_headers(text: &str) -> (Vec<(String, String)>, String) {
    let normalized = text.replace("\r\n", "\n");
    if let Some(idx) = normalized.find("\n\n") {
        (
            parse_header_block(&normalized[..idx]),
            normalized[idx + 2..].to_string(),
        )
    } else {
        (parse_header_block(&normalized), String::new())
    }
}

fn parse_header_block(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in block.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, ref mut v)) = current {
                v.push(' ');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if let Some(prev) = current.take() {
                out.push(prev);
            }
            current = Some((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if let Some(prev) = current {
        out.push(prev);
    }
    out
}

fn unfold(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
