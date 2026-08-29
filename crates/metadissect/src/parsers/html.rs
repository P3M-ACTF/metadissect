use crate::types::{Field, Section};

pub fn parse_html(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let text = decode_text(data);
    parse_html_str(&text)
}

pub fn parse_html_str(html: &str) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let warnings = Vec::new();
    let lower = html.to_ascii_lowercase();

    let mut meta = Section::new("html-meta", "HTML meta");
    if let Some(title) = extract_tag(html, "title") {
        meta.add("Title", title, Some("HTML"));
    }
    for (attrs, _) in iter_tags(html, "meta") {
        let name = attr(&attrs, "name")
            .or_else(|| attr(&attrs, "property"))
            .or_else(|| attr(&attrs, "itemprop"))
            .or_else(|| attr(&attrs, "http-equiv"));
        let content = attr(&attrs, "content").or_else(|| attr(&attrs, "value"));
        if let (Some(n), Some(c)) = (name, content) {
            let ns = if n.starts_with("og:") {
                "HTML:OG"
            } else if n.starts_with("twitter:") {
                "HTML:Twitter"
            } else if n.starts_with("dc.") || n.starts_with("dcterms.") {
                "HTML:DublinCore"
            } else {
                "HTML:meta"
            };
            meta.fields.push(Field::new(n, c).with_namespace(ns));
        }
    }
    if !meta.is_empty() {
        sections.push(meta);
    }

    let mut links = Section::new("html-links", "HTML links");
    for (attrs, _) in iter_tags(html, "link") {
        let rel = attr(&attrs, "rel").unwrap_or_default();
        let href = attr(&attrs, "href").unwrap_or_default();
        if rel.is_empty() && href.is_empty() {
            continue;
        }
        links.fields.push(
            Field::new(if rel.is_empty() { "href" } else { &rel }, href)
                .with_namespace("HTML:link"),
        );
    }
    if !links.is_empty() {
        sections.push(links);
    }

    let mut jsonld = Section::new("html-jsonld", "JSON-LD");
    for block in extract_json_ld(html) {
        flatten_json(&block, "JSON-LD", &mut jsonld, 0);
    }
    if !jsonld.is_empty() {
        sections.push(jsonld);
    }

    if lower.contains("<script") {
        let mut s = Section::new("html-scripts", "HTML scripts");
        s.add(
            "ScriptTags",
            lower.matches("<script").count().to_string(),
            Some("HTML"),
        );
        sections.push(s);
    }

    (sections, warnings)
}

pub fn parse_json(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let text = decode_text(data);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(v) => {
            let mut sec = Section::new("json", "JSON document");
            flatten_json(&v, "JSON", &mut sec, 0);
            (vec![sec], Vec::new())
        }
        Err(err) => (Vec::new(), vec![format!("JSON parse: {err}")]),
    }
}

pub fn flatten_json(value: &serde_json::Value, prefix: &str, section: &mut Section, depth: u8) {
    if depth > 8 || section.fields.len() > 400 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match v {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        flatten_json(v, &path, section, depth + 1);
                    }
                    other => {
                        section
                            .fields
                            .push(Field::new(path, json_scalar(other)).with_namespace("JSON"));
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate().take(50) {
                flatten_json(v, &format!("{prefix}[{i}]"), section, depth + 1);
            }
        }
        other => {
            section
                .fields
                .push(Field::new(prefix, json_scalar(other)).with_namespace("JSON"));
        }
    }
}

fn json_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".into(),
        other => other.to_string(),
    }
}

fn decode_text(data: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(data) {
        return s.to_string();
    }
    encoding_rs::UTF_8.decode(data).0.into_owned()
}

fn extract_tag(html: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let lower = html.to_ascii_lowercase();
    let start = lower.find(&open)?;
    let after = html[start..].find('>')? + start + 1;
    let end_rel = html[after..].to_ascii_lowercase().find(&close)?;
    Some(html[after..after + end_rel].trim().to_string())
}

fn iter_tags<'a>(html: &'a str, tag: &'a str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let needle = format!("<{tag}");
    let mut search = 0;
    while let Some(pos) = lower[search..].find(&needle) {
        let abs = search + pos;
        let Some(gt) = html[abs..].find('>') else {
            break;
        };
        let raw = &html[abs + 1 + tag.len()..abs + gt];
        out.push((raw.to_string(), String::new()));
        search = abs + gt + 1;
        if out.len() > 300 {
            break;
        }
    }
    out
}

fn attr(attrs: &str, name: &str) -> Option<String> {
    let lower = attrs.to_ascii_lowercase();
    let key = name.to_ascii_lowercase();
    let mut i = 0;
    while let Some(pos) = lower[i..].find(&key) {
        let abs = i + pos;
        let after_name = abs + key.len();
        let rest = attrs[after_name..].trim_start();
        if !rest.starts_with('=') {
            i = after_name;
            continue;
        }
        let rest = rest[1..].trim_start();
        return Some(unquote(rest));
    }
    None
}

fn unquote(s: &str) -> String {
    let s = s.trim_start();
    if let Some(q) = s.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let rest = &s[1..];
        return rest.split(q).next().unwrap_or("").to_string();
    }
    s.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('>')
        .to_string()
}

fn extract_json_ld(html: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut search = 0;
    while let Some(pos) = lower[search..].find("<script") {
        let abs = search + pos;
        let Some(gt) = html[abs..].find('>') else {
            break;
        };
        let open = &html[abs..abs + gt + 1];
        if !open.to_ascii_lowercase().contains("ld+json") {
            search = abs + gt + 1;
            continue;
        }
        let body_start = abs + gt + 1;
        let Some(end) = html[body_start..].to_ascii_lowercase().find("</script>") else {
            break;
        };
        let body = html[body_start..body_start + end].trim();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            out.push(v);
        }
        search = body_start + end + 9;
    }
    out
}
