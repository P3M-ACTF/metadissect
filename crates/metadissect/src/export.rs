use crate::types::Analysis;

pub fn to_json(analysis: &Analysis) -> serde_json::Result<String> {
    serde_json::to_string_pretty(analysis)
}

pub fn to_csv(analysis: &Analysis) -> String {
    let mut out = String::from("section,key,label,namespace,value,offset,length\n");
    for sec in &analysis.sections {
        for f in &sec.fields {
            out.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                csv(&sec.label),
                csv(&f.key),
                csv(&f.label),
                csv(f.namespace.as_deref().unwrap_or("")),
                csv(&f.value),
                f.offset.map(|v| v.to_string()).unwrap_or_default(),
                f.length.map(|v| v.to_string()).unwrap_or_default(),
            ));
        }
    }
    out
}

pub fn to_markdown(analysis: &Analysis) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# MetaDissect — {}\n\n",
        analysis.filename.as_deref().unwrap_or("untitled")
    ));
    md.push_str(&format!(
        "- MIME: `{}`\n- Size: {}\n- Entropy: {:.4}\n- SHA-256: `{}`\n\n",
        analysis.mime, analysis.size, analysis.entropy, analysis.hashes.sha256
    ));
    for sec in &analysis.sections {
        md.push_str(&format!("## {}\n\n", sec.label));
        md.push_str("| Key | Value | Namespace |\n|---|---|---|\n");
        for f in &sec.fields {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                escape_md(&f.key),
                escape_md(&truncate(&f.value, 200)),
                escape_md(f.namespace.as_deref().unwrap_or(""))
            ));
        }
        md.push('\n');
    }
    if !analysis.warnings.is_empty() {
        md.push_str("## Warnings\n\n");
        for w in &analysis.warnings {
            md.push_str(&format!("- {}\n", escape_md(w)));
        }
    }
    md
}

fn csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
