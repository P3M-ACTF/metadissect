use crate::entropy::shannon_entropy;
use crate::hashes::compute_hashes;
use crate::magic::{inspect_magic, mime_from_filename};
use crate::normalize;
use crate::parsers;
use crate::types::{Analysis, AnalyzeOptions, Field, Section, Source};
use std::fs;
use std::path::Path;

pub fn analyze_buffer(data: &[u8], options: AnalyzeOptions) -> Analysis {
    let mut magic = inspect_magic(data);
    // Extension only as fallback when magic is unknown / octet-stream.
    if parsers::is_unknown_mime(&magic.mime) {
        if let Some(name) = options.filename.as_deref() {
            if let Some(hint) = mime_from_filename(name) {
                magic.mime = hint.to_string();
            }
        }
    }
    if matches!(options.source, Some(Source::Html)) {
        magic.mime = "text/html".into();
    }
    if matches!(options.source, Some(Source::Json)) {
        magic.mime = "application/json".into();
    }

    let hashes = if options.include_hashes {
        compute_hashes(data)
    } else {
        Default::default()
    };

    let mut analysis = Analysis {
        source: options.source.unwrap_or(Source::File),
        mime: magic.mime.clone(),
        filename: options.filename.clone(),
        size: options.file_size.unwrap_or(data.len() as u64),
        extracted_at: chrono::Utc::now().to_rfc3339(),
        hashes,
        magic,
        entropy: shannon_entropy(data),
        sections: Vec::new(),
        warnings: Vec::new(),
        notes_educativas: Vec::new(),
    };

    let mut general = Section::new("general", "General");
    general.add("MIME", analysis.mime.clone(), Some("General"));
    general.add("Size", analysis.size.to_string(), Some("General"));
    general.add(
        "Entropy",
        format!("{:.4} bits/byte", analysis.entropy),
        Some("General"),
    );
    general.add("Magic", analysis.magic.description.clone(), Some("General"));
    general.add(
        "Signature",
        analysis.magic.hex_signature.clone(),
        Some("General"),
    );
    if let Some(name) = &analysis.filename {
        general.add("Filename", name.clone(), Some("General"));
    }
    if let Some(url) = &options.source_url {
        general.add("SourceURL", url.clone(), Some("General"));
    }
    if let Some(m) = &options.mtime {
        general.add("FilesystemMtime", m.clone(), Some("FS"));
    }
    if let Some(c) = &options.ctime {
        general.add("FilesystemCtime", c.clone(), Some("FS"));
    }
    if let Some(a) = &options.atime {
        general.add("FilesystemAtime", a.clone(), Some("FS"));
    }
    analysis.push_section(general);

    let mut hash_sec = Section::new("hashes", "Hashes");
    hash_sec.add("MD5", analysis.hashes.md5.clone(), Some("Hash"));
    hash_sec.add("SHA-1", analysis.hashes.sha1.clone(), Some("Hash"));
    hash_sec.add("SHA-256", analysis.hashes.sha256.clone(), Some("Hash"));
    hash_sec.add("SHA-512", analysis.hashes.sha512.clone(), Some("Hash"));
    hash_sec.add("BLAKE3", analysis.hashes.blake3.clone(), Some("Hash"));
    analysis.push_section(hash_sec);

    if !options.response_headers.is_empty() {
        let mut hs = Section::new("http-headers", "HTTP headers");
        for (k, v) in &options.response_headers {
            hs.fields.push(Field::new(k, v).with_namespace("HTTP"));
        }
        analysis.push_section(hs);
    }

    let max_depth = options.max_embed_depth;
    let (secs, warns) = parsers::parse_for_mime_at_depth(
        data,
        &analysis.mime,
        options.filename.as_deref(),
        0,
        max_depth,
    );
    analysis.warnings.extend(warns);
    for s in secs {
        analysis.push_section(s);
    }

    #[cfg(feature = "c2pa")]
    {
        let (c2pa_secs, c2pa_warns) = crate::c2pa_support::extract_with(
            data,
            &analysis.mime,
            &crate::c2pa_support::C2paOptions {
                verbose: options.verbose,
                trust_anchors: options.trust_anchors.clone(),
            },
        );
        analysis.warnings.extend(c2pa_warns);
        for s in c2pa_secs {
            analysis.push_section(s);
        }
    }

    let normalized = normalize::build_normalized_section(&analysis.sections);
    analysis.push_section(normalized);

    if !options.verbose {
        crate::parsers::png::compact_png_chunks_in(&mut analysis.sections);
    }
    reorder_c2pa_before_png_chunks(&mut analysis.sections);

    if analysis.mime.contains("heic") || analysis.mime.contains("heif") {
        analysis.warnings.push(
            "HEIC/HEIF: without libheif this tool lists ISO-BMFF boxes and extracts embedded EXIF/XMP when present. It does not decode pixels or walk item/iloc trees.".into(),
        );
    }
    analysis
}

pub fn analyze_path(path: &Path) -> crate::error::Result<Analysis> {
    analyze_path_with_options(path, AnalyzeOptions::default())
}

/// Analyze a file, preserving extra options such as [`AnalyzeOptions::verbose`].
pub fn analyze_path_with_options(
    path: &Path,
    extra: AnalyzeOptions,
) -> crate::error::Result<Analysis> {
    let data = fs::read(path)?;
    analyze_path_from_bytes_with(path, &data, extra)
}

/// Single read: bytes and analysis come from the same buffer (no TOCTOU).
pub fn analyze_path_with_bytes(path: &Path) -> crate::error::Result<(Vec<u8>, Analysis)> {
    let data = fs::read(path)?;
    let analysis = analyze_path_from_bytes(path, &data)?;
    Ok((data, analysis))
}

pub fn analyze_path_from_bytes(path: &Path, data: &[u8]) -> crate::error::Result<Analysis> {
    analyze_path_from_bytes_with(path, data, AnalyzeOptions::default())
}

fn analyze_path_from_bytes_with(
    path: &Path,
    data: &[u8],
    extra: AnalyzeOptions,
) -> crate::error::Result<Analysis> {
    let meta = fs::metadata(path)?;
    let filename = extra.filename.clone().unwrap_or_else(|| {
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    });
    let mut options = AnalyzeOptions::from_filename(filename);
    options.verbose = extra.verbose;
    options.max_embed_depth = extra.max_embed_depth;
    options.trust_anchors = extra.trust_anchors.clone();
    options.file_size = Some(meta.len());
    if let Ok(mtime) = meta.modified() {
        options.mtime = Some(to_rfc(mtime));
    }
    if let Ok(ctime) = meta.created() {
        options.ctime = Some(to_rfc(ctime));
    }
    if let Ok(atime) = meta.accessed() {
        options.atime = Some(to_rfc(atime));
    }
    Ok(analyze_buffer(data, options))
}

pub fn analyze_html_string(html: &str, filename: Option<String>) -> Analysis {
    let mut options = AnalyzeOptions {
        filename: filename.or_else(|| Some("input.html".into())),
        source: Some(Source::Html),
        include_hashes: true,
        ..Default::default()
    };
    options.source = Some(Source::Html);
    analyze_buffer(html.as_bytes(), options)
}

pub fn analyze_json_string(json: &str, filename: Option<String>) -> Analysis {
    let options = AnalyzeOptions {
        filename: filename.or_else(|| Some("input.json".into())),
        source: Some(Source::Json),
        include_hashes: true,
        ..Default::default()
    };
    analyze_buffer(json.as_bytes(), options)
}

fn to_rfc(t: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.to_rfc3339()
}

/// When a C2PA manifest is present, show C2PA + `normalized` before `png-chunks`
/// (and other format-specific sections) so claim generator / actions are visible
/// without scrolling past IDAT noise.
fn reorder_c2pa_before_png_chunks(sections: &mut Vec<Section>) {
    if !sections.iter().any(|s| s.id == "c2pa") {
        return;
    }
    let mut prefix = Vec::new();
    let mut c2pa = Vec::new();
    let mut normalized = Vec::new();
    let mut rest = Vec::new();
    for s in sections.drain(..) {
        if s.id == "general" || s.id == "hashes" || s.id == "http-headers" {
            prefix.push(s);
        } else if s.id == "normalized" {
            normalized.push(s);
        } else if s.id == "c2pa" || s.id.starts_with("c2pa-") {
            c2pa.push(s);
        } else {
            rest.push(s);
        }
    }
    sections.extend(prefix);
    sections.extend(c2pa);
    sections.extend(normalized);
    sections.extend(rest);
}
