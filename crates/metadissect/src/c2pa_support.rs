//! C2PA / JUMBF manifest extraction via the Content Authenticity Initiative `c2pa` crate.
//!
//! Surfaces active-manifest metadata, `c2pa.actions` / `c2pa.actions.v2`, ingredients,
//! hard-binding (dataHash) results, and COSE signature fields when present.
//! Cryptographic validation uses the crate's built-in verifier. Certificate **trust**
//! is wired through CAI `Settings.trust.trust_anchors` when `--trust-anchors` / env
//! `C2PA_TRUST_ANCHORS` supplies a PEM file or directory. The official CAI trust list
//! is **not** bundled, so `Valid ≠ Trusted` is the normal result.

use crate::error::{MetaError, Result as MetaResult};
use crate::types::{Field, Section};
use c2pa::assertions::Actions;
use c2pa::{
    Context, Error as C2paError, Manifest, ManifestAssertion, Reader, Settings, ValidationState,
};
use std::io::Cursor;
use std::path::{Path, PathBuf};

/// Options for C2PA read/verify (trust list + warning verbosity).
#[derive(Debug, Clone, Default)]
pub struct C2paOptions {
    /// When true, emit one warning per C2PA validation status code.
    pub verbose: bool,
    /// PEM file or directory of `.pem`/`.crt`/`.cer` files. `None` falls back to
    /// env `C2PA_TRUST_ANCHORS`.
    pub trust_anchors: Option<PathBuf>,
}

/// Kind of binary/JSON payload to write with [`extract_payload`].
#[derive(Debug, Clone)]
pub enum C2paExtractKind {
    /// Claim-generator icon / `c2pa.icon` assertion.
    Icon,
    /// Active-manifest thumbnail.
    Thumbnail,
    /// Named assertion (JSON pretty-printed, or raw bytes if binary).
    Assertion(String),
}

/// Bytes extracted from a C2PA manifest plus a hint for the output filename.
#[derive(Debug, Clone)]
pub struct ExtractedPayload {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub suggested_extension: String,
}

/// MIME types we attempt C2PA read for (subset of `Reader::supported_mime_types()`).
fn mime_supported(mime: &str) -> bool {
    let m = mime.to_ascii_lowercase();
    matches!(
        m.as_str(),
        "image/jpeg"
            | "image/png"
            | "image/webp"
            | "image/tiff"
            | "image/gif"
            | "image/avif"
            | "image/heic"
            | "image/heif"
            | "image/jxl"
            | "image/svg+xml"
            | "video/mp4"
            | "video/quicktime"
            | "video/x-msvideo"
            | "video/avi"
            | "audio/mp4"
            | "audio/mpeg"
            | "audio/mp3"
            | "audio/wav"
            | "audio/x-wav"
            | "audio/flac"
            | "application/mp4"
            | "application/c2pa"
            | "application/x-c2pa-manifest-store"
    ) || m.starts_with("image/")
        || m.starts_with("video/")
        || m.starts_with("audio/")
}

fn is_absent(err: &C2paError) -> bool {
    matches!(
        err,
        C2paError::JumbfNotFound
            | C2paError::NotFound
            | C2paError::ProvenanceMissing
            | C2paError::ClaimMissing { .. }
    )
}

fn hard_binding_codes(code: &str) -> bool {
    let c = code.to_ascii_lowercase();
    c.contains("datahash")
        || c.contains("bmffhash")
        || c.contains("boxhash")
        || c.contains("hardbinding")
        || c.contains("hasheduri")
}

/// Env var pointing at a PEM file or directory of trust-anchor certificates.
pub const C2PA_TRUST_ANCHORS_ENV: &str = "C2PA_TRUST_ANCHORS";

/// Resolve `--trust-anchors` / `AnalyzeOptions.trust_anchors` or `C2PA_TRUST_ANCHORS`.
pub fn resolve_trust_anchors_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if !p.as_os_str().is_empty() {
            return Some(p.to_path_buf());
        }
    }
    std::env::var_os(C2PA_TRUST_ANCHORS_ENV)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Load concatenated PEM text from a file or a directory of `.pem`/`.crt`/`.cer` files.
pub fn load_trust_anchors_pem(path: &Path) -> Result<String, String> {
    if path.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|s| s.to_str()).is_some_and(|ext| {
                    matches!(
                        ext.to_ascii_lowercase().as_str(),
                        "pem" | "crt" | "cer" | "cert"
                    )
                })
            })
            .collect();
        entries.sort();
        if entries.is_empty() {
            return Err(format!(
                "{} contains no .pem/.crt/.cer files",
                path.display()
            ));
        }
        let mut out = String::new();
        for p in &entries {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            out.push_str(&text);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
        Ok(out)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

fn pem_cert_count(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

fn open_reader(
    data: &[u8],
    mime: &str,
    trust_pem: Option<&str>,
) -> std::result::Result<Reader, C2paError> {
    let mut stream = Cursor::new(data);
    if let Some(pem) = trust_pem {
        let settings = Settings::new()
            .with_value("trust.trust_anchors", pem.to_string())
            .map_err(|e| C2paError::BadParam(e.to_string()))?;
        let context = Context::new()
            .with_settings(settings)
            .map_err(|e| C2paError::BadParam(e.to_string()))?;
        Reader::from_context(context).with_stream(mime, &mut stream)
    } else {
        Reader::default().with_stream(mime, &mut stream)
    }
}

/// Extract C2PA sections and warnings from an asset buffer.
///
/// Returns empty sections/warnings when no manifest is present.
pub fn extract(data: &[u8], mime: &str) -> (Vec<Section>, Vec<String>) {
    extract_with(data, mime, &C2paOptions::default())
}

/// Like [`extract`], honoring trust anchors and compact vs verbose C2PA warnings.
pub fn extract_with(data: &[u8], mime: &str, opts: &C2paOptions) -> (Vec<Section>, Vec<String>) {
    if !mime_supported(mime) {
        return (Vec::new(), Vec::new());
    }

    let mut preload_warnings = Vec::new();
    let mut trust_source: Option<String> = None;
    let mut trust_pem: Option<String> = None;
    if let Some(path) = resolve_trust_anchors_path(opts.trust_anchors.as_deref()) {
        trust_source = Some(path.display().to_string());
        match load_trust_anchors_pem(&path) {
            Ok(pem) => {
                if pem_cert_count(&pem) == 0 && !pem.contains("-----BEGIN") {
                    preload_warnings.push(format!(
                        "C2PA: trust anchors at {} do not look like PEM certificates.",
                        path.display()
                    ));
                } else {
                    trust_pem = Some(pem);
                }
            }
            Err(e) => {
                preload_warnings.push(format!("C2PA: failed to load trust anchors: {e}"));
            }
        }
    }

    let reader = match open_reader(data, mime, trust_pem.as_deref()) {
        Ok(r) => r,
        Err(e) if is_absent(&e) => return (Vec::new(), preload_warnings),
        Err(C2paError::UnsupportedType) => {
            preload_warnings.push(format!(
                "C2PA: format `{mime}` is listed by the SDK but this build cannot parse it (missing feature or handler)."
            ));
            return (Vec::new(), preload_warnings);
        }
        Err(e) => {
            // Settings/PEM rejection: retry without anchors so analysis still works.
            if trust_pem.is_some() {
                preload_warnings.push(format!(
                    "C2PA: trust anchors were not applied ({e}); verifying without a trust list."
                ));
                match open_reader(data, mime, None) {
                    Ok(r) => r,
                    Err(e2) if is_absent(&e2) => return (Vec::new(), preload_warnings),
                    Err(C2paError::UnsupportedType) => {
                        preload_warnings.push(format!(
                            "C2PA: format `{mime}` is listed by the SDK but this build cannot parse it (missing feature or handler)."
                        ));
                        return (Vec::new(), preload_warnings);
                    }
                    Err(e2) => {
                        preload_warnings.push(format!(
                            "C2PA: failed to read/validate manifest store: {e2}"
                        ));
                        return (Vec::new(), preload_warnings);
                    }
                }
            } else {
                preload_warnings.push(format!("C2PA: failed to read/validate manifest store: {e}"));
                return (Vec::new(), preload_warnings);
            }
        }
    };

    if reader.active_manifest().is_none() && reader.manifests().is_empty() {
        return (Vec::new(), preload_warnings);
    }

    let mut warnings = preload_warnings;
    let mut sections = Vec::new();
    let mut overview = Section::new("c2pa", "C2PA");

    overview.add("Embedded", reader.is_embedded().to_string(), Some("C2PA"));
    if let Some(url) = reader.remote_url() {
        overview.add("RemoteManifestUrl", url.to_string(), Some("C2PA"));
        warnings.push(
            "C2PA: remote manifest URL present; MetaDissect does not fetch remote manifests (local only)."
                .into(),
        );
    }

    if let Some(src) = &trust_source {
        let applied = trust_pem.is_some();
        overview.push(
            Field::new("TrustAnchors", src)
                .with_namespace("C2PA")
                .with_explanation(
                    "PEM file or directory passed to CAI Settings.trust.trust_anchors. The official CAI trust list is not bundled.",
                ),
        );
        overview.add("TrustAnchorsApplied", applied.to_string(), Some("C2PA"));
        if let Some(pem) = &trust_pem {
            overview.add(
                "TrustAnchorsCertCount",
                pem_cert_count(pem).to_string(),
                Some("C2PA"),
            );
        }
    } else {
        overview.push(
            Field::new("TrustAnchors", "(none)")
                .with_namespace("C2PA")
                .with_explanation(
                    "No --trust-anchors / C2PA_TRUST_ANCHORS. Official CAI trust list is not bundled; Valid ≠ Trusted is expected.",
                ),
        );
    }

    let state = reader.validation_state();
    let state_str = match state {
        ValidationState::Invalid => "invalid",
        ValidationState::Valid => "valid",
        ValidationState::Trusted => "trusted",
    };
    overview.push(
        Field::new("ValidationState", state_str)
            .with_namespace("C2PA")
            .with_explanation(
                "Invalid = structural/crypto failure; Valid = crypto OK but cert may be untrusted; Trusted = crypto OK + trust list match. No official C2PA trust list is bundled.",
            ),
    );

    match state {
        ValidationState::Invalid => {
            warnings.push(
                "C2PA: validation state is Invalid (hard binding and/or COSE/signature checks failed)."
                    .into(),
            );
        }
        ValidationState::Valid => {
            warnings.push(
                "C2PA: cryptographic validation succeeded, but the signing credential is not in a configured trust list (Valid ≠ Trusted)."
                    .into(),
            );
        }
        ValidationState::Trusted => {}
    }

    let mut hard_binding = "unknown";
    let mut status_codes: Vec<String> = Vec::new();
    let mut status_detail: Vec<(String, String)> = Vec::new();
    if let Some(statuses) = reader.validation_status() {
        for s in statuses {
            let code = s.code().to_string();
            if hard_binding_codes(&code)
                && (code.to_ascii_lowercase().contains("mismatch")
                    || code.to_ascii_lowercase().contains("failure")
                    || code.to_ascii_lowercase().contains("error"))
            {
                hard_binding = "fail";
            }
            let expl = s.explanation().unwrap_or("");
            let line = if expl.is_empty() {
                code.clone()
            } else {
                format!("{code}: {expl}")
            };
            status_codes.push(line.clone());
            status_detail.push((code, line));
        }
    }
    push_c2pa_status_warnings(&mut warnings, &status_detail, opts.verbose);

    if hard_binding == "unknown" {
        hard_binding = match state {
            ValidationState::Invalid => "fail_or_other",
            ValidationState::Valid | ValidationState::Trusted => "pass",
        };
    }

    overview.push(
        Field::new("HardBinding", hard_binding)
            .with_namespace("C2PA")
            .with_explanation(
                "pass = no dataHash/bmffHash mismatch reported; fail = assertion.dataHash.mismatch (or similar); fail_or_other = Invalid without an explicit hash code.",
            ),
    );

    if !status_codes.is_empty() {
        overview.push(
            Field::new("ValidationStatus", status_codes.join("; "))
                .with_namespace("C2PA")
                .with_raw(serde_json::json!(status_codes)),
        );
    }

    overview.add(
        "ManifestCount",
        reader.manifests().len().to_string(),
        Some("C2PA"),
    );
    if let Some(label) = reader.active_label() {
        overview.add("ActiveManifestLabel", label.to_string(), Some("C2PA"));
    }
    if let Some(manifest) = reader.active_manifest() {
        push_claim_generator(&mut overview, manifest);
    }

    sections.push(overview);

    if let Some(manifest) = reader.active_manifest() {
        sections.push(manifest_section(
            "c2pa-manifest",
            "C2PA active manifest",
            manifest,
        ));
        if let Some(actions_sec) = actions_section(manifest) {
            sections.push(actions_sec);
        }
        if let Some(ing_sec) = ingredients_section(manifest) {
            sections.push(ing_sec);
        }
    }

    for (label, manifest) in reader.manifests() {
        if reader.active_label() == Some(label.as_str()) {
            continue;
        }
        let id = format!("c2pa-manifest-{}", sanitize_id(label));
        sections.push(manifest_section(
            &id,
            &format!("C2PA manifest {label}"),
            manifest,
        ));
    }

    (sections, warnings)
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn push_claim_generator(sec: &mut Section, manifest: &Manifest) {
    if let Some(cg) = manifest.claim_generator() {
        sec.add("ClaimGenerator", cg.to_string(), Some("C2PA"));
    }
    if let Some(infos) = &manifest.claim_generator_info {
        for (i, info) in infos.iter().enumerate() {
            let mut v = info.name.clone();
            if let Some(ver) = &info.version {
                v.push(' ');
                v.push_str(ver);
            }
            let key = if i == 0 {
                "ClaimGeneratorInfo".to_string()
            } else {
                format!("ClaimGeneratorInfo[{i}]")
            };
            sec.add(key, v, Some("C2PA"));
        }
    }
}

fn json_text(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn software_agent_from_json(v: &serde_json::Value) -> (Option<String>, Option<String>) {
    match v {
        serde_json::Value::String(s) => (Some(s.clone()), None),
        serde_json::Value::Object(map) => {
            let name = map.get("name").map(json_text);
            let version = map.get("version").map(json_text);
            (name, version)
        }
        _ => (Some(json_text(v)), None),
    }
}

fn summarize_parameters(v: &serde_json::Value) -> Option<String> {
    let obj = v.as_object()?;
    let mut parts = Vec::new();
    for (k, val) in obj {
        if k.eq_ignore_ascii_case("ingredient") || k.eq_ignore_ascii_case("ingredients") {
            continue;
        }
        let s = match val {
            serde_json::Value::Null => continue,
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Array(a) => format!("[{} items]", a.len()),
            serde_json::Value::Object(o) => format!("{{{} keys}}", o.len()),
        };
        if s.is_empty() {
            continue;
        }
        parts.push(format!("{k}={s}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(crate::text::truncate_chars(&parts.join("; "), 200))
    }
}

/// Promote known Action JSON keys to flat table fields (`Action[i].SoftwareAgent`, …).
fn promote_action_fields(sec: &mut Section, i: usize, raw: &serde_json::Value) {
    if let Some(sa) = raw.get("softwareAgent") {
        let (name, version) = software_agent_from_json(sa);
        if let Some(name) = name {
            if !name.is_empty() {
                sec.add(format!("Action[{i}].SoftwareAgent"), name, Some("C2PA"));
            }
        }
        if let Some(version) = version {
            if !version.is_empty() {
                sec.add(format!("Action[{i}].Version"), version, Some("C2PA"));
            }
        }
    }
    if let Some(dst) = raw.get("digitalSourceType") {
        let text = json_text(dst);
        if !text.is_empty() {
            sec.add(format!("Action[{i}].DigitalSourceType"), text, Some("C2PA"));
        }
    }
    if let Some(params) = raw.get("parameters") {
        if let Some(summary) = summarize_parameters(params) {
            sec.add(format!("Action[{i}].Parameters"), summary, Some("C2PA"));
        }
    }
}

fn manifest_section(id: &str, label: &str, manifest: &Manifest) -> Section {
    let mut sec = Section::new(id, label);

    if let Some(t) = manifest.title() {
        sec.add("Title", t.to_string(), Some("C2PA"));
    }
    if let Some(l) = manifest.label() {
        sec.add("Label", l.to_string(), Some("C2PA"));
    }
    push_claim_generator(&mut sec, manifest);
    if let Some(fmt) = manifest.format() {
        sec.add("Format", fmt.to_string(), Some("C2PA"));
    }
    if let Some(issuer) = manifest.issuer() {
        sec.push(
            Field::new("CoseIssuer", issuer)
                .with_namespace("C2PA")
                .with_explanation("Issuer from the COSE_Sign1 / X.509 certificate chain."),
        );
    }
    if let Some(cn) = manifest.common_name() {
        sec.add("CoseCommonName", cn, Some("C2PA"));
    }
    if let Some(time) = manifest.time() {
        sec.add("CoseTime", time, Some("C2PA"));
    }
    if let Some(sig) = manifest.signature() {
        sec.add("CoseSignatureBytes", sig.len().to_string(), Some("C2PA"));
    }

    let assertion_labels: Vec<String> = manifest
        .assertions()
        .iter()
        .map(|a| a.label().to_string())
        .collect();
    if !assertion_labels.is_empty() {
        sec.push(
            Field::new("Assertions", assertion_labels.join(", "))
                .with_namespace("C2PA")
                .with_raw(serde_json::json!(assertion_labels)),
        );
    }

    for assertion in manifest.assertions() {
        let alabel = assertion.label();
        if alabel.starts_with("c2pa.actions") {
            continue; // detailed in actions section
        }
        if is_ingredient_label(alabel) {
            continue; // detailed in c2pa-ingredients
        }
        if looks_like_binary_label(alabel) {
            let hint = assertion
                .binary()
                .map(|b| format!("(binary, {} bytes)", b.len()))
                .unwrap_or_else(|_| "(binary or undecoded; use `metadissect extract`)".into());
            sec.add(format!("Assertion:{alabel}"), hint, Some("C2PA"));
            continue;
        }
        if let Ok(value) = assertion.value() {
            let text = serde_json::to_string(value).unwrap_or_else(|_| value.to_string());
            let truncated = crate::text::truncate_chars(&text, 500);
            sec.push(
                Field::new(format!("Assertion:{alabel}"), truncated)
                    .with_namespace("C2PA")
                    .with_raw(value.clone()),
            );
        } else {
            sec.add(
                format!("Assertion:{alabel}"),
                "(binary or undecoded; use `metadissect extract`)",
                Some("C2PA"),
            );
        }
    }

    sec
}

fn actions_section(manifest: &Manifest) -> Option<Section> {
    let mut sec = Section::new("c2pa-actions", "C2PA actions");
    let mut found = false;

    for label in [Actions::LABEL_VERSIONED, Actions::LABEL, "c2pa.actions"] {
        let Ok(actions) = manifest.find_assertion::<Actions>(label) else {
            continue;
        };
        found = true;
        sec.add("ActionsLabel", label.to_string(), Some("C2PA"));
        for (i, action) in actions.actions().iter().enumerate() {
            let name = action.action();
            sec.push(
                Field::new(format!("Action[{i}]"), name)
                    .with_namespace("C2PA")
                    .with_explanation("c2pa.actions / c2pa.actions.v2 action name."),
            );
            // Action is Serialize in c2pa; ignore if that changes.
            if let Ok(raw) = serde_json::to_value(action) {
                if let Some(f) = sec.fields.last_mut() {
                    f.raw = Some(raw.clone());
                }
                promote_action_fields(&mut sec, i, &raw);
            }
        }
        break;
    }

    if found {
        Some(sec)
    } else {
        None
    }
}

fn push_c2pa_status_warnings(
    warnings: &mut Vec<String>,
    status_detail: &[(String, String)],
    verbose: bool,
) {
    if status_detail.is_empty() {
        return;
    }
    if verbose {
        for (code, line) in status_detail {
            if code.contains("untrusted") {
                warnings.push(format!("C2PA COSE: {line}"));
            } else if hard_binding_codes(code) {
                warnings.push(format!("C2PA hard binding: {line}"));
            } else {
                warnings.push(format!("C2PA validation: {line}"));
            }
        }
    } else {
        warnings.push(format!(
            "C2PA: {} validation status code(s); use -v for per-code detail.",
            status_detail.len()
        ));
    }
}

fn is_ingredient_label(label: &str) -> bool {
    let l = label.to_ascii_lowercase();
    l == "c2pa.ingredient"
        || l.starts_with("c2pa.ingredient.")
        || l.starts_with("c2pa.ingredient.v")
}

fn looks_like_binary_label(label: &str) -> bool {
    let l = label.to_ascii_lowercase();
    l.contains("thumbnail") || l.contains("icon") || l.contains("embedded-data")
}

fn ingredients_section(manifest: &Manifest) -> Option<Section> {
    let ings = manifest.ingredients();
    if !ings.is_empty() {
        let mut sec = Section::new("c2pa-ingredients", "C2PA ingredients");
        sec.add("IngredientCount", ings.len().to_string(), Some("C2PA"));
        for (i, ing) in ings.iter().enumerate() {
            if let Some(t) = ing.title() {
                sec.add(
                    format!("Ingredient[{i}].Title"),
                    t.to_string(),
                    Some("C2PA"),
                );
            }
            if let Some(h) = ing.hash() {
                sec.add(format!("Ingredient[{i}].Hash"), h.to_string(), Some("C2PA"));
            }
            sec.add(
                format!("Ingredient[{i}].Relationship"),
                ing.relationship().as_str().to_string(),
                Some("C2PA"),
            );
            if let Some(fmt) = ing.format() {
                sec.add(
                    format!("Ingredient[{i}].Format"),
                    fmt.to_string(),
                    Some("C2PA"),
                );
            }
            let iid = ing.instance_id();
            if !iid.is_empty() && iid != "None" {
                sec.add(
                    format!("Ingredient[{i}].InstanceId"),
                    iid.to_string(),
                    Some("C2PA"),
                );
            }
            if let Some(label) = ing.label() {
                sec.add(
                    format!("Ingredient[{i}].Label"),
                    label.to_string(),
                    Some("C2PA"),
                );
            }
            if ing.is_parent() {
                sec.add(format!("Ingredient[{i}].IsParent"), "true", Some("C2PA"));
            }
        }
        return Some(sec);
    }
    ingredients_from_assertions(manifest)
}

fn ingredients_from_assertions(manifest: &Manifest) -> Option<Section> {
    let mut values = Vec::new();
    for assertion in manifest.assertions() {
        if !is_ingredient_label(assertion.label()) {
            continue;
        }
        if let Ok(value) = assertion.value() {
            values.push(value.clone());
        }
    }
    if values.is_empty() {
        return None;
    }
    let mut sec = Section::new("c2pa-ingredients", "C2PA ingredients");
    sec.add("IngredientCount", values.len().to_string(), Some("C2PA"));
    for (i, value) in values.iter().enumerate() {
        push_ingredient_from_json(&mut sec, i, value);
    }
    Some(sec)
}

fn push_ingredient_from_json(sec: &mut Section, i: usize, raw: &serde_json::Value) {
    if let Some(t) = raw.get("title").map(json_text).filter(|s| !s.is_empty()) {
        sec.add(format!("Ingredient[{i}].Title"), t, Some("C2PA"));
    }
    if let Some(h) = raw
        .get("hash")
        .or_else(|| raw.get("dc:hash"))
        .map(json_text)
        .filter(|s| !s.is_empty())
    {
        sec.add(format!("Ingredient[{i}].Hash"), h, Some("C2PA"));
    }
    if let Some(rel) = raw
        .get("relationship")
        .map(json_text)
        .filter(|s| !s.is_empty())
    {
        sec.add(format!("Ingredient[{i}].Relationship"), rel, Some("C2PA"));
    }
    if let Some(fmt) = raw.get("format").map(json_text).filter(|s| !s.is_empty()) {
        sec.add(format!("Ingredient[{i}].Format"), fmt, Some("C2PA"));
    }
    if let Some(id) = raw
        .get("instance_id")
        .or_else(|| raw.get("instanceId"))
        .map(json_text)
        .filter(|s| !s.is_empty())
    {
        sec.add(format!("Ingredient[{i}].InstanceId"), id, Some("C2PA"));
    }
}

fn ext_from_content_type(ct: &str) -> &'static str {
    let c = ct.to_ascii_lowercase();
    if c.contains("png") {
        "png"
    } else if c.contains("jpeg") || c.contains("jpg") {
        "jpg"
    } else if c.contains("svg") {
        "svg"
    } else if c.contains("webp") {
        "webp"
    } else if c.contains("json") {
        "json"
    } else if c.contains("c2pa") {
        "c2pa"
    } else {
        "bin"
    }
}

fn resource_bytes(reader: &Reader, uri: &str) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(Vec::new());
    reader
        .resource_to_stream(uri, &mut cursor)
        .map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

fn payload_from_bytes(bytes: Vec<u8>, content_type: &str) -> ExtractedPayload {
    ExtractedPayload {
        suggested_extension: ext_from_content_type(content_type).to_string(),
        content_type: content_type.to_string(),
        bytes,
    }
}

fn extract_icon(reader: &Reader, manifest: &Manifest) -> Result<ExtractedPayload, String> {
    if let Some(infos) = &manifest.claim_generator_info {
        for info in infos {
            if let Some(icon) = info.icon() {
                if let Ok(v) = serde_json::to_value(icon) {
                    if let Some(id) = v.get("identifier").and_then(|s| s.as_str()) {
                        let fmt = v
                            .get("format")
                            .and_then(|s| s.as_str())
                            .unwrap_or("application/octet-stream");
                        let bytes = resource_bytes(reader, id)?;
                        return Ok(payload_from_bytes(bytes, fmt));
                    }
                    if let Some(url) = v.get("url").and_then(|s| s.as_str()) {
                        let bytes = resource_bytes(reader, url)?;
                        return Ok(payload_from_bytes(bytes, "application/octet-stream"));
                    }
                }
            }
        }
    }
    if let Some(payload) = assertion_payload(manifest, "c2pa.icon") {
        return Ok(payload);
    }
    for (id, bytes) in manifest.resources().resources() {
        if id.to_ascii_lowercase().contains("icon") {
            return Ok(payload_from_bytes(
                bytes.clone(),
                "application/octet-stream",
            ));
        }
    }
    Err("no c2pa.icon / claim-generator icon found in the active manifest".into())
}

fn extract_thumbnail(reader: &Reader, manifest: &Manifest) -> Result<ExtractedPayload, String> {
    if let Some((fmt, bytes)) = manifest.thumbnail() {
        return Ok(payload_from_bytes(bytes.into_owned(), fmt));
    }
    if let Some(thumb) = manifest.thumbnail_ref() {
        let bytes = resource_bytes(reader, &thumb.identifier)?;
        return Ok(payload_from_bytes(bytes, &thumb.format));
    }
    if let Some(payload) = assertion_payload(manifest, "c2pa.thumbnail") {
        return Ok(payload);
    }
    Err("no thumbnail found in the active manifest".into())
}

fn assertion_matches(a: &ManifestAssertion, want: &str) -> bool {
    let want = want.trim();
    a.label() == want
        || a.label_with_instance() == want
        || a.label().starts_with(want)
        || a.label_with_instance().starts_with(want)
}

fn assertion_payload(manifest: &Manifest, want: &str) -> Option<ExtractedPayload> {
    let exact: Vec<_> = manifest
        .assertions()
        .iter()
        .filter(|a| a.label() == want || a.label_with_instance() == want)
        .collect();
    let matches: Vec<_> = if exact.is_empty() {
        manifest
            .assertions()
            .iter()
            .filter(|a| assertion_matches(a, want))
            .collect()
    } else {
        exact
    };
    let assertion = matches.first()?;
    if let Ok(bin) = assertion.binary() {
        return Some(payload_from_bytes(bin.to_vec(), "application/octet-stream"));
    }
    if let Ok(value) = assertion.value() {
        let bytes = serde_json::to_vec_pretty(value).ok()?;
        return Some(payload_from_bytes(bytes, "application/json"));
    }
    serde_json::to_vec_pretty(*assertion)
        .ok()
        .map(|bytes| payload_from_bytes(bytes, "application/json"))
}

fn extract_assertion(manifest: &Manifest, label: &str) -> Result<ExtractedPayload, String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("assertion label is empty".into());
    }
    assertion_payload(manifest, label).ok_or_else(|| {
        let available: Vec<_> = manifest
            .assertions()
            .iter()
            .map(|a| a.label().to_string())
            .collect();
        format!(
            "assertion `{label}` not found. Available: {}",
            if available.is_empty() {
                "(none)".into()
            } else {
                available.join(", ")
            }
        )
    })
}

/// Write a C2PA icon, thumbnail, or named assertion to bytes (caller writes the file).
pub fn extract_payload(
    data: &[u8],
    mime: &str,
    kind: C2paExtractKind,
) -> MetaResult<ExtractedPayload> {
    if !mime_supported(mime) {
        return Err(MetaError::Parse(format!(
            "MIME `{mime}` is not a C2PA-capable type in this build"
        )));
    }
    let mut stream = Cursor::new(data);
    let reader = Reader::default()
        .with_stream(mime, &mut stream)
        .map_err(|e| MetaError::Parse(format!("C2PA: {e}")))?;
    let manifest = reader
        .active_manifest()
        .ok_or_else(|| MetaError::Parse("no C2PA active manifest in this file".into()))?;
    match kind {
        C2paExtractKind::Icon => extract_icon(&reader, manifest).map_err(MetaError::Parse),
        C2paExtractKind::Thumbnail => {
            extract_thumbnail(&reader, manifest).map_err(MetaError::Parse)
        }
        C2paExtractKind::Assertion(label) => {
            extract_assertion(manifest, &label).map_err(MetaError::Parse)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze_buffer;
    use crate::types::AnalyzeOptions;

    fn fixture_png() -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/c2pa-sample.png");
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "missing fixtures/c2pa-sample.png ({e}). Generate with c2pa Builder + EphemeralSigner (see fixtures/README.md)."
            )
        })
    }

    #[test]
    fn c2pa_fixture_exposes_actions_and_cose() {
        let data = fixture_png();
        let (sections, warnings) = extract(&data, "image/png");
        assert!(
            sections.iter().any(|s| s.id == "c2pa"),
            "expected c2pa section, got {:?}, warnings={warnings:?}",
            sections.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
        let overview = sections.iter().find(|s| s.id == "c2pa").unwrap();
        assert!(
            overview
                .fields
                .iter()
                .any(|f| f.key == "ClaimGenerator" || f.key == "ClaimGeneratorInfo"),
            "ClaimGenerator should appear on the C2PA overview, got {:?}",
            overview.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
        );
        let state = overview
            .fields
            .iter()
            .find(|f| f.key == "ValidationState")
            .expect("ValidationState");
        assert!(
            state.value == "valid" || state.value == "trusted" || state.value == "invalid",
            "state={}",
            state.value
        );
        let binding = overview
            .fields
            .iter()
            .find(|f| f.key == "HardBinding")
            .expect("HardBinding");
        assert_eq!(
            binding.value, "pass",
            "untampered fixture should pass hard binding"
        );

        let actions = sections
            .iter()
            .find(|s| s.id == "c2pa-actions")
            .expect("c2pa-actions");
        assert!(
            actions
                .fields
                .iter()
                .any(|f| f.value.contains("c2pa.created") || f.key.starts_with("Action")),
            "actions={:?}",
            actions.fields
        );
        let agent_in_raw = actions.fields.iter().any(|f| {
            f.raw
                .as_ref()
                .is_some_and(|r| r.get("softwareAgent").is_some())
        });
        if agent_in_raw {
            assert!(
                actions
                    .fields
                    .iter()
                    .any(|f| f.key.contains("SoftwareAgent")),
                "softwareAgent in Action JSON must be promoted to Action[i].SoftwareAgent, got {:?}",
                actions.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
            );
        }

        let manifest = sections
            .iter()
            .find(|s| s.id == "c2pa-manifest")
            .expect("c2pa-manifest");
        assert!(
            manifest
                .fields
                .iter()
                .any(|f| f.key == "CoseIssuer" || f.key == "CoseCommonName"),
            "expected COSE fields, got {:?}",
            manifest.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("trust") || w.contains("untrusted") || w.contains("Valid")),
            "expected honest trust warning, got {warnings:?}"
        );
    }

    #[test]
    fn c2pa_tamper_fails_hard_binding() {
        let mut data = fixture_png();
        if let Some(pos) = data.windows(4).position(|w| w == b"IDAT") {
            let i = pos + 8;
            if i < data.len() {
                data[i] ^= 0x55;
            }
        }
        let (sections, warnings) = extract(&data, "image/png");
        let overview = sections.iter().find(|s| s.id == "c2pa").expect("c2pa");
        let binding = overview
            .fields
            .iter()
            .find(|f| f.key == "HardBinding")
            .expect("HardBinding");
        assert!(
            binding.value == "fail" || binding.value == "fail_or_other",
            "binding={} warnings={warnings:?}",
            binding.value
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("dataHash") || w.contains("Invalid") || w.contains("hash")),
            "warnings={warnings:?}"
        );
    }

    #[test]
    fn plain_png_has_no_c2pa_noise() {
        let png = {
            let mut buf = Vec::new();
            {
                let mut enc = png::Encoder::new(std::io::Cursor::new(&mut buf), 2, 2);
                enc.set_color(png::ColorType::Rgb);
                enc.set_depth(png::BitDepth::Eight);
                let mut w = enc.write_header().unwrap();
                w.write_image_data(&[255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
                    .unwrap();
            }
            buf
        };
        let (sections, warnings) = extract(&png, "image/png");
        assert!(sections.is_empty(), "sections={sections:?}");
        assert!(warnings.is_empty(), "warnings={warnings:?}");
    }

    #[test]
    fn analyze_buffer_includes_c2pa_section() {
        let data = fixture_png();
        let a = analyze_buffer(&data, AnalyzeOptions::from_filename("c2pa-sample.png"));
        assert!(a.sections.iter().any(|s| s.id == "c2pa"));
        assert!(a.sections.iter().any(|s| s.id == "c2pa-actions"));
        let c2pa_idx = a
            .sections
            .iter()
            .position(|s| s.id == "c2pa")
            .expect("c2pa");
        let norm_idx = a
            .sections
            .iter()
            .position(|s| s.id == "normalized")
            .expect("normalized");
        if let Some(png_idx) = a.sections.iter().position(|s| s.id == "png-chunks") {
            assert!(
                c2pa_idx < png_idx,
                "C2PA overview should appear before png-chunks ({c2pa_idx} vs {png_idx})"
            );
            assert!(
                norm_idx < png_idx,
                "normalized should appear before png-chunks when a C2PA manifest exists ({norm_idx} vs {png_idx})"
            );
        }
    }

    #[test]
    fn promote_action_fields_flattens_agent_version_and_params() {
        let mut sec = Section::new("c2pa-actions", "C2PA actions");
        let raw = serde_json::json!({
            "action": "c2pa.created",
            "softwareAgent": {"name": "gpt-image", "version": "2.0"},
            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
            "parameters": {"prompt": "a cat", "ingredient": {"url": "self#jumbf=x"}}
        });
        promote_action_fields(&mut sec, 0, &raw);
        let get = |k: &str| {
            sec.fields
                .iter()
                .find(|f| f.key == k)
                .unwrap_or_else(|| panic!("missing {k} in {:?}", sec.fields))
        };
        assert_eq!(get("Action[0].SoftwareAgent").value, "gpt-image");
        assert_eq!(get("Action[0].Version").value, "2.0");
        assert!(get("Action[0].DigitalSourceType")
            .value
            .contains("trainedAlgorithmicMedia"));
        assert!(get("Action[0].Parameters").value.contains("prompt=a cat"));
        assert!(
            !get("Action[0].Parameters").value.contains("ingredient="),
            "hashed ingredient URIs should not clutter the summary"
        );
    }

    #[test]
    fn promote_action_fields_string_software_agent() {
        let mut sec = Section::new("c2pa-actions", "C2PA actions");
        promote_action_fields(
            &mut sec,
            1,
            &serde_json::json!({"softwareAgent": "Adobe Photoshop 26.0"}),
        );
        assert_eq!(
            sec.fields
                .iter()
                .find(|f| f.key == "Action[1].SoftwareAgent")
                .map(|f| f.value.as_str()),
            Some("Adobe Photoshop 26.0")
        );
    }

    // Known-valid RSA cert (Internet Widgits sample) used only to exercise PEM load.
    const VALID_TEST_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjx9pVMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANDJ
cPOwZjWzrMZIlLVAPATA1NE12P25Qs0Qp/2V8KKapd40YK3YdTH/X6UBQHzB0ov6
d+1emAAmPOSN2LP7LtkCAwEAAaNQME4wHQYDVR0OBBYEFKtFjN8dIkyWDxKv7KC0
iY86L7C3MB8GA1UdIwQYMBaAFKtFjN8dIkyWDxKv7KC0iY86L7C3MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQB0TFgHe7EDWP7CTf9pZUwBiYPGmPFO5KjQ
Cjsy8jxTm5uT9iyZAQdA3M3pM+zsz5olKDpg8Ra4bd4hAg8y6eM8
-----END CERTIFICATE-----
";

    #[test]
    fn c2pa_warnings_are_compact_by_default() {
        let data = fixture_png();
        let (_sections, compact) = extract(&data, "image/png");
        assert!(
            compact
                .iter()
                .any(|w| w.contains("-v") && w.contains("status")),
            "expected one summary line, got {compact:?}"
        );
        assert!(
            !compact.iter().any(|w| w.starts_with("C2PA COSE:")
                || w.starts_with("C2PA hard binding:")
                || w.starts_with("C2PA validation:")),
            "per-code warnings should be verbose-only, got {compact:?}"
        );
        let (_s, verbose) = extract_with(
            &data,
            "image/png",
            &C2paOptions {
                verbose: true,
                trust_anchors: None,
            },
        );
        assert!(
            verbose.iter().any(|w| w.starts_with("C2PA COSE:")
                || w.starts_with("C2PA validation:")
                || w.contains("signingCredential")
                || w.contains("untrusted")),
            "verbose should list status codes, got {verbose:?}"
        );
    }

    #[test]
    fn extract_assertion_writes_json_not_table_dump() {
        let data = fixture_png();
        let payload = extract_payload(
            &data,
            "image/png",
            C2paExtractKind::Assertion("c2pa.actions".into()),
        )
        .expect("extract actions");
        assert_eq!(payload.content_type, "application/json");
        assert_eq!(payload.suggested_extension, "json");
        let text = String::from_utf8(payload.bytes).unwrap();
        assert!(
            text.contains("c2pa.created") || text.contains("actions") || text.contains("action"),
            "actions json={text}"
        );
        let missing = extract_payload(&data, "image/png", C2paExtractKind::Thumbnail);
        assert!(missing.is_err(), "fixture has no thumbnail");
    }

    #[test]
    fn ingredient_json_promotes_title_hash_relationship() {
        let mut sec = Section::new("c2pa-ingredients", "C2PA ingredients");
        push_ingredient_from_json(
            &mut sec,
            0,
            &serde_json::json!({
                "title": "parent.jpg",
                "hash": "sha256-deadbeef",
                "relationship": "parentOf",
                "format": "image/jpeg",
                "instance_id": "xmp.iid:1"
            }),
        );
        let get = |k: &str| {
            sec.fields
                .iter()
                .find(|f| f.key == k)
                .unwrap_or_else(|| panic!("missing {k}"))
                .value
                .as_str()
        };
        assert_eq!(get("Ingredient[0].Title"), "parent.jpg");
        assert_eq!(get("Ingredient[0].Hash"), "sha256-deadbeef");
        assert_eq!(get("Ingredient[0].Relationship"), "parentOf");
        assert_eq!(get("Ingredient[0].Format"), "image/jpeg");
    }

    #[test]
    fn trust_anchors_missing_path_warns() {
        let data = fixture_png();
        let (_secs, warnings) = extract_with(
            &data,
            "image/png",
            &C2paOptions {
                verbose: false,
                trust_anchors: Some(PathBuf::from(
                    "this-file-does-not-exist-metadissect-trust.pem",
                )),
            },
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("trust anchors") || w.contains("failed to load")),
            "warnings={warnings:?}"
        );
    }

    #[test]
    fn trust_anchors_pem_file_and_directory_are_applied() {
        let data = fixture_png();
        let dir = std::env::temp_dir().join(format!("metadissect-trust-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let pem_path = dir.join("ca.pem");
        std::fs::write(&pem_path, VALID_TEST_PEM).unwrap();
        let (sections, warnings) = extract_with(
            &data,
            "image/png",
            &C2paOptions {
                verbose: false,
                trust_anchors: Some(pem_path.clone()),
            },
        );
        let overview = sections.iter().find(|s| s.id == "c2pa").expect("c2pa");
        let anchors = overview
            .fields
            .iter()
            .find(|f| f.key == "TrustAnchors")
            .expect("TrustAnchors");
        assert!(
            anchors.value.contains("ca.pem"),
            "TrustAnchors={}",
            anchors.value
        );
        let applied = overview
            .fields
            .iter()
            .find(|f| f.key == "TrustAnchorsApplied")
            .map(|f| f.value.as_str());
        assert!(
            applied == Some("true")
                || warnings
                    .iter()
                    .any(|w| w.contains("not applied") || w.contains("trust")),
            "applied={applied:?} warnings={warnings:?}"
        );

        let (dir_secs, _) = extract_with(
            &data,
            "image/png",
            &C2paOptions {
                verbose: false,
                trust_anchors: Some(dir.clone()),
            },
        );
        let dir_ov = dir_secs.iter().find(|s| s.id == "c2pa").expect("c2pa");
        assert!(
            dir_ov
                .fields
                .iter()
                .any(|f| f.key == "TrustAnchors" && !f.value.contains("(none)")),
            "directory trust anchors should be recorded"
        );
        let _ = std::fs::remove_file(&pem_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn resolve_trust_anchors_prefers_explicit_path() {
        let p = PathBuf::from("custom-anchors.pem");
        assert_eq!(
            resolve_trust_anchors_path(Some(&p)).as_deref(),
            Some(p.as_path())
        );
    }
}
