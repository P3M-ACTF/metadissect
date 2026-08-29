//! C2PA / JUMBF manifest extraction via the Content Authenticity Initiative `c2pa` crate.
//!
//! Surfaces active-manifest metadata, `c2pa.actions` / `c2pa.actions.v2`, hard-binding
//! (dataHash) results, and COSE signature fields when present. Cryptographic validation
//! uses the crate's built-in verifier; certificate **trust** requires an external trust
//! list (not bundled), so `Trusted` is rare and `signingCredential.untrusted` is common
//! for self-signed / unlisted CAs — that is reported honestly in warnings.

use crate::types::{Field, Section};
use c2pa::assertions::Actions;
use c2pa::{Error as C2paError, Manifest, Reader, ValidationState};
use std::io::Cursor;

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

/// Extract C2PA sections and warnings from an asset buffer.
///
/// Returns empty sections/warnings when no manifest is present.
pub fn extract(data: &[u8], mime: &str) -> (Vec<Section>, Vec<String>) {
    if !mime_supported(mime) {
        return (Vec::new(), Vec::new());
    }

    let mut stream = Cursor::new(data);
    let reader = match Reader::default().with_stream(mime, &mut stream) {
        Ok(r) => r,
        Err(e) if is_absent(&e) => return (Vec::new(), Vec::new()),
        Err(C2paError::UnsupportedType) => {
            return (
                Vec::new(),
                vec![format!(
                    "C2PA: format `{mime}` is listed by the SDK but this build cannot parse it (missing feature or handler)."
                )],
            );
        }
        Err(e) => {
            return (
                Vec::new(),
                vec![format!("C2PA: failed to read/validate manifest store: {e}")],
            );
        }
    };

    if reader.active_manifest().is_none() && reader.manifests().is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut warnings = Vec::new();
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
                "Invalid = structural/crypto failure; Valid = crypto OK but cert may be untrusted; Trusted = crypto OK + trust list match. No C2PA trust anchors are bundled.",
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
            if code.contains("untrusted") {
                warnings.push(format!("C2PA COSE: {line}"));
            } else if hard_binding_codes(&code) {
                warnings.push(format!("C2PA hard binding: {line}"));
            } else {
                warnings.push(format!("C2PA validation: {line}"));
            }
        }
    }

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

fn manifest_section(id: &str, label: &str, manifest: &Manifest) -> Section {
    let mut sec = Section::new(id, label);

    if let Some(t) = manifest.title() {
        sec.add("Title", t.to_string(), Some("C2PA"));
    }
    if let Some(l) = manifest.label() {
        sec.add("Label", l.to_string(), Some("C2PA"));
    }
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
                "(binary or undecoded)",
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
                    f.raw = Some(raw);
                }
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
    }
}
