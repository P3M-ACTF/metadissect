//! Metadata Working Group (MWG) reconciliation for IPTC vs XMP.
//!
//! Photoshop IRB resource 0x0425 stores an MD5 (IPTCDigest) of the IPTC-NAA block.
//! When the digest matches the current IPTC bytes, IPTC and XMP are treated as in sync.
//! When missing or mismatched, overlapping properties prefer XMP over IPTC (MWG guidance).

use crate::types::Section;
use md5::{Digest, Md5};
use std::collections::HashMap;

/// Result of comparing Photoshop IPTCDigest with the IPTC payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestStatus {
    /// No 0x0425 resource present.
    Missing,
    /// Digest present and equals MD5(IPTC).
    Match,
    /// Digest present but does not equal MD5(IPTC).
    Mismatch,
    /// Digest present but no IPTC block to hash.
    NoIptc,
}

impl DigestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestStatus::Missing => "missing",
            DigestStatus::Match => "match",
            DigestStatus::Mismatch => "mismatch",
            DigestStatus::NoIptc => "no_iptc",
        }
    }

    pub fn in_sync(&self) -> bool {
        matches!(self, DigestStatus::Match)
    }
}

/// Overlapping IPTC ↔ XMP property pairs (local names, case-insensitive).
const OVERLAP: &[(&str, &str)] = &[
    ("ObjectName", "title"),
    ("Headline", "Headline"),
    ("Byline", "creator"),
    ("CaptionAbstract", "description"),
    ("CopyrightNotice", "rights"),
    ("Keywords", "subject"),
    ("DateCreated", "DateCreated"),
    ("City", "City"),
    ("ProvinceState", "State"),
    ("CountryPrimaryLocationName", "Country"),
    ("Credit", "Credit"),
    ("Source", "Source"),
];

pub fn md5_hex(data: &[u8]) -> String {
    hex::encode(Md5::digest(data))
}

pub fn compare_iptc_digest(
    iptc_bytes: Option<&[u8]>,
    stored_digest: Option<&[u8]>,
) -> DigestStatus {
    match (iptc_bytes, stored_digest) {
        (_, None) => DigestStatus::Missing,
        (None, Some(_)) => DigestStatus::NoIptc,
        (Some(iptc), Some(dig)) => {
            let computed = Md5::digest(iptc);
            if dig.len() == 16 && dig == computed.as_slice() {
                DigestStatus::Match
            } else {
                DigestStatus::Mismatch
            }
        }
    }
}

/// Apply MWG precedence: when out of sync, mark conflicting IPTC fields and prefer XMP.
/// Returns an MWG status section plus warnings. Mutates `sections` in place for IPTC fields.
pub fn reconcile(
    sections: &mut [Section],
    iptc_bytes: Option<&[u8]>,
    stored_digest: Option<&[u8]>,
) -> (Section, Vec<String>) {
    let mut warnings = Vec::new();
    let status = compare_iptc_digest(iptc_bytes, stored_digest);

    let mut mwg = Section::new("mwg", "MWG / IPTCDigest");
    mwg.add("IptcDigestStatus", status.as_str(), Some("MWG"));
    if let Some(dig) = stored_digest {
        mwg.add("IptcDigestStored", hex::encode(dig), Some("MWG"));
    }
    if let Some(bytes) = iptc_bytes {
        mwg.add("IptcDigestComputed", md5_hex(bytes), Some("MWG"));
        mwg.add("IptcByteLength", bytes.len().to_string(), Some("MWG"));
    }

    match status {
        DigestStatus::Match => {
            mwg.add("Precedence", "in_sync", Some("MWG"));
        }
        DigestStatus::Mismatch => {
            mwg.add("Precedence", "xmp_over_iptc", Some("MWG"));
            warnings.push(
                "MWG: IPTCDigest does not match IPTC bytes; preferring XMP over IPTC for overlapping properties.".into(),
            );
            demote_conflicting_iptc(sections, &mut mwg);
        }
        DigestStatus::Missing => {
            if has_iptc_and_xmp(sections) {
                mwg.add("Precedence", "xmp_over_iptc", Some("MWG"));
                warnings.push(
                    "MWG: IPTCDigest missing while both IPTC and XMP are present; preferring XMP on conflicts.".into(),
                );
                demote_conflicting_iptc(sections, &mut mwg);
            } else {
                mwg.add("Precedence", "n/a", Some("MWG"));
            }
        }
        DigestStatus::NoIptc => {
            mwg.add("Precedence", "n/a", Some("MWG"));
            warnings.push("MWG: IPTCDigest present but no IPTC-NAA block found.".into());
        }
    }

    (mwg, warnings)
}

fn has_iptc_and_xmp(sections: &[Section]) -> bool {
    let mut iptc = false;
    let mut xmp = false;
    for s in sections {
        for f in &s.fields {
            let ns = f.namespace.as_deref().unwrap_or("");
            if ns.contains("IPTC") {
                iptc = true;
            }
            if ns.contains("XMP") {
                xmp = true;
            }
        }
    }
    iptc && xmp
}

fn demote_conflicting_iptc(sections: &mut [Section], mwg: &mut Section) {
    let xmp_vals = collect_xmp_overlap(sections);
    let mut conflicts = 0usize;
    for sec in sections.iter_mut() {
        for f in sec.fields.iter_mut() {
            let ns = f.namespace.as_deref().unwrap_or("");
            if !ns.contains("IPTC") {
                continue;
            }
            let Some(xmp_key) = overlap_xmp_for_iptc(&f.key) else {
                continue;
            };
            let Some(xmp_val) = xmp_vals.get(&xmp_key.to_ascii_lowercase()) else {
                continue;
            };
            if values_differ(&f.value, xmp_val) {
                conflicts += 1;
                let note = format!(
                    "MWG: superseded by XMP ({xmp_key}={xmp_val}); IPTC kept as raw evidence"
                );
                f.explanation = Some(note.clone());
                // Preserve original in raw if missing
                if f.raw.is_none() {
                    f.raw = Some(serde_json::json!({
                        "iptc_value": f.value,
                        "preferred_xmp": xmp_val,
                        "mwg": "xmp_preferred",
                    }));
                }
            }
        }
    }
    if conflicts > 0 {
        mwg.add("ConflictCount", conflicts.to_string(), Some("MWG"));
    }
}

fn collect_xmp_overlap(sections: &[Section]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for sec in sections {
        for f in &sec.fields {
            let ns = f.namespace.as_deref().unwrap_or("");
            if !ns.contains("XMP") {
                continue;
            }
            let local = f.key.rsplit(':').next().unwrap_or(&f.key);
            let local = local.rsplit('@').next().unwrap_or(local);
            for &(_, xmp_name) in OVERLAP {
                if local.eq_ignore_ascii_case(xmp_name) {
                    map.insert(xmp_name.to_ascii_lowercase(), f.value.clone());
                }
            }
        }
    }
    map
}

fn overlap_xmp_for_iptc(iptc_key: &str) -> Option<&'static str> {
    let local = iptc_key.rsplit(':').next().unwrap_or(iptc_key);
    for &(iptc, xmp) in OVERLAP {
        if local.eq_ignore_ascii_case(iptc) {
            return Some(xmp);
        }
    }
    None
}

fn values_differ(a: &str, b: &str) -> bool {
    a.trim() != b.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Field;

    #[test]
    fn digest_match_and_mismatch() {
        let iptc = b"\x1c\x02\x50\x00\x04test";
        let dig = Md5::digest(iptc);
        assert_eq!(
            compare_iptc_digest(Some(iptc), Some(dig.as_slice())),
            DigestStatus::Match
        );
        assert_eq!(
            compare_iptc_digest(Some(iptc), Some(&[0u8; 16])),
            DigestStatus::Mismatch
        );
        assert_eq!(compare_iptc_digest(Some(iptc), None), DigestStatus::Missing);
    }

    #[test]
    fn out_of_sync_prefers_xmp() {
        let mut iptc = Section::new("iptc-iim", "IPTC");
        iptc.push(
            Field::new("Byline", "Iptc Person")
                .with_namespace("IPTC:IIM")
                .with_span(10, 4),
        );
        let mut xmp = Section::new("xmp", "XMP");
        xmp.push(Field::new("creator", "Xmp Person").with_namespace("XMP"));
        let mut sections = vec![iptc, xmp];
        let wrong = [0u8; 16];
        let (mwg, warns) = reconcile(&mut sections, Some(b"iptc-bytes"), Some(&wrong));
        assert!(warns.iter().any(|w| w.contains("preferring XMP")));
        assert_eq!(
            mwg.fields
                .iter()
                .find(|f| f.key == "Precedence")
                .map(|f| f.value.as_str()),
            Some("xmp_over_iptc")
        );
        let byline = sections[0]
            .fields
            .iter()
            .find(|f| f.key == "Byline")
            .unwrap();
        assert!(byline
            .explanation
            .as_deref()
            .unwrap()
            .contains("superseded"));
        assert_eq!(byline.value, "Iptc Person"); // raw IPTC retained
        assert!(byline.offset.is_some());
    }
}
