//! Ontological normalization: map heterogeneous metadata keys to unified labels
//! while preserving original `raw`, namespace, and offset on each source Field.

use crate::types::{Field, Section};
use std::collections::BTreeMap;

/// Canonical keys used across formats (MWG-oriented).
pub const CANON_CREATOR: &str = "Creator";
pub const CANON_CREATED: &str = "Created";
pub const CANON_TITLE: &str = "Title";
pub const CANON_SOFTWARE: &str = "Software";
pub const CANON_GPS: &str = "Gps";
pub const CANON_COPYRIGHT: &str = "Copyright";
pub const CANON_DESCRIPTION: &str = "Description";
pub const CANON_KEYWORDS: &str = "Keywords";

/// Build a `normalized` section from already-parsed sections.
/// Source fields are left intact; this only adds a consolidated view.
pub fn build_normalized_section(sections: &[Section]) -> Section {
    let mut best: BTreeMap<&'static str, Field> = BTreeMap::new();
    let mut lat: Option<&Field> = None;
    let mut lon: Option<&Field> = None;

    for sec in sections {
        for f in &sec.fields {
            if let Some(canon) = map_to_canonical(&f.key) {
                let rank = source_rank(f.namespace.as_deref());
                match best.get(canon) {
                    Some(existing) => {
                        let existing_rank = source_rank(existing.namespace.as_deref());
                        if rank > existing_rank {
                            best.insert(canon, promote(f, canon));
                        }
                    }
                    None => {
                        best.insert(canon, promote(f, canon));
                    }
                }
            }
            let k = f.key.to_ascii_lowercase();
            if k.contains("gpslatitude") && !k.contains("ref") {
                lat = Some(f);
            }
            if k.contains("gpslongitude") && !k.contains("ref") {
                lon = Some(f);
            }
        }
    }

    if let (Some(la), Some(lo)) = (lat, lon) {
        let value = format!("{}, {}", la.value, lo.value);
        let mut gps = Field::new(CANON_GPS, value).with_namespace("Normalized");
        gps.raw = Some(serde_json::json!({
            "latitude": la.value,
            "longitude": lo.value,
            "lat_key": la.key,
            "lon_key": lo.key,
        }));
        if let Some(off) = la.offset {
            gps.offset = Some(off);
        }
        best.insert(CANON_GPS, gps);
    }

    let mut section = Section::new("normalized", "Normalized");
    for (canon, field) in best {
        let _ = canon;
        section.push(field);
    }
    section
}

fn promote(src: &Field, canon: &str) -> Field {
    let mut f = Field::new(canon, src.value.clone());
    f.label = canon.to_string();
    f.namespace = Some("Normalized".into());
    f.offset = src.offset;
    f.length = src.length;
    f.raw = Some(serde_json::json!({
        "source_key": src.key,
        "source_namespace": src.namespace,
        "source_value": src.value,
    }));
    if let Some(ref r) = src.raw {
        if let Some(obj) = f.raw.as_mut().and_then(|v| v.as_object_mut()) {
            obj.insert("raw".into(), r.clone());
        }
    }
    f
}

/// Rank namespaces for conflict resolution (higher wins).
/// MWG-out-of-sync prefers XMP; when in sync EXIF/XMP/IPTC are close.
fn source_rank(ns: Option<&str>) -> i32 {
    let n = ns.unwrap_or("").to_ascii_lowercase();
    if n.starts_with("normalized") {
        return -1;
    }
    if n.contains("xmp") {
        return 80;
    }
    if n.contains("exif") {
        return 70;
    }
    if n.contains("iptc") {
        return 50;
    }
    if n.contains("pdf") || n.contains("office") || n.contains("odf") {
        return 40;
    }
    if n.starts_with("pe") || n.starts_with("elf") || n.starts_with("macho") {
        return 45;
    }
    30
}

pub fn map_to_canonical(key: &str) -> Option<&'static str> {
    let k = key.rsplit(':').next().unwrap_or(key);
    let k = k.rsplit('@').next().unwrap_or(k);
    let lower = k.to_ascii_lowercase().replace(['_', '-', ' '], "");

    match lower.as_str() {
        "creator" | "author" | "byline" | "artist" | "dccreator" | "authors" | "writereditor"
        | "companyname" => Some(CANON_CREATOR),
        "created" | "creationdate" | "createdate" | "datetimeoriginal"
        | "datetime" | "datecreated" | "xmpcreatedate" | "digitalcreationdate"
        | "creatim" => Some(CANON_CREATED),
        "title" | "objectname" | "headline" | "dctitle" | "tit2" | "productname"
        | "filedescription" => Some(CANON_TITLE),
        "software" | "creatortool" | "producer" | "processingsoftware" | "encodingsoftware" => {
            Some(CANON_SOFTWARE)
        }
        "copyright" | "copyrightnotice" | "dcrights" | "rights" | "legalcopyright" => {
            Some(CANON_COPYRIGHT)
        }
        "description" | "captionabstract" | "imagedescription" | "dcdescription" | "comment"
        | "comments" => Some(CANON_DESCRIPTION),
        "keywords" | "subject" | "dcsubject" | "supplementalcategory" => Some(CANON_KEYWORDS),
        "gps" | "gpsposition" | "location" => Some(CANON_GPS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_aliases() {
        assert_eq!(map_to_canonical("Byline"), Some(CANON_CREATOR));
        assert_eq!(map_to_canonical("dc:creator"), Some(CANON_CREATOR));
        assert_eq!(map_to_canonical("DateTimeOriginal"), Some(CANON_CREATED));
        assert_eq!(map_to_canonical("CreatorTool"), Some(CANON_SOFTWARE));
        assert_eq!(map_to_canonical("ObjectName"), Some(CANON_TITLE));
    }

    #[test]
    fn prefers_xmp_over_iptc() {
        let mut iptc = Section::new("iptc", "IPTC");
        iptc.push(Field::new("Byline", "Iptc Author").with_namespace("IPTC:IIM"));
        let mut xmp = Section::new("xmp", "XMP");
        xmp.push(Field::new("creator", "Xmp Author").with_namespace("XMP"));
        let norm = build_normalized_section(&[iptc, xmp]);
        let creator = norm.fields.iter().find(|f| f.key == CANON_CREATOR).unwrap();
        assert_eq!(creator.value, "Xmp Author");
        assert!(creator.raw.is_some());
    }
}
