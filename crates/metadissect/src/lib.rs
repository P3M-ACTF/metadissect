//! Exhaustive local metadata extraction: parsers, hashes, MIME magic, and SSRF-safe fetch.
//!
//! # Quick start
//!
//! ```no_run
//! use std::path::Path;
//! use metadissect::{analyze_path, analyze_buffer, AnalyzeOptions};
//!
//! let analysis = analyze_path(Path::new("photo.jpg"))?;
//! println!("{} fields", analysis.field_count());
//!
//! let bytes = std::fs::read("photo.jpg")?;
//! let analysis = analyze_buffer(&bytes, AnalyzeOptions::from_filename("photo.jpg"));
//! # Ok::<(), metadissect::MetaError>(())
//! ```
//!
//! Main entry points: [`analyze_buffer`], [`analyze_path`], [`analyze_path_with_options`],
//! [`analyze_path_with_bytes`], [`analyze_html_string`], and [`analyze_json_string`]. For remote
//! URLs use [`fetch::fetch_and_analyze`] (SSRF-safe). Serialize results with [`export`].
//!
//! C2PA: pass [`AnalyzeOptions::trust_anchors`] (or env `C2PA_TRUST_ANCHORS`) so the CAI
//! verifier can treat a PEM list as `Settings.trust.trust_anchors`. Without a list,
//! `Valid ≠ Trusted` is expected — the official CAI trust list is not bundled.
//!
//! Educational narrative lives in MetaInstructor (`meta-explain`); this crate keeps
//! technical `warnings` only. The JSON HTTP API is served by the `metadissect` CLI
//! (`metadissect serve --api`), not by this library.

pub mod analyze;
#[cfg(feature = "c2pa")]
pub mod c2pa_support;
pub mod embed;
pub mod entropy;
pub mod error;
pub mod export;
pub mod fetch;
#[doc(hidden)]
pub mod fixture_jpeg;
pub mod hashes;
pub mod magic;
pub mod mwg;
pub mod normalize;
pub mod parsers;
pub mod text;
pub mod types;

pub use analyze::{
    analyze_buffer, analyze_html_string, analyze_json_string, analyze_path,
    analyze_path_with_bytes, analyze_path_with_options,
};
pub use error::{MetaError, Result};
pub use text::truncate_chars;
pub use types::{Analysis, AnalyzeOptions, Field, Hashes, Magic, Section, Source};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_jpeg::rich_exif_jpeg;

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
    }

    fn write_fixture(name: &str, bytes: &[u8]) {
        let dir = fixtures_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        let _ = std::fs::write(path, bytes);
    }

    #[test]
    fn jpeg_fixture_returns_dozens_of_exif_fields() {
        let jpeg = rich_exif_jpeg();
        write_fixture("rich-exif.jpg", &jpeg);
        assert_eq!(&jpeg[0..2], &[0xFF, 0xD8]);
        let analysis = analyze_buffer(&jpeg, AnalyzeOptions::from_filename("rich-exif.jpg"));
        let exif_fields: Vec<_> = analysis
            .sections
            .iter()
            .filter(|s| {
                s.id.contains("exif")
                    || s.label.contains("EXIF")
                    || s.fields
                        .iter()
                        .any(|f| f.namespace.as_deref().unwrap_or("").starts_with("EXIF"))
            })
            .flat_map(|s| s.fields.iter())
            .collect();
        assert!(
            exif_fields.len() >= 30,
            "expected dozens of EXIF fields, got {} across {} sections. sections={:?}",
            exif_fields.len(),
            analysis.sections.len(),
            analysis
                .sections
                .iter()
                .map(|s| format!("{}:{}", s.id, s.fields.len()))
                .collect::<Vec<_>>()
        );
        assert!(analysis.find_field("Make").is_some());
        assert!(analysis.find_field("Model").is_some());
        assert!(analysis.find_field("DateTimeOriginal").is_some());
        assert!(analysis.find_field("GPSLatitude").is_some());
        assert!(analysis.find_field("LensModel").is_some());
    }

    #[test]
    fn hashes_and_entropy_always_present() {
        let analysis = analyze_buffer(b"hello", AnalyzeOptions::from_filename("hello.txt"));
        assert_eq!(analysis.hashes.md5.len(), 32);
        assert_eq!(analysis.hashes.sha256.len(), 64);
        assert_eq!(analysis.hashes.blake3.len(), 64);
        assert!(analysis.entropy > 0.0);
    }

    #[test]
    fn html_extracts_meta_and_jsonld() {
        let html = r#"<!DOCTYPE html><html><head>
            <title>Demo</title>
            <meta name="description" content="Hello">
            <meta property="og:title" content="OG Title">
            <meta name="twitter:card" content="summary">
            <meta name="dc.creator" content="Ada">
            <link rel="canonical" href="https://example.com/x">
            <script type="application/ld+json">{"@type":"Article","headline":"Hi","author":{"name":"Ada"}}</script>
            </head><body></body></html>"#;
        write_fixture("sample.html", html.as_bytes());
        let a = analyze_html_string(html, Some("sample.html".into()));
        assert!(a.find_field("og:title").is_some() || a.find_field("Title").is_some());
        assert!(a.field_count() > 6);
    }

    #[test]
    fn png_text_chunks_are_listed() {
        let png = tiny_png_with_text();
        write_fixture("sample.png", &png);
        let a = analyze_buffer(&png, AnalyzeOptions::from_filename("sample.png"));
        assert!(
            a.sections.iter().any(|s| s
                .fields
                .iter()
                .any(|f| f.key == "Comment" || f.value.contains("hello"))),
            "PNG text missing: {:?}",
            a.sections.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pdf_info_and_eof() {
        let pdf = MINIMAL_PDF.as_bytes();
        write_fixture("sample.pdf", pdf);
        let a = analyze_buffer(pdf, AnalyzeOptions::from_filename("sample.pdf"));
        assert_eq!(a.mime, "application/pdf");
        assert!(a.find_field("Title").is_some() || a.find_field("EofMarkers").is_some());
    }

    #[test]
    fn ole_compound_is_detected_with_subset_parser() {
        let mut ole = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        ole.extend_from_slice(&[0u8; 64]);
        let a = analyze_buffer(&ole, AnalyzeOptions::from_filename("legacy.doc"));
        assert!(
            a.sections.iter().any(|s| s.id == "ole-cfbf")
                || a.warnings.iter().any(|w| w.contains("OLE")),
            "expected ole-cfbf section or OLE warning"
        );
    }

    #[test]
    fn magic_first_ignores_wrong_extension() {
        let jpeg = rich_exif_jpeg();
        let a = analyze_buffer(&jpeg, AnalyzeOptions::from_filename("disguised.pdf"));
        assert_eq!(a.mime, "image/jpeg");
        assert!(a.find_field("Make").is_some() || a.field_count() > 10);
        assert!(a.sections.iter().any(|s| s.id == "normalized"));
    }

    #[test]
    fn mwg_out_of_sync_marks_iptc() {
        // Build minimal Photoshop APP13: IPTC Byline + wrong digest + XMP APP1
        let iptc_payload = {
            let mut v = Vec::new();
            // 0x1C 02 50 (Byline) + len + "Iptc"
            v.extend_from_slice(&[0x1C, 0x02, 0x50, 0x00, 0x04]);
            v.extend_from_slice(b"Iptc");
            v
        };
        let digest = [0u8; 16]; // deliberately wrong
        let irb = build_irb(&[(0x0404, &iptc_payload), (0x0425, &digest)]);
        let mut app13 = b"Photoshop 3.0\0".to_vec();
        app13.extend_from_slice(&irb);

        let xmp = br#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>XmpPerson</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"#;
        let mut app1_xmp = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
        app1_xmp.extend_from_slice(xmp);

        let jpeg = assemble_jpeg_with_apps(&[&app1_xmp], &app13);
        let a = analyze_buffer(&jpeg, AnalyzeOptions::from_filename("mwg.jpg"));
        assert!(
            a.warnings
                .iter()
                .any(|w| w.contains("MWG") && w.contains("XMP")),
            "warnings={:?}",
            a.warnings
        );
        let mwg = a
            .sections
            .iter()
            .find(|s| s.id == "mwg")
            .expect("mwg section");
        assert!(mwg
            .fields
            .iter()
            .any(|f| f.key == "Precedence" && f.value.contains("xmp")));
        let byline = a
            .sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .find(|f| f.key == "Byline")
            .expect("Byline");
        assert!(
            byline
                .explanation
                .as_deref()
                .unwrap_or("")
                .contains("superseded")
                || byline.value == "Iptc",
            "byline={byline:?}"
        );
    }

    #[test]
    fn zip_nested_jpeg_embed_is_parsed() {
        let jpeg = {
            let j = rich_exif_jpeg();
            assert_eq!(&j[0..2], &[0xFF, 0xD8]);
            j
        };
        let zip_bytes = build_zip_with_media_jpeg(&jpeg);
        let a = analyze_buffer(&zip_bytes, AnalyzeOptions::from_filename("pack.docx"));
        assert!(
            a.sections.iter().any(|s| {
                s.id.starts_with("embed")
                    || s.fields
                        .iter()
                        .any(|f| f.key == "EmbedAnchor" || f.key == "EmbedMime")
            }),
            "expected embed sections, got {:?}",
            a.sections.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }

    fn build_irb(resources: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(id, payload) in resources {
            out.extend_from_slice(b"8BIM");
            out.extend_from_slice(&id.to_be_bytes());
            out.push(0); // empty Pascal name
                         // name padding already even (1 byte name_len + 0 name = odd → pad 1)
            out.push(0);
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(payload);
            if payload.len() % 2 == 1 {
                out.push(0);
            }
        }
        out
    }

    fn assemble_jpeg_with_apps(app1s: &[&[u8]], app13: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI
        for payload in app1s {
            out.push(0xFF);
            out.push(0xE1);
            let len = (payload.len() + 2) as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out.push(0xFF);
        out.push(0xED);
        let len = (app13.len() + 2) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(app13);
        // minimal SOF0 + SOS + EOI stub
        out.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF,
            0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0xFF, 0xD9,
        ]);
        out
    }

    fn build_zip_with_media_jpeg(jpeg: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("word/media/image1.jpg", opts).unwrap();
            zip.write_all(jpeg).unwrap();
            zip.start_file("docProps/core.xml", opts).unwrap();
            zip.write_all(
                br#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>EmbedTest</dc:creator><dc:title>Nested</dc:title></cp:coreProperties>"#,
            )
            .unwrap();
            zip.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn heic_note_is_honest() {
        let mut heic = vec![0u8; 32];
        heic[4..8].copy_from_slice(b"ftyp");
        heic[8..12].copy_from_slice(b"heic");
        let a = analyze_buffer(&heic, AnalyzeOptions::from_filename("a.heic"));
        assert!(
            a.notes_educativas
                .iter()
                .any(|n| n.contains("iloc") || n.contains("HEIC"))
                || a.warnings
                    .iter()
                    .any(|w| w.contains("HEIC") || w.contains("iloc")),
            "expected honest HEIC note"
        );
    }

    #[test]
    fn office_and_eml_and_mp3_fixtures() {
        let dir = fixtures_dir();
        for (name, pred) in [
            ("sample.docx", "creator"),
            ("sample.eml", "Subject"),
            ("sample.mp3", "TIT2"),
        ] {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            let data = std::fs::read(&path).unwrap();
            let a = analyze_buffer(&data, AnalyzeOptions::from_filename(name));
            let blob = a
                .sections
                .iter()
                .flat_map(|s| s.fields.iter())
                .map(|f| format!("{} {}", f.key, f.value))
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                blob.to_ascii_lowercase().contains(pred) || a.field_count() > 4,
                "{name} should expose metadata, got {}",
                a.field_count()
            );
        }
    }

    fn tiny_png_with_text() -> Vec<u8> {
        use std::io::Cursor;
        let mut buf = Vec::new();
        {
            let mut enc = png::Encoder::new(Cursor::new(&mut buf), 2, 2);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            enc.add_text_chunk("Comment".into(), "hello from png".into())
                .unwrap();
            enc.add_text_chunk("Author".into(), "MetaDissect".into())
                .unwrap();
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
                .unwrap();
        }
        buf
    }

    const MINIMAL_PDF: &str = "%PDF-1.4\n1 0 obj<< /Title (Fixture PDF) /Author (MetaDissect) /Creator (metadissect) /Producer (Rust) /CreationDate (D:20240615120000+02'00') >>endobj\n3 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n2 0 obj<< /Type /Pages /Count 0 /Kids [] >>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000200 00000 n \n0000000150 00000 n \ntrailer<< /Size 4 /Root 3 0 R /Info 1 0 R >>\nstartxref\n280\n%%EOF\n";
}
