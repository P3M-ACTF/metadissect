pub mod audio;
pub mod eml;
pub mod font;
pub mod generic;
pub mod html;
pub mod image;
pub mod iptc;
pub mod jpeg;
pub mod office;
pub mod pdf;
pub mod png;
pub mod tiff;
pub mod video;
mod xml_util;
pub mod xmp;

use crate::embed;
use crate::magic::mime_from_filename;
use crate::types::Section;

/// Dispatch parsers by MIME (from magic). Extension is used only when MIME is
/// `application/octet-stream` or otherwise unknown.
pub fn parse_for_mime(
    data: &[u8],
    mime: &str,
    filename: Option<&str>,
) -> (Vec<Section>, Vec<String>) {
    parse_for_mime_at_depth(
        data,
        mime,
        filename,
        0,
        embed::DEFAULT_MAX_EMBED_DEPTH,
    )
}

pub fn parse_for_mime_at_depth(
    data: &[u8],
    mime: &str,
    filename: Option<&str>,
    depth: u8,
    max_depth: u8,
) -> (Vec<Section>, Vec<String>) {
    let effective = resolve_dispatch_mime(mime, filename);
    dispatch(data, &effective, depth, max_depth)
}

/// Extension fallback only for unknown / octet-stream MIME.
pub fn resolve_dispatch_mime(mime: &str, filename: Option<&str>) -> String {
    if !is_unknown_mime(mime) {
        return mime.to_string();
    }
    if let Some(name) = filename {
        if let Some(hint) = mime_from_filename(name) {
            return hint.to_string();
        }
    }
    mime.to_string()
}

pub fn is_unknown_mime(mime: &str) -> bool {
    mime.is_empty()
        || mime == "application/octet-stream"
        || mime == "application/unknown"
        || mime == "binary/octet-stream"
}

fn dispatch(data: &[u8], mime: &str, depth: u8, max_depth: u8) -> (Vec<Section>, Vec<String>) {
    if mime.starts_with("image/") {
        return image::parse_image(data, mime);
    }
    if mime.starts_with("audio/") || mime == "application/ogg" {
        return audio::parse_audio(data);
    }
    if mime.starts_with("video/") {
        return video::parse_video(data, mime);
    }
    if mime == "application/pdf" {
        return pdf::parse_pdf_at_depth(data, depth, max_depth);
    }
    if office::is_office_mime(mime) {
        return office::parse_office_at_depth(data, mime, depth, max_depth);
    }
    if mime.contains("epub") || mime == "application/zip" {
        return office::parse_zip_xml_package_at_depth(data, depth, max_depth);
    }
    if mime == "text/html" {
        return html::parse_html(data);
    }
    if mime.contains("json") {
        return html::parse_json(data);
    }
    if mime.starts_with("font/") {
        return font::parse_font(data);
    }
    if mime == "message/rfc822" {
        return eml::parse_eml(data);
    }
    // Weak magic: still sniff container signatures before giving up
    if data.starts_with(b"%PDF-") {
        return pdf::parse_pdf_at_depth(data, depth, max_depth);
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return office::parse_zip_xml_package_at_depth(data, depth, max_depth);
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return office::parse_office_at_depth(data, "application/vnd.ms-office", depth, max_depth);
    }
    generic::parse_generic(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_mime_wins_over_mismatched_extension() {
        // JPEG bytes labeled as .pdf must still go to the image path
        let jpeg = [0xFFu8, 0xD8, 0xFF, 0xD9];
        let mime = "image/jpeg";
        let resolved = resolve_dispatch_mime(mime, Some("trick.pdf"));
        assert_eq!(resolved, "image/jpeg");
        let (secs, _) = parse_for_mime(&jpeg, mime, Some("trick.pdf"));
        assert!(
            secs.iter().any(|s| s.id.contains("jpeg") || s.label.contains("JPEG")),
            "expected JPEG sections, got {:?}",
            secs.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn extension_fallback_only_for_octet_stream() {
        assert_eq!(
            resolve_dispatch_mime("application/octet-stream", Some("photo.jpg")),
            "image/jpeg"
        );
        assert_eq!(
            resolve_dispatch_mime("text/plain", Some("photo.jpg")),
            "text/plain"
        );
    }
}
