use crate::types::Magic;

pub fn inspect_magic(data: &[u8]) -> Magic {
    let hex_signature = hex_preview(data, 16);
    // Prefer our MSG / WARC classifiers over generic infer (OLE storage / octet-stream).
    if looks_like_warc(data) {
        return Magic {
            mime: "application/warc".into(),
            extension: Some("warc".into()),
            description: "WARC (ISO 28500)".into(),
            hex_signature,
        };
    }
    if crate::parsers::msg::looks_like_msg(data) {
        return Magic {
            mime: "application/vnd.ms-outlook".into(),
            extension: Some("msg".into()),
            description: "Outlook MSG (OLE/MAPI)".into(),
            hex_signature,
        };
    }
    if let Some(kind) = infer::get(data) {
        return Magic {
            mime: kind.mime_type().to_string(),
            extension: Some(kind.extension().to_string()),
            description: format!("infer: {}", kind.mime_type()),
            hex_signature,
        };
    }
    let (mime, description) = fallback_magic(data);
    Magic {
        mime: mime.to_string(),
        extension: extension_for_mime(mime).map(|s| s.to_string()),
        description: description.to_string(),
        hex_signature,
    }
}

pub fn hex_preview(data: &[u8], n: usize) -> String {
    data.iter()
        .take(n)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn fallback_magic(data: &[u8]) -> (&'static str, &'static str) {
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return ("image/jpeg", "JPEG SOI");
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return ("image/png", "PNG signature");
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return ("image/gif", "GIF");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return ("image/webp", "RIFF WEBP");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"AVI " {
        return ("video/x-msvideo", "RIFF AVI");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WAVE" {
        return ("audio/wav", "RIFF WAVE");
    }
    if data.starts_with(b"BM") {
        return ("image/bmp", "BMP");
    }
    if data.len() >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 1 && data[3] == 0 {
        return ("image/x-icon", "ICO");
    }
    if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return ("video/x-matroska", "EBML / Matroska / WebM");
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        if crate::parsers::msg::looks_like_msg(data) {
            return ("application/vnd.ms-outlook", "Outlook MSG (OLE/MAPI)");
        }
        return (
            "application/vnd.ms-office",
            "OLE Compound File (legacy Office)",
        );
    }
    if looks_like_warc(data) {
        return ("application/warc", "WARC (ISO 28500)");
    }
    if data.starts_with(b"%PDF-") {
        return ("application/pdf", "PDF");
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return classify_zip(data);
    }
    if data.starts_with(b"{\\rtf") {
        return ("application/rtf", "RTF");
    }
    if data.starts_with(b"ID3") || looks_like_mpeg_audio(data) {
        return ("audio/mpeg", "MP3 / ID3");
    }
    if data.starts_with(b"fLaC") {
        return ("audio/flac", "FLAC");
    }
    if data.starts_with(b"OggS") {
        return ("application/ogg", "Ogg container");
    }
    if data.starts_with(b"FORM") && data.len() >= 12 && &data[8..12] == b"AIFF" {
        return ("audio/aiff", "AIFF");
    }
    if looks_like_mp4(data) {
        return classify_isobmff(data);
    }
    if looks_like_ttf(data) {
        return ("font/ttf", "TrueType / OpenType");
    }
    if data.starts_with(b"wOFF") {
        return ("font/woff", "WOFF");
    }
    if looks_like_eml(data) {
        return ("message/rfc822", "Email / EML");
    }
    if looks_like_pe(data) {
        return (
            "application/vnd.microsoft.portable-executable",
            "PE / MZ executable",
        );
    }
    if data.starts_with(b"\x7fELF") {
        return ("application/x-elf", "ELF executable");
    }
    if looks_like_macho(data) {
        return ("application/x-mach-binary", "Mach-O binary");
    }
    if looks_like_html(data) {
        return ("text/html", "HTML");
    }
    if looks_like_json(data) {
        return ("application/json", "JSON");
    }
    if looks_like_xml(data) {
        return ("application/xml", "XML");
    }
    if is_mostly_text(data) {
        return ("text/plain", "Text");
    }
    ("application/octet-stream", "Unknown binary")
}

fn classify_zip(data: &[u8]) -> (&'static str, &'static str) {
    let hay = String::from_utf8_lossy(&data[..data.len().min(4096)]);
    if hay.contains("word/") {
        (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "DOCX",
        )
    } else if hay.contains("xl/") {
        (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "XLSX",
        )
    } else if hay.contains("ppt/") {
        (
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "PPTX",
        )
    } else if hay.contains("META-INF/container.xml") || hay.contains("mimetypeapplication/epub") {
        ("application/epub+zip", "EPUB")
    } else if hay.contains("mimetypeapplication/vnd.oasis.opendocument") {
        ("application/vnd.oasis.opendocument.text", "ODF")
    } else {
        ("application/zip", "ZIP")
    }
}

fn classify_isobmff(data: &[u8]) -> (&'static str, &'static str) {
    if data.len() < 12 {
        return ("application/mp4", "ISO BMFF");
    }
    let brand = &data[8..12];
    match brand {
        b"heic" | b"heix" | b"mif1" | b"msf1" => ("image/heic", "HEIC / HEIF"),
        b"avif" | b"avis" => ("image/avif", "AVIF"),
        b"M4A " | b"M4B " => ("audio/mp4", "M4A"),
        b"qt  " => ("video/quicktime", "QuickTime MOV"),
        _ => ("video/mp4", "MP4"),
    }
}

fn looks_like_mp4(data: &[u8]) -> bool {
    data.len() >= 12 && &data[4..8] == b"ftyp"
}

fn looks_like_mpeg_audio(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0xFF && data[1] & 0xE0 == 0xE0
}

fn looks_like_ttf(data: &[u8]) -> bool {
    data.starts_with(&[0x00, 0x01, 0x00, 0x00])
        || data.starts_with(b"OTTO")
        || data.starts_with(b"true")
}

fn looks_like_html(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(&data[..data.len().min(512)]).to_ascii_lowercase();
    let t = s.trim_start();
    t.starts_with("<!doctype html") || t.starts_with("<html") || t.contains("<meta")
}

fn looks_like_json(data: &[u8]) -> bool {
    let t = skip_ws(data);
    t.first() == Some(&b'{') || t.first() == Some(&b'[')
}

fn looks_like_xml(data: &[u8]) -> bool {
    skip_ws(data).starts_with(b"<?xml")
}

fn looks_like_eml(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(&data[..data.len().min(800)]);
    s.contains("From:")
        && (s.contains("Subject:") || s.contains("To:") || s.contains("MIME-Version:"))
}

fn looks_like_warc(data: &[u8]) -> bool {
    let head = &data[..data.len().min(16)];
    head.starts_with(b"WARC/1.") || head.starts_with(b"WARC/0.")
}

fn looks_like_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }
    let pe_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    pe_off
        .checked_add(4)
        .filter(|&end| end <= data.len())
        .is_some_and(|end| &data[pe_off..end] == b"PE\0\0")
}

fn looks_like_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    matches!(le, 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE)
        || matches!(be, 0xCAFEBABE | 0xBEBAFECA)
}

fn is_mostly_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let sample = &data[..data.len().min(4096)];
    let textish = sample
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    textish * 100 / sample.len() > 90
}

fn skip_ws(data: &[u8]) -> &[u8] {
    let n = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    &data[n..]
}

pub fn extension_for_mime(mime: &str) -> Option<&'static str> {
    Some(match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/bmp" => "bmp",
        "image/tiff" => "tiff",
        "image/heic" => "heic",
        "image/avif" => "avif",
        "audio/mpeg" => "mp3",
        "audio/flac" => "flac",
        "audio/wav" => "wav",
        "audio/mp4" => "m4a",
        "video/mp4" => "mp4",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "text/html" => "html",
        "application/json" => "json",
        "message/rfc822" => "eml",
        "application/vnd.ms-outlook" | "application/x-msg" => "msg",
        "application/warc" | "application/x-warc" => "warc",
        "font/ttf" => "ttf",
        "application/vnd.microsoft.portable-executable" | "application/x-dosexec" => "exe",
        "application/x-elf" => "elf",
        "application/x-mach-binary" => "macho",
        _ => return None,
    })
}

pub fn mime_from_filename(name: &str) -> Option<&'static str> {
    let ext = name.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "ico" => "image/x-icon",
        "heic" | "heif" => "image/heic",
        "avif" => "image/avif",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "aiff" | "aif" => "audio/aiff",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "rtf" => "application/rtf",
        "doc" => "application/msword",
        "xls" => "application/vnd.ms-excel",
        "ppt" => "application/vnd.ms-powerpoint",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "epub" => "application/epub+zip",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "woff" => "font/woff",
        "eml" => "message/rfc822",
        "msg" => "application/vnd.ms-outlook",
        "warc" => "application/warc",
        "exe" | "dll" | "sys" | "scr" => "application/vnd.microsoft.portable-executable",
        "elf" | "so" | "o" => "application/x-elf",
        "dylib" | "macho" | "bundle" => "application/x-mach-binary",
        _ => return None,
    })
}
