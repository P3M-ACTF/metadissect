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

use crate::types::Section;

pub fn parse_for_mime(
    data: &[u8],
    mime: &str,
    filename: Option<&str>,
) -> (Vec<Section>, Vec<String>) {
    let name = filename.unwrap_or("").to_ascii_lowercase();
    if mime.starts_with("image/")
        || name.ends_with(".jpg")
        || name.ends_with(".jpeg")
        || name.ends_with(".png")
        || name.ends_with(".tif")
        || name.ends_with(".tiff")
        || name.ends_with(".gif")
        || name.ends_with(".webp")
        || name.ends_with(".bmp")
        || name.ends_with(".ico")
        || name.ends_with(".heic")
        || name.ends_with(".avif")
    {
        return image::parse_image(data, mime);
    }
    if mime.starts_with("audio/")
        || name.ends_with(".mp3")
        || name.ends_with(".flac")
        || name.ends_with(".ogg")
        || name.ends_with(".m4a")
        || name.ends_with(".wav")
        || name.ends_with(".aiff")
        || name.ends_with(".aif")
    {
        return audio::parse_audio(data);
    }
    if mime.starts_with("video/")
        || name.ends_with(".mp4")
        || name.ends_with(".mov")
        || name.ends_with(".mkv")
        || name.ends_with(".webm")
        || name.ends_with(".avi")
    {
        return video::parse_video(data, mime);
    }
    if mime == "application/pdf" || name.ends_with(".pdf") {
        return pdf::parse_pdf(data);
    }
    if office::is_office_mime(mime)
        || name.ends_with(".docx")
        || name.ends_with(".xlsx")
        || name.ends_with(".pptx")
        || name.ends_with(".odt")
        || name.ends_with(".ods")
        || name.ends_with(".odp")
        || name.ends_with(".rtf")
        || name.ends_with(".doc")
        || name.ends_with(".xls")
        || name.ends_with(".ppt")
    {
        return office::parse_office(data, mime);
    }
    if mime.contains("epub")
        || name.ends_with(".epub")
        || mime == "application/zip"
        || name.ends_with(".zip")
    {
        return office::parse_zip_xml_package(data);
    }
    if mime == "text/html" || name.ends_with(".html") || name.ends_with(".htm") {
        return html::parse_html(data);
    }
    if mime.contains("json") || name.ends_with(".json") {
        return html::parse_json(data);
    }
    if mime.starts_with("font/")
        || name.ends_with(".ttf")
        || name.ends_with(".otf")
        || name.ends_with(".woff")
    {
        return font::parse_font(data);
    }
    if mime == "message/rfc822" || name.ends_with(".eml") {
        return eml::parse_eml(data);
    }
    generic::parse_generic(data)
}
