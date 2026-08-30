pub fn shell_css() -> &'static [u8] {
    include_bytes!("../static/shell.css")
}

pub fn shell_js() -> &'static [u8] {
    include_bytes!("../static/shell.js")
}

pub fn shell_css_mime() -> &'static str {
    "text/css; charset=utf-8"
}

pub fn shell_js_mime() -> &'static str {
    "application/javascript; charset=utf-8"
}
