use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesRef, BytesText};
use quick_xml::XmlVersion;

pub(crate) fn decode_text(t: &BytesText<'_>) -> String {
    t.decode().map(|c| c.into_owned()).unwrap_or_default()
}

pub(crate) fn attr_value(attr: &Attribute<'_>) -> String {
    attr.normalized_value(XmlVersion::Implicit1_0)
        .map(|v| v.into_owned())
        .unwrap_or_default()
}

pub(crate) fn general_ref_text(r: &BytesRef<'_>) -> String {
    if let Ok(Some(ch)) = r.resolve_char_ref() {
        return ch.to_string();
    }
    let Ok(name) = r.decode() else {
        return String::new();
    };
    match name.as_ref() {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "quot" => "\"".into(),
        "apos" => "'".into(),
        _ => String::new(),
    }
}
