use crate::types::Section;

pub fn parse_generic(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sec = Section::new("generic", "Generic file");
    sec.add("Length", data.len().to_string(), Some("Generic"));
    let printable = data
        .iter()
        .take(64)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    sec.add(
        "PrintablePrefix64",
        format!("{printable}/{}", data.len().min(64)),
        Some("Generic"),
    );
    if data.len() >= 4 {
        sec.add(
            "HeaderAscii",
            String::from_utf8_lossy(&data[..4.min(data.len())])
                .chars()
                .map(|c| if c.is_control() { '.' } else { c })
                .collect::<String>(),
            Some("Generic"),
        );
    }
    (vec![sec], Vec::new())
}
