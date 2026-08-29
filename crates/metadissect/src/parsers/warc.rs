//! WARC (ISO 28500) record metadata. Graceful on truncated files.

use crate::types::{Field, Section};

const INTERESTING_WARC_HEADERS: &[&str] = &[
    "WARC-Type",
    "WARC-Target-URI",
    "WARC-Date",
    "WARC-Record-ID",
    "WARC-IP-Address",
    "WARC-Payload-Digest",
    "WARC-Block-Digest",
    "WARC-Concurrent-To",
    "WARC-Refers-To",
    "WARC-Filename",
    "WARC-Truncated",
    "Content-Type",
    "Content-Length",
];

const HTTP_HEADER_KEYS: &[&str] = &[
    "Server",
    "Date",
    "Content-Type",
    "Content-Length",
    "Last-Modified",
    "ETag",
    "Location",
    "Set-Cookie",
    "X-Powered-By",
    "Via",
];

pub fn parse_warc(data: &[u8]) -> (Vec<Section>, Vec<String>) {
    let mut sections = Vec::new();
    let mut warnings = Vec::new();
    let mut summary = Section::new("warc", "WARC archive");
    summary.add("Size", data.len().to_string(), Some("WARC"));

    let mut offset = 0usize;
    let mut record_idx = 0usize;
    let mut type_counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    while offset < data.len() {
        // Skip leading blank lines / CR LF between records
        while offset < data.len() && (data[offset] == b'\r' || data[offset] == b'\n') {
            offset += 1;
        }
        if offset >= data.len() {
            break;
        }

        match parse_one_record(data, offset) {
            Ok((rec, next)) => {
                let warc_type = rec
                    .warc_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("WARC-Type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| "unknown".into());
                *type_counts.entry(warc_type.clone()).or_insert(0) += 1;

                let mut sec = Section::new(
                    format!("warc-record-{record_idx}"),
                    format!("WARC record {record_idx} ({warc_type})"),
                );
                sec.add("Offset", offset.to_string(), Some("WARC"));
                for key in INTERESTING_WARC_HEADERS {
                    if let Some(v) = header_get(&rec.warc_headers, key) {
                        sec.fields.push(
                            Field::new(*key, v)
                                .with_namespace("WARC")
                                .with_span(offset as u64, (next - offset) as u64),
                        );
                    }
                }
                // Any other WARC-* headers not already listed
                for (k, v) in &rec.warc_headers {
                    if k.starts_with("WARC-")
                        && !INTERESTING_WARC_HEADERS
                            .iter()
                            .any(|h| h.eq_ignore_ascii_case(k))
                    {
                        sec.fields
                            .push(Field::new(k.clone(), v.clone()).with_namespace("WARC"));
                    }
                }

                if let Some(http) = &rec.http_headers {
                    for key in HTTP_HEADER_KEYS {
                        if let Some(v) = header_get(http, key) {
                            sec.fields.push(
                                Field::new(format!("HTTP-{key}"), v).with_namespace("WARC:HTTP"),
                            );
                        }
                    }
                    if let Some(status) = &rec.http_status_line {
                        sec.add("HTTP-StatusLine", status.clone(), Some("WARC:HTTP"));
                    }
                }

                if rec.truncated {
                    warnings.push(format!(
                        "WARC record {record_idx} truncated (Content-Length exceeds remaining bytes)"
                    ));
                    sec.add("Truncated", "true", Some("WARC"));
                }

                sections.push(sec);
                record_idx += 1;
                offset = next;
                if rec.truncated {
                    break;
                }
            }
            Err(msg) => {
                if record_idx == 0 {
                    warnings.push(format!("WARC: {msg}"));
                } else {
                    warnings.push(format!(
                        "WARC: stopped after {record_idx} record(s): {msg}"
                    ));
                }
                break;
            }
        }
    }

    summary.add("RecordCount", record_idx.to_string(), Some("WARC"));
    for (ty, n) in type_counts {
        summary.add(format!("Type:{ty}"), n.to_string(), Some("WARC"));
    }
    sections.insert(0, summary);
    (sections, warnings)
}

struct WarcRecord {
    warc_headers: Vec<(String, String)>,
    http_status_line: Option<String>,
    http_headers: Option<Vec<(String, String)>>,
    truncated: bool,
}

fn parse_one_record(data: &[u8], start: usize) -> Result<(WarcRecord, usize), String> {
    let version_line_end = find_line_end(data, start).ok_or_else(|| {
        "incomplete version line".to_string()
    })?;
    let version = std::str::from_utf8(&data[start..version_line_end])
        .unwrap_or("")
        .trim();
    if !version.starts_with("WARC/") {
        return Err(format!("expected WARC/ version line, got {version:?}"));
    }

    let mut pos = skip_crlf(data, version_line_end);
    let (warc_headers, after_headers) = parse_header_block(data, pos)?;
    pos = after_headers;

    let content_length = header_get(&warc_headers, "Content-Length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let remaining = data.len().saturating_sub(pos);
    let truncated = content_length > remaining;
    let payload_len = content_length.min(remaining);
    let payload = &data[pos..pos + payload_len];
    pos += payload_len;

    let warc_type = header_get(&warc_headers, "WARC-Type").unwrap_or_default();
    let (http_status_line, http_headers) =
        if matches!(warc_type.as_str(), "response" | "request" | "resource") {
            parse_http_block(payload, &warc_type)
        } else {
            (None, None)
        };

    // Trailing CRLF CRLF after payload (best-effort; missing on truncate)
    if !truncated {
        pos = skip_record_separator(data, pos);
    }

    Ok((
        WarcRecord {
            warc_headers,
            http_status_line,
            http_headers,
            truncated,
        },
        pos,
    ))
}

fn parse_http_block(
    payload: &[u8],
    warc_type: &str,
) -> (Option<String>, Option<Vec<(String, String)>>) {
    if payload.is_empty() {
        return (None, None);
    }
    let text = String::from_utf8_lossy(payload);
    let normalized = text.replace("\r\n", "\n");
    let (head, _) = normalized
        .split_once("\n\n")
        .unwrap_or((normalized.as_str(), ""));
    let mut lines = head.lines();
    let status = lines.next().map(|s| s.trim().to_string()).filter(|s| {
        if warc_type == "request" {
            s.contains("HTTP/") || s.starts_with("GET ") || s.starts_with("POST ")
        } else {
            s.starts_with("HTTP/")
        }
    });
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (status, Some(headers))
}

fn parse_header_block(
    data: &[u8],
    start: usize,
) -> Result<(Vec<(String, String)>, usize), String> {
    let mut headers = Vec::new();
    let mut pos = start;
    let mut current: Option<(String, String)> = None;

    loop {
        if pos >= data.len() {
            return Err("truncated while reading WARC headers".into());
        }
        let line_end = find_line_end(data, pos).ok_or_else(|| {
            "truncated WARC header line".to_string()
        })?;
        let raw = &data[pos..line_end];
        let next = skip_crlf(data, line_end);

        // Empty line ends headers
        if raw.is_empty() {
            if let Some(prev) = current.take() {
                headers.push(prev);
            }
            return Ok((headers, next));
        }

        let line = String::from_utf8_lossy(raw);
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, ref mut v)) = current {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            if let Some(prev) = current.take() {
                headers.push(prev);
            }
            current = Some((k.trim().to_string(), v.trim().to_string()));
        }
        pos = next;
    }
}

fn header_get(headers: &[(String, String)], key: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
}

fn find_line_end(data: &[u8], start: usize) -> Option<usize> {
    data[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| {
            let end = start + i;
            if end > start && data[end - 1] == b'\r' {
                end - 1
            } else {
                end
            }
        })
}

fn skip_crlf(data: &[u8], at: usize) -> usize {
    let mut p = at;
    if p < data.len() && data[p] == b'\r' {
        p += 1;
    }
    if p < data.len() && data[p] == b'\n' {
        p += 1;
    }
    p
}

fn skip_record_separator(data: &[u8], mut pos: usize) -> usize {
    // After payload: typically \r\n\r\n
    let mut blanks = 0;
    while pos < data.len() && blanks < 2 {
        if data[pos] == b'\r' {
            pos += 1;
        }
        if pos < data.len() && data[pos] == b'\n' {
            pos += 1;
            blanks += 1;
        } else {
            break;
        }
    }
    pos
}

/// Minimal synthetic WARC with warcinfo + response (for tests / fixtures).
pub fn minimal_warc_fixture() -> Vec<u8> {
    let warcinfo_body = "software: MetaDissect/0.7.0\r\nformat: WARC File Format 1.0\r\n";
    let response_http = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Server: ExampleServer/1.0\r\n",
        "Content-Type: text/html\r\n",
        "Content-Length: 13\r\n",
        "\r\n",
        "<html></html>"
    );
    let mut out = String::new();
    out.push_str("WARC/1.0\r\n");
    out.push_str("WARC-Type: warcinfo\r\n");
    out.push_str("WARC-Date: 2024-06-15T12:00:00Z\r\n");
    out.push_str("WARC-Record-ID: <urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee>\r\n");
    out.push_str("WARC-Filename: sample.warc\r\n");
    out.push_str("Content-Type: application/warc-fields\r\n");
    out.push_str(&format!("Content-Length: {}\r\n\r\n", warcinfo_body.len()));
    out.push_str(warcinfo_body);
    out.push_str("\r\n\r\n");

    out.push_str("WARC/1.0\r\n");
    out.push_str("WARC-Type: response\r\n");
    out.push_str("WARC-Target-URI: https://example.com/\r\n");
    out.push_str("WARC-Date: 2024-06-15T12:00:01Z\r\n");
    out.push_str("WARC-Record-ID: <urn:uuid:11111111-2222-3333-4444-555555555555>\r\n");
    out.push_str("WARC-IP-Address: 93.184.216.34\r\n");
    out.push_str("WARC-Payload-Digest: sha1:ABCDEF0123456789ABCDEF0123456789ABCDEF01\r\n");
    out.push_str("Content-Type: application/http; msgtype=response\r\n");
    out.push_str(&format!("Content-Length: {}\r\n\r\n", response_http.len()));
    out.push_str(response_http);
    out.push_str("\r\n\r\n");
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_warcinfo_and_response() {
        let data = minimal_warc_fixture();
        let (secs, warns) = parse_warc(&data);
        assert!(warns.is_empty(), "{warns:?}");
        assert!(secs.iter().any(|s| s.id == "warc"));
        let response = secs
            .iter()
            .find(|s| s.id == "warc-record-1")
            .expect("response record");
        assert!(response.fields.iter().any(|f| {
            f.key == "WARC-Target-URI" && f.value.contains("example.com")
        }));
        assert!(response
            .fields
            .iter()
            .any(|f| f.key == "WARC-IP-Address"));
        assert!(response
            .fields
            .iter()
            .any(|f| f.key == "WARC-Payload-Digest"));
        assert!(response
            .fields
            .iter()
            .any(|f| f.key == "HTTP-Server" && f.value.contains("ExampleServer")));
    }

    #[test]
    fn truncated_warc_warns() {
        let mut data = minimal_warc_fixture();
        data.truncate(data.len() / 2);
        let (secs, warns) = parse_warc(&data);
        assert!(!secs.is_empty());
        assert!(
            warns.iter().any(|w| w.contains("truncat")),
            "warns={warns:?}"
        );
    }
}
