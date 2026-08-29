use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    File,
    Url,
    Html,
    Json,
    Bytes,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::File => write!(f, "file"),
            Source::Url => write!(f, "url"),
            Source::Html => write!(f, "html"),
            Source::Json => write!(f, "json"),
            Source::Bytes => write!(f, "bytes"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Magic {
    pub mime: String,
    pub extension: Option<String>,
    pub description: String,
    pub hex_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

impl Field {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let label = humanize(&key);
        Self {
            key,
            label,
            value: value.into(),
            raw: None,
            namespace: None,
            offset: None,
            length: None,
            explanation: None,
        }
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn with_raw(mut self, raw: serde_json::Value) -> Self {
        self.raw = Some(raw);
        self
    }

    pub fn with_span(mut self, offset: u64, length: u64) -> Self {
        self.offset = Some(offset);
        self.length = Some(length);
        self
    }

    pub fn with_explanation(mut self, text: impl Into<String>) -> Self {
        self.explanation = Some(text.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Section {
    pub id: String,
    pub label: String,
    pub fields: Vec<Field>,
}

impl Section {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            fields: Vec::new(),
        }
    }

    pub fn push(&mut self, field: Field) {
        self.fields.push(field);
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn add(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        namespace: Option<&str>,
    ) {
        let mut field = Field::new(key, value);
        if let Some(ns) = namespace {
            field.namespace = Some(ns.to_string());
        }
        self.fields.push(field);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub source: Source,
    pub mime: String,
    pub filename: Option<String>,
    pub size: u64,
    pub extracted_at: String,
    pub hashes: Hashes,
    pub magic: Magic,
    pub entropy: f64,
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
    pub notes_educativas: Vec<String>,
}

impl Analysis {
    pub fn push_section(&mut self, section: Section) {
        if !section.is_empty() {
            self.sections.push(section);
        }
    }

    pub fn field_count(&self) -> usize {
        self.sections.iter().map(|s| s.fields.len()).sum()
    }

    pub fn find_field(&self, key: &str) -> Option<&Field> {
        self.sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .find(|f| f.key.eq_ignore_ascii_case(key) || f.label.eq_ignore_ascii_case(key))
    }

    pub fn fields_in_namespace(&self, prefix: &str) -> Vec<&Field> {
        self.sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .filter(|f| {
                f.namespace
                    .as_deref()
                    .is_some_and(|ns| ns.starts_with(prefix))
                    || f.key
                        .to_ascii_lowercase()
                        .starts_with(&prefix.to_ascii_lowercase())
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub filename: Option<String>,
    pub source: Option<Source>,
    pub include_hashes: bool,
    pub file_size: Option<u64>,
    pub mtime: Option<String>,
    pub ctime: Option<String>,
    pub atime: Option<String>,
    pub source_url: Option<String>,
    pub response_headers: Vec<(String, String)>,
    /// Max recursion depth for nested embeds (OOXML/PDF). Default: 2.
    pub max_embed_depth: u8,
    /// When true, PNG `png-chunks` lists every chunk (including each IDAT).
    /// Default compact mode aggregates IDAT into `IDATCount` / `IDATBytes`.
    pub verbose: bool,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            filename: None,
            source: None,
            include_hashes: false,
            file_size: None,
            mtime: None,
            ctime: None,
            atime: None,
            source_url: None,
            response_headers: Vec::new(),
            max_embed_depth: crate::embed::DEFAULT_MAX_EMBED_DEPTH,
            verbose: false,
        }
    }
}

impl AnalyzeOptions {
    pub fn from_filename(name: impl Into<String>) -> Self {
        Self {
            filename: Some(name.into()),
            include_hashes: true,
            ..Default::default()
        }
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

pub fn humanize(key: &str) -> String {
    let trimmed = key.rsplit(':').next().unwrap_or(key);
    let mut out = String::new();
    for (i, ch) in trimmed.chars().enumerate() {
        if ch == '_' || ch == '-' {
            out.push(' ');
            continue;
        }
        if i > 0 && ch.is_uppercase() && out.chars().last().is_some_and(|p| p.is_lowercase()) {
            out.push(' ');
        }
        if out.is_empty() || out.chars().last().is_some_and(|p| p == ' ') {
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        key.to_string()
    } else {
        out
    }
}
