use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("fetch error: {0}")]
    Fetch(String),
    #[error("blocked URL (SSRF protection): {0}")]
    BlockedUrl(String),
    #[error("payload too large ({size} > {limit})")]
    TooLarge { size: u64, limit: u64 },
}

pub type Result<T> = std::result::Result<T, MetaError>;
