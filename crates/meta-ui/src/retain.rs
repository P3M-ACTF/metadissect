use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct RetainConfig {
    pub dir: PathBuf,
    pub ttl: Duration,
}

impl RetainConfig {
    pub fn new(dir: PathBuf, ttl_secs: u64) -> Self {
        Self {
            dir,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.dir.as_os_str().is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RetainedEntry {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug)]
pub struct RetainStore {
    config: RetainConfig,
    sessions: Mutex<HashMap<String, Vec<String>>>,
}

impl RetainStore {
    pub fn new(config: RetainConfig) -> Self {
        if config.enabled() {
            let _ = std::fs::create_dir_all(&config.dir);
        }
        Self {
            config,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &RetainConfig {
        &self.config
    }

    pub fn store(&self, session_id: &str, filename: &str, data: &[u8]) -> Option<RetainedEntry> {
        if !self.config.enabled() {
            return None;
        }
        self.cleanup_expired();
        let now = now_secs();
        let id = format!("{session_id}-{}", now);
        let safe_name = sanitize_filename(filename);
        let final_path = self.config.dir.join(format!("{id}_{safe_name}"));
        if let Err(e) = std::fs::write(&final_path, data) {
            eprintln!("retain write failed: {e}");
            return None;
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions
                .entry(session_id.to_string())
                .or_default()
                .push(id.clone());
        }
        Some(RetainedEntry {
            id,
            filename: safe_name,
            size: data.len() as u64,
            created_at: now,
            expires_at: now + self.config.ttl.as_secs(),
        })
    }

    pub fn list_session(&self, session_id: &str) -> Vec<RetainedEntry> {
        self.cleanup_expired();
        let ids = self
            .sessions
            .lock()
            .map(|m| m.get(session_id).cloned().unwrap_or_default())
            .unwrap_or_default();
        ids.into_iter()
            .filter_map(|id| self.entry_for_id(&id))
            .collect()
    }

    fn entry_for_id(&self, id: &str) -> Option<RetainedEntry> {
        let dir = &self.config.dir;
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(id) {
                let meta = entry.metadata().ok()?;
                let created = meta
                    .created()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(now_secs());
                let fname = name.split('_').skip(1).collect::<Vec<_>>().join("_");
                return Some(RetainedEntry {
                    id: id.to_string(),
                    filename: fname,
                    size: meta.len(),
                    created_at: created,
                    expires_at: created + self.config.ttl.as_secs(),
                });
            }
        }
        None
    }

    pub fn cleanup_expired(&self) {
        if !self.config.enabled() {
            return;
        }
        let cutoff = now_secs().saturating_sub(self.config.ttl.as_secs());
        if let Ok(entries) = std::fs::read_dir(&self.config.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let created = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.created().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if created < cutoff {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sanitize_filename(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out = "upload.bin".to_string();
    }
    if out.len() > 120 {
        out.truncate(120);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retain_store_and_list() {
        let dir = std::env::temp_dir().join(format!("meta-ui-retain-{}", now_secs()));
        let store = RetainStore::new(RetainConfig::new(dir.clone(), 3600));
        let entry = store.store("sess1", "photo.jpg", b"testdata").unwrap();
        assert_eq!(entry.filename, "photo.jpg");
        let list = store.list_session("sess1");
        assert_eq!(list.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
