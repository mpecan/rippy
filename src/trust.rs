//! Project config trust model.
//!
//! Stores SHA-256 hashes of trusted project config files in
//! `~/.rippy/trusted.json`. When rippy encounters a project config,
//! it checks this database before loading. Untrusted or modified
//! configs are ignored with a stderr warning.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::RippyError;

/// A single trust entry recording the hash and timestamp of a trusted config.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustEntry {
    /// Content hash in the form `"sha256:<hex>"`.
    pub hash: String,
    /// ISO 8601 timestamp when the file was trusted.
    pub trusted_at: String,
}

/// Result of checking a project config against the trust database.
#[derive(Debug, PartialEq, Eq)]
pub enum TrustStatus {
    /// The file's hash matches the stored entry.
    Trusted,
    /// No entry exists for this file path.
    Untrusted,
    /// An entry exists but the file content has changed.
    Modified { expected: String, actual: String },
}

/// Trust database backed by a JSON file at `~/.rippy/trusted.json`.
#[derive(Debug)]
pub struct TrustDb {
    entries: HashMap<String, TrustEntry>,
    path: PathBuf,
}

impl TrustDb {
    /// Load the trust database from `~/.rippy/trusted.json`.
    ///
    /// Returns an empty database if the file does not exist or cannot be parsed.
    pub fn load() -> Self {
        trust_db_path().map_or_else(
            || Self {
                entries: HashMap::new(),
                path: PathBuf::new(),
            },
            |path| Self::load_from(&path),
        )
    }

    /// Load the trust database from a specific path (for testing).
    pub fn load_from(path: &Path) -> Self {
        let entries = std::fs::read_to_string(path)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default();
        Self {
            entries,
            path: path.to_owned(),
        }
    }

    /// Save the trust database back to disk.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Trust` if the file cannot be written.
    pub fn save(&self) -> Result<(), RippyError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                RippyError::Trust(format!(
                    "could not create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| RippyError::Trust(format!("could not serialize trust db: {e}")))?;
        std::fs::write(&self.path, json)
            .map_err(|e| RippyError::Trust(format!("could not write {}: {e}", self.path.display())))
    }

    /// Check whether a project config file is trusted.
    pub fn check(&self, path: &Path, content: &str) -> TrustStatus {
        let key = canonical_key(path);
        let actual_hash = hash_content(content);
        match self.entries.get(&key) {
            None => TrustStatus::Untrusted,
            Some(entry) if entry.hash == actual_hash => TrustStatus::Trusted,
            Some(entry) => TrustStatus::Modified {
                expected: entry.hash.clone(),
                actual: actual_hash,
            },
        }
    }

    /// Mark a project config file as trusted using its current content.
    pub fn trust(&mut self, path: &Path, content: &str) {
        let key = canonical_key(path);
        let hash = hash_content(content);
        let now = now_iso8601();
        self.entries.insert(
            key,
            TrustEntry {
                hash,
                trusted_at: now,
            },
        );
    }

    /// Remove trust for a project config file.
    ///
    /// Returns `true` if an entry was removed.
    pub fn revoke(&mut self, path: &Path) -> bool {
        let key = canonical_key(path);
        self.entries.remove(&key).is_some()
    }

    /// Return all trusted entries.
    #[must_use]
    pub const fn list(&self) -> &HashMap<String, TrustEntry> {
        &self.entries
    }

    /// Check if the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute a SHA-256 hash of the given content, prefixed with `"sha256:"`.
#[must_use]
pub fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{result:x}")
}

/// Derive a stable key from a file path.
///
/// Uses the canonical (absolute) path if possible, falling back to the
/// original path string.
fn canonical_key(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_owned())
        .to_string_lossy()
        .into_owned()
}

/// Return the path to `~/.rippy/trusted.json`.
fn trust_db_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".rippy/trusted.json"))
}

/// Current time as an ISO 8601 string (UTC-like, using system time).
fn now_iso8601() -> String {
    // Use a simple seconds-since-epoch representation to avoid pulling in chrono.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Format as a readable timestamp without external crate.
    let secs = dur.as_secs();
    format_epoch_secs(secs)
}

/// Format seconds since epoch as `YYYY-MM-DDTHH:MM:SSZ`.
fn format_epoch_secs(secs: u64) -> String {
    // Days since epoch, then decompose into y/m/d.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since 1970-01-01 to (year, month, day).
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hash_content_deterministic() {
        let h1 = hash_content("allow *\n");
        let h2 = hash_content("allow *\n");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn hash_content_different_for_different_input() {
        let h1 = hash_content("allow *");
        let h2 = hash_content("deny *");
        assert_ne!(h1, h2);
    }

    #[test]
    fn empty_db_returns_untrusted() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let db = TrustDb::load_from(tmp.path());
        assert_eq!(
            db.check(Path::new("/fake/.rippy"), "content"),
            TrustStatus::Untrusted
        );
    }

    #[test]
    fn trust_then_check_returns_trusted() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut db = TrustDb::load_from(tmp.path());
        let path = tmp.path();
        db.trust(path, "allow git status\n");
        assert_eq!(db.check(path, "allow git status\n"), TrustStatus::Trusted);
    }

    #[test]
    fn modified_content_returns_modified() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut db = TrustDb::load_from(tmp.path());
        let path = tmp.path();
        db.trust(path, "allow git status\n");
        let status = db.check(path, "allow *\n");
        assert!(matches!(status, TrustStatus::Modified { .. }));
    }

    #[test]
    fn revoke_existing_returns_true() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut db = TrustDb::load_from(tmp.path());
        let path = tmp.path();
        db.trust(path, "content");
        assert!(db.revoke(path));
        assert_eq!(db.check(path, "content"), TrustStatus::Untrusted);
    }

    #[test]
    fn revoke_nonexistent_returns_false() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut db = TrustDb::load_from(tmp.path());
        assert!(!db.revoke(Path::new("/nonexistent/.rippy")));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("trusted.json");

        let mut db = TrustDb::load_from(&db_path);
        let config_path = dir.path().join(".rippy");
        std::fs::write(&config_path, "deny rm -rf").unwrap();
        db.trust(&config_path, "deny rm -rf");
        db.save().unwrap();

        let db2 = TrustDb::load_from(&db_path);
        assert_eq!(db2.check(&config_path, "deny rm -rf"), TrustStatus::Trusted);
    }

    #[test]
    fn format_epoch_known_date() {
        // 2024-01-01T00:00:00Z = 1704067200
        let s = format_epoch_secs(1_704_067_200);
        assert_eq!(s, "2024-01-01T00:00:00Z");
    }
}
