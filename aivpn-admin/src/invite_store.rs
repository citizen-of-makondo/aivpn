use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InviteStatus {
    Active,
    Used,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteRecord {
    pub id: String,
    pub code_hash: String,
    pub status: InviteStatus,
    pub created_at: DateTime<Utc>,
    pub used_by_tg_id: Option<i64>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InviteFileData {
    invites: Vec<InviteRecord>,
}

#[derive(Debug, Clone)]
pub struct InviteStore {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub code: String,
    pub record: InviteRecord,
}

impl InviteStore {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        ensure_parent_dir(&path)?;
        if !path.exists() {
            let initial = InviteFileData::default();
            let json = serde_json::to_string_pretty(&initial).map_err(to_io_error)?;
            std::fs::write(&path, json)?;
        }
        Ok(Self { path })
    }

    pub fn list(&self) -> Result<Vec<InviteRecord>, String> {
        self.with_locked_data(false, |data| {
            let mut rows = data.invites.clone();
            rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            Ok(rows)
        })
    }

    pub fn create_invite(&self) -> Result<CreatedInvite, String> {
        self.with_locked_data(true, |data| {
            let id = new_id();
            let code = new_code();
            let record = InviteRecord {
                id: id.clone(),
                code_hash: hash_code(&code),
                status: InviteStatus::Active,
                created_at: Utc::now(),
                used_by_tg_id: None,
                used_at: None,
                revoked_at: None,
            };
            data.invites.push(record.clone());
            Ok(CreatedInvite { code, record })
        })
    }

    pub fn revoke_invite(&self, id: &str) -> Result<InviteRecord, String> {
        self.with_locked_data(true, |data| {
            let now = Utc::now();
            let invite = data
                .invites
                .iter_mut()
                .find(|row| row.id == id)
                .ok_or_else(|| format!("Invite '{id}' not found"))?;

            if invite.status == InviteStatus::Used {
                return Err("Invite already used".to_string());
            }

            invite.status = InviteStatus::Revoked;
            invite.revoked_at = Some(now);
            Ok(invite.clone())
        })
    }

    #[allow(dead_code)]
    pub fn redeem_code(&self, code: &str, tg_user_id: i64) -> Result<InviteRecord, String> {
        let code_hash = hash_code(code.trim());
        self.with_locked_data(true, |data| {
            let now = Utc::now();
            let invite = data
                .invites
                .iter_mut()
                .find(|row| row.code_hash == code_hash)
                .ok_or_else(|| "Invite code is invalid".to_string())?;

            match invite.status {
                InviteStatus::Active => {
                    invite.status = InviteStatus::Used;
                    invite.used_by_tg_id = Some(tg_user_id);
                    invite.used_at = Some(now);
                    Ok(invite.clone())
                }
                InviteStatus::Used => Err("Invite code has already been used".to_string()),
                InviteStatus::Revoked => Err("Invite code has been revoked".to_string()),
            }
        })
    }

    fn with_locked_data<T, F>(&self, write_back: bool, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut InviteFileData) -> Result<T, String>,
    {
        ensure_parent_dir(&self.path).map_err(|e| e.to_string())?;
        let mut file = open_rw_create(&self.path).map_err(|e| e.to_string())?;
        file.lock_exclusive().map_err(|e| e.to_string())?;

        let mut data = read_data(&mut file).map_err(|e| e.to_string())?;
        let result = f(&mut data);

        if write_back && result.is_ok() {
            write_data_atomic(&self.path, &data).map_err(|e| e.to_string())?;
        }

        // lock released on drop
        result
    }
}

fn open_rw_create(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

fn read_data(file: &mut File) -> std::io::Result<InviteFileData> {
    file.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    if content.trim().is_empty() {
        return Ok(InviteFileData::default());
    }
    serde_json::from_str::<InviteFileData>(&content).map_err(to_io_error)
}

fn write_data_atomic(path: &Path, data: &InviteFileData) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "path has no parent"))?;
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("invites"),
        std::process::id()
    );
    let tmp_path = parent.join(tmp_name);

    let json = serde_json::to_string_pretty(data).map_err(to_io_error)?;
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn to_io_error<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

fn new_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn new_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut groups = Vec::with_capacity(4);
    for _ in 0..4 {
        let mut group = String::with_capacity(4);
        for _ in 0..4 {
            let idx = rng.gen_range(0..ALPHABET.len());
            group.push(ALPHABET[idx] as char);
        }
        groups.push(group);
    }
    groups.join("-")
}

pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "aivpn-admin-{}-{}-{}",
            name,
            std::process::id(),
            rand::thread_rng().gen_range(10000..99999)
        );
        path.push(unique);
        path
    }

    #[test]
    fn redeem_is_single_use_under_race() {
        let path = temp_path("invites");
        let store = Arc::new(InviteStore::new(path.clone()).expect("store init"));

        let created = store.create_invite().expect("create invite");
        let code = created.code.clone();

        let mut handles = Vec::new();
        for i in 0..16 {
            let store = Arc::clone(&store);
            let code = code.clone();
            handles.push(std::thread::spawn(move || store.redeem_code(&code, 1000 + i as i64).is_ok()));
        }

        let successes = handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .filter(|ok| *ok)
            .count();

        assert_eq!(successes, 1, "only one concurrent redeem must succeed");

        let rows = store.list().expect("list invites");
        let row = rows
            .into_iter()
            .find(|v| v.id == created.record.id)
            .expect("created invite must exist");
        assert_eq!(row.status, InviteStatus::Used);
        assert!(row.used_at.is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn revoke_then_redeem_fails() {
        let path = temp_path("invites");
        let store = InviteStore::new(path.clone()).expect("store init");

        let created = store.create_invite().expect("create invite");
        store
            .revoke_invite(&created.record.id)
            .expect("revoke invite");

        let result = store.redeem_code(&created.code, 42);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Invite code has been revoked");

        let _ = std::fs::remove_file(path);
    }
}
