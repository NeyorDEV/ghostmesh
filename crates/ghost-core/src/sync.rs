use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncStatus {
    pub is_active: bool,
    pub watched_dir: Option<String>,
    pub file_count: usize,
    pub last_sync_secs_ago: Option<u64>,
    pub status_message: String,
}

#[derive(Clone)]
pub struct GhostSyncEngine {
    pub watched_dir: Arc<RwLock<Option<PathBuf>>>,
    pub file_manifest: Arc<RwLock<HashMap<String, u64>>>,
    pub last_sync: Arc<RwLock<Option<Instant>>>,
    pub is_active: Arc<RwLock<bool>>,
}

impl GhostSyncEngine {
    pub fn new() -> Self {
        Self {
            watched_dir: Arc::new(RwLock::new(None)),
            file_manifest: Arc::new(RwLock::new(HashMap::new())),
            last_sync: Arc::new(RwLock::new(None)),
            is_active: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn set_watched_directory(&self, path_str: &str) -> Result<(), String> {
        let p = PathBuf::from(path_str);
        if !p.exists() {
            tokio::fs::create_dir_all(&p)
                .await
                .map_err(|e| format!("Cannot create sync folder: {e}"))?;
        }

        {
            let mut guard = self.watched_dir.write().await;
            *guard = Some(p);
        }
        {
            let mut active = self.is_active.write().await;
            *active = true;
        }

        info!("GhostSync directory set to: {path_str}");
        Ok(())
    }

    pub async fn get_status(&self) -> SyncStatus {
        let is_act = *self.is_active.read().await;
        let dir = self.watched_dir.read().await.as_ref().map(|p| p.to_string_lossy().to_string());
        let count = self.file_manifest.read().await.len();
        let last = self.last_sync.read().await.as_ref().map(|t| t.elapsed().as_secs());

        let msg = if is_act {
            if let Some(ref d) = dir {
                format!("Watching {} ({} files tracked)", d, count)
            } else {
                "Idle - No directory configured".into()
            }
        } else {
            "Paused".into()
        };

        SyncStatus {
            is_active: is_act,
            watched_dir: dir,
            file_count: count,
            last_sync_secs_ago: last,
            status_message: msg,
        }
    }

    pub async fn scan_and_detect_changes(&self) -> Vec<PathBuf> {
        let dir = {
            let guard = self.watched_dir.read().await;
            guard.clone()
        };

        let mut changed_files = Vec::new();
        if let Some(root) = dir {
            let mut manifest = self.file_manifest.write().await;
            let mut entries = match tokio::fs::read_dir(&root).await {
                Ok(rd) => rd,
                Err(_) => return changed_files,
            };

            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(meta) = entry.metadata().await {
                    if meta.is_file() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let size = meta.len();
                        let prev_size = manifest.insert(name.clone(), size);
                        if prev_size != Some(size) {
                            changed_files.push(entry.path());
                        }
                    }
                }
            }

            if !changed_files.is_empty() {
                let mut last = self.last_sync.write().await;
                *last = Some(Instant::now());
            }
        }

        changed_files
    }
}
