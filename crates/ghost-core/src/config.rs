use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppConfig {
    pub private_key_hex: Option<String>,
    pub public_key_hex: Option<String>,
    pub known_peers: Vec<KnownPeer>,
    #[serde(default)]
    pub autostart: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KnownPeer {
    pub alias: String,
    pub node_id: String,
    pub endpoint: String,
    pub last_seen: String,
    #[serde(default = "default_true")]
    pub allow_rdp: bool,
    #[serde(default = "default_true")]
    pub allow_ghostdrop: bool,
    #[serde(default)]
    pub temporary_session: bool,
}

pub fn get_config_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = PathBuf::from(appdata).join("GhostMesh");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("config.json")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        let dir = PathBuf::from(home).join(".ghostmesh");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("config.json")
    } else {
        PathBuf::from("ghostmesh-config.json")
    }
}

pub fn load_config() -> AppConfig {
    let path = get_config_path();
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str(&data) {
                return cfg;
            }
        }
    }
    AppConfig::default()
}

pub fn save_config(config: &AppConfig) -> Result<(), String> {
    let path = get_config_path();
    let json = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(())
}
