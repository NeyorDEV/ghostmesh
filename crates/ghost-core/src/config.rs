use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppConfig {
    pub private_key_hex: Option<String>,
    pub public_key_hex: Option<String>,
    pub known_peers: Vec<KnownPeer>,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub allow_exit_node: bool,
    #[serde(default = "default_true")]
    pub auto_clipboard: bool,
    /// Relay servers, tried in order. No relay is configured by default.
    #[serde(default)]
    pub relays: Vec<RelayEndpoint>,
    /// Rendezvous servers (host:port). None by default: the user chooses who sees their address records.
    #[serde(default)]
    pub rendezvous: Vec<String>,
    /// STUN servers (host:port). When empty, built-in public servers are used.
    #[serde(default)]
    pub stun_servers: Vec<String>,
    /// Name of this machine on the mesh (`<name>.ghost`). Defaults to the computer name.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Inner MTU of the virtual interface; the default leaves room for the tunnel headers.
    #[serde(default)]
    pub mtu: Option<u16>,
}

/// A relay server: its address and the hex public key the client pins.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub addr: String,
    pub public_key: String,
}

impl RelayEndpoint {
    pub fn key_bytes(&self) -> Result<[u8; 32], String> {
        let b = hex::decode(self.public_key.trim())
            .map_err(|e| format!("relay key is not hex: {e}"))?;
        b.try_into()
            .map_err(|_| "relay key must be 32 bytes (64 hex characters)".to_string())
    }
}

impl std::str::FromStr for RelayEndpoint {
    type Err = String;

    /// Parses `host:port#<64 hex chars of the relay public key>`.
    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, key) = s
            .trim()
            .split_once('#')
            .ok_or("expected host:port#publickey")?;
        if addr.is_empty() || !addr.contains(':') {
            return Err("relay address must look like host:port".into());
        }
        let ep = Self {
            addr: addr.to_string(),
            public_key: key.to_string(),
        };
        ep.key_bytes()?;
        Ok(ep)
    }
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
    /// Revoked devices are refused, and the revocation is passed on to the other paired devices.
    #[serde(default)]
    pub revoked: bool,
    /// Unix time after which the device is refused (until the date is extended).
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// What this device may reach on this machine through the virtual network.
    #[serde(default)]
    pub access: ghost_tun::filter::AccessPolicy,
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
