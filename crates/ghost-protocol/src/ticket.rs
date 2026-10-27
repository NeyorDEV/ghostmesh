use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;

use crate::NodeId;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TicketError {
    #[error("Ticket must start with 'gm1_' prefix")]
    InvalidPrefix,
    #[error("Base64 decoding error: {0}")]
    Base64(String),
    #[error("JSON deserialization error: {0}")]
    Json(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteTicket {
    pub node_id: NodeId,
    pub endpoint: SocketAddr,
    #[serde(with = "hex_32")]
    pub public_key: [u8; 32],
    #[serde(default)]
    pub lan_endpoints: Vec<SocketAddr>,
}

impl InviteTicket {
    pub fn new(node_id: NodeId, endpoint: SocketAddr, public_key: [u8; 32]) -> Self {
        Self {
            node_id,
            endpoint,
            public_key,
            lan_endpoints: Vec::new(),
        }
    }

    pub fn with_lan_endpoints(mut self, lan_endpoints: Vec<SocketAddr>) -> Self {
        self.lan_endpoints = lan_endpoints;
        self
    }

    pub fn all_endpoints(&self) -> Vec<SocketAddr> {
        let mut endpoints = Vec::new();
        for &lan in &self.lan_endpoints {
            if !endpoints.contains(&lan) {
                endpoints.push(lan);
            }
        }
        if !endpoints.contains(&self.endpoint) {
            endpoints.push(self.endpoint);
        }
        endpoints
    }

    pub fn to_ticket_string(&self) -> String {
        let json = serde_json::to_vec(self).expect("InviteTicket serialization cannot fail");
        let encoded = URL_SAFE_NO_PAD.encode(json);
        format!("gm1_{encoded}")
    }
}

impl FromStr for InviteTicket {
    type Err = TicketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload = s.trim().strip_prefix("gm1_").ok_or(TicketError::InvalidPrefix)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| TicketError::Base64(e.to_string()))?;
        let ticket: InviteTicket = serde_json::from_slice(&decoded)
            .map_err(|e| TicketError::Json(e.to_string()))?;
        Ok(ticket)
    }
}

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes (64 hex characters), got {}",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_roundtrip() {
        let node_id = NodeId::new([0xAB; 16]);
        let endpoint = "92.171.157.150:4242".parse().unwrap();
        let pub_key = [0x42; 32];

        let ticket = InviteTicket::new(node_id, endpoint, pub_key);
        let ticket_str = ticket.to_ticket_string();

        assert!(ticket_str.starts_with("gm1_"));

        let parsed: InviteTicket = ticket_str.parse().expect("Failed to parse ticket string");
        assert_eq!(parsed, ticket);
        assert_eq!(parsed.all_endpoints(), vec![endpoint]);
    }

    #[test]
    fn test_ticket_with_lan_endpoints() {
        let node_id = NodeId::new([0xCD; 16]);
        let endpoint = "92.171.157.150:4242".parse().unwrap();
        let pub_key = [0x55; 32];
        let lan1 = "127.0.0.1:4242".parse().unwrap();
        let lan2 = "192.168.1.50:4242".parse().unwrap();

        let ticket = InviteTicket::new(node_id, endpoint, pub_key)
            .with_lan_endpoints(vec![lan1, lan2]);
        let ticket_str = ticket.to_ticket_string();
        let parsed: InviteTicket = ticket_str.parse().expect("Failed to parse ticket with lan endpoints");

        assert_eq!(parsed.lan_endpoints, vec![lan1, lan2]);
        assert_eq!(parsed.all_endpoints(), vec![lan1, lan2, endpoint]);
    }
}
