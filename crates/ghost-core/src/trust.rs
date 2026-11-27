//! Device trust: revocation (propagated to the other paired devices) and expiry.
//!
//! A revoked or expired NodeId is put in the engine's block list: its packets are dropped before
//! any processing and it is removed from the peer table. Revocation notices are sealed packets, so
//! only an authenticated paired device can send one. A compromised paired device could therefore
//! revoke others (see SECURITY.md); there is no team/admin model in a personal mesh.

use crate::{load_config, save_config, KnownPeer, MeshEngine, PeerState};
use ghost_protocol::{NodeId, PacketType};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl MeshEngine {
    /// Recomputes the block list from the saved devices (revoked, or past their expiry) and drops
    /// the corresponding peers. Ephemeral engines keep only in-memory revocations.
    pub async fn refresh_blocklist(&self) {
        if self.is_ephemeral {
            return;
        }
        let now = unix_secs();
        let known = load_config().known_peers;
        let parse = |k: &KnownPeer| k.node_id.parse::<NodeId>().ok();
        let revoked: Vec<NodeId> = known
            .iter()
            .filter(|k| k.revoked)
            .filter_map(parse)
            .collect();
        let expired: Vec<NodeId> = known
            .iter()
            .filter(|k| !k.revoked && k.expires_at.map(|t| t <= now).unwrap_or(false))
            .filter_map(parse)
            .collect();

        // Expiry can be extended, so the set is rebuilt from the config instead of only growing.
        let newly_revoked: Vec<NodeId> = {
            let mut blocked = self.blocked.write().await;
            let fresh = revoked
                .iter()
                .filter(|n| !blocked.contains(n))
                .copied()
                .collect();
            *blocked = revoked.iter().chain(expired.iter()).copied().collect();
            fresh
        };
        {
            let mut table = self.peers.write().await;
            for n in revoked.iter().chain(expired.iter()) {
                table.remove(n);
            }
        }
        // A revocation made from another process (the CLI) is announced by the running node.
        for node in newly_revoked {
            self.announce_revocation(node).await;
        }
    }

    async fn announce_revocation(&self, node: NodeId) {
        let others: Vec<NodeId> = {
            let table = self.peers.read().await;
            table
                .iter()
                .filter(|p| p.node_id != node && p.state == PeerState::Connected)
                .map(|p| p.node_id)
                .collect()
        };
        let mut notice = node.as_bytes().to_vec();
        notice.extend_from_slice(&unix_secs().to_be_bytes());
        for other in others {
            let _ = self.send_packet(other, PacketType::Revoke, &notice).await;
        }
    }

    pub async fn is_blocked(&self, node: &NodeId) -> bool {
        self.blocked.read().await.contains(node)
    }

    /// Revokes a device: blocks it here, remembers it, and tells every connected peer to do the same.
    pub async fn revoke_peer(&self, node: NodeId) {
        self.blocked.write().await.insert(node);
        if !self.is_ephemeral {
            let mut cfg = load_config();
            let id = node.to_string();
            match cfg.known_peers.iter_mut().find(|k| k.node_id == id) {
                Some(k) => k.revoked = true,
                None => cfg.known_peers.push(KnownPeer {
                    alias: format!("Revoked-{}", &id[..6]),
                    node_id: id,
                    endpoint: "0.0.0.0:0".into(),
                    last_seen: "Revoked".into(),
                    allow_rdp: false,
                    allow_ghostdrop: false,
                    temporary_session: false,
                    revoked: true,
                    expires_at: None,
                    access: Default::default(),
                }),
            }
            if let Err(e) = save_config(&cfg) {
                warn!("Could not save revocation: {e}");
            }
        }

        // Tell the others before the revoked peer leaves the table.
        self.announce_revocation(node).await;
        self.peers.write().await.remove(&node);
        info!("Device {node} revoked");
    }

    /// Gives a saved device a lifetime; after it, the device is refused until the date is extended.
    pub async fn set_device_expiry(&self, node: NodeId, in_hours: Option<u64>) -> bool {
        if self.is_ephemeral {
            return false;
        }
        let mut cfg = load_config();
        let id = node.to_string();
        let Some(k) = cfg.known_peers.iter_mut().find(|k| k.node_id == id) else {
            return false;
        };
        k.expires_at = in_hours.map(|h| unix_secs() + h * 3600);
        let saved = save_config(&cfg).is_ok();
        self.refresh_blocklist().await;
        saved
    }

    /// A paired device announced that `target` was revoked.
    pub(crate) async fn handle_revoke(self: &Arc<Self>, from: NodeId, plain: &[u8]) {
        if plain.len() != 24 {
            self.diag
                .rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&plain[..16]);
        let target = NodeId::new(id);
        // Nobody can revoke us or the device that is telling us.
        if target == self.node_id() || target == from {
            return;
        }
        info!("Device {target} revoked on the advice of {from}");
        self.revoke_peer_local(target).await;
    }

    /// Same as `revoke_peer` without forwarding the notice again (avoids notice loops).
    async fn revoke_peer_local(&self, node: NodeId) {
        self.blocked.write().await.insert(node);
        if !self.is_ephemeral {
            let mut cfg = load_config();
            let id = node.to_string();
            if let Some(k) = cfg.known_peers.iter_mut().find(|k| k.node_id == id) {
                k.revoked = true;
                let _ = save_config(&cfg);
            }
        }
        self.peers.write().await.remove(&node);
    }

    pub(crate) fn spawn_trust_task(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                engine.refresh_blocklist().await;
                engine.reload_access();
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }
}
