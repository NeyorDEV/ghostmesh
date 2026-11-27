//! Network access control per peer: glue between the saved policies and the TUN packet paths.

use crate::{load_config, save_config, MeshEngine};
use ghost_protocol::NodeId;
use ghost_tun::filter::{parse_packet, AccessPolicy, Dir, PeerFilter, Verdict};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use tracing::{info, warn};

#[derive(Default)]
pub struct AccessControl {
    peers: Mutex<HashMap<NodeId, PeerFilter>>,
    pub allowed_in: AtomicU64,
    pub denied_in: AtomicU64,
    pub denied_out: AtomicU64,
    pub spoofed_in: AtomicU64,
}

/// A packet whose source IP belongs to another device than the one that sent it is a forgery,
/// unless the sender is our exit node (which legitimately carries packets from the Internet).
pub fn is_spoofed(
    owner_of_source_ip: Option<NodeId>,
    sender: NodeId,
    sender_is_exit_node: bool,
) -> bool {
    !sender_is_exit_node && owner_of_source_ip != Some(sender)
}

impl AccessControl {
    pub fn set_policy(&self, node: NodeId, policy: AccessPolicy) {
        if let Ok(mut m) = self.peers.lock() {
            // Keep the learned flows when only the policy is re-applied unchanged.
            if m.get(&node).map(|f| f.policy() == &policy).unwrap_or(false) {
                return;
            }
            m.insert(node, PeerFilter::new(policy));
        }
    }

    pub fn policy(&self, node: &NodeId) -> AccessPolicy {
        self.peers
            .lock()
            .ok()
            .and_then(|m| m.get(node).map(|f| f.policy().clone()))
            .unwrap_or_default()
    }

    pub fn is_unrestricted(&self, node: &NodeId) -> bool {
        self.peers
            .lock()
            .map(|m| m.get(node).map(|f| f.is_unrestricted()).unwrap_or(true))
            .unwrap_or(false)
    }

    pub fn check(&self, node: &NodeId, dir: Dir, packet: &[u8]) -> Verdict {
        let Ok(mut m) = self.peers.lock() else {
            return Verdict::Deny(ghost_tun::filter::DenyReason::NoRule);
        };
        match m.get_mut(node) {
            Some(f) => f.check(dir, packet, Instant::now()),
            None => Verdict::Allow,
        }
    }
}

impl MeshEngine {
    /// Applies the policies saved in the config (called at start-up and periodically).
    pub fn reload_access(&self) {
        if self.is_ephemeral {
            return;
        }
        for k in load_config().known_peers {
            if let Ok(node) = k.node_id.parse::<NodeId>() {
                self.access.set_policy(node, k.access);
            }
        }
    }

    /// Changes and saves the policy of a paired device.
    pub fn set_peer_access(&self, node: NodeId, policy: AccessPolicy) -> Result<(), String> {
        self.access.set_policy(node, policy.clone());
        if self.is_ephemeral {
            return Ok(());
        }
        let mut cfg = load_config();
        let id = node.to_string();
        let Some(k) = cfg.known_peers.iter_mut().find(|k| k.node_id == id) else {
            return Err("unknown device".into());
        };
        k.access = policy;
        save_config(&cfg)?;
        info!("Access policy of {node} updated");
        Ok(())
    }

    /// Filter for an IP packet that a peer sent us, before it is written to the TUN device.
    pub(crate) async fn admit_inbound_ip(&self, from: NodeId, packet: &[u8]) -> bool {
        if self.access.is_unrestricted(&from) {
            return true;
        }
        if let Ok(parsed) = parse_packet(packet) {
            let owner = {
                let guard = self.adapter.read().await;
                match guard.as_ref() {
                    Some(a) => {
                        let routes = a.routes.read().await;
                        Some(match parsed.flow.src {
                            std::net::IpAddr::V4(v4) => routes.get_node_by_ip(&v4),
                            std::net::IpAddr::V6(v6) => routes.get_node_by_ip6(&v6),
                        })
                    }
                    None => None,
                }
            };
            if let Some(owner) = owner {
                let is_exit = self.active_exit_node.read().await.as_deref()
                    == Some(from.to_string().as_str());
                if is_spoofed(owner, from, is_exit) {
                    self.access.spoofed_in.fetch_add(1, Ordering::Relaxed);
                    warn!("Dropped packet from {from} with a source address that is not theirs");
                    return false;
                }
            }
        }
        match self.access.check(&from, Dir::In, packet) {
            Verdict::Allow => {
                self.access.allowed_in.fetch_add(1, Ordering::Relaxed);
                true
            }
            Verdict::Deny(_) => {
                self.access.denied_in.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Filter for an IP packet from a local program, before it is sent to `to`.
    pub(crate) fn admit_outbound_ip(&self, to: NodeId, packet: &[u8]) -> bool {
        match self.access.check(&to, Dir::Out, packet) {
            Verdict::Allow => true,
            Verdict::Deny(_) => {
                self.access.denied_out.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spoof_rule() {
        let a = NodeId::new([1; 16]);
        let b = NodeId::new([2; 16]);
        assert!(!is_spoofed(Some(a), a, false));
        assert!(is_spoofed(Some(b), a, false), "source IP of another device");
        assert!(is_spoofed(None, a, false), "source IP nobody owns");
        assert!(
            !is_spoofed(None, a, true),
            "exit node may carry any source address"
        );
    }
}
