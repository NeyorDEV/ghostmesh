//! Session key renewal (rekey).
//!
//! Every peer starts on a base session derived from the two static identities. After
//! `rekey_secs` seconds or `rekey_bytes` sealed bytes, the peer with the lower NodeId proposes a new
//! epoch: both sides exchange ephemeral X25519 keys (sealed under the current keys) and derive new
//! keys that also depend on the static secret. The epoch number travels in the top byte of each
//! packet's sequence number, so packets of the previous epoch still in flight keep decrypting for a
//! short grace period. A peer that does not understand `Rekey` simply never answers and stays on
//! the base session.

use crate::{MeshEngine, PeerState};
use ghost_crypto::{EphemeralKey, SessionKeys};
use ghost_protocol::{NodeId, PacketType};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

pub const DEFAULT_REKEY_SECS: u64 = 600;
pub const DEFAULT_REKEY_BYTES: u64 = 1 << 30;
/// Low 56 bits of the sequence number; the top byte is the epoch.
pub const SEQ_MASK: u64 = (1 << 56) - 1;
/// An unanswered proposal is dropped (and may be repeated) after this long.
const PENDING_TIMEOUT: Duration = Duration::from_secs(20);

fn next_epoch(current: u8) -> u8 {
    match current.wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

impl MeshEngine {
    /// Changes when session keys are renewed (mostly useful for tests).
    pub fn set_rekey_policy(&self, secs: u64, bytes: u64) {
        self.rekey_secs.store(secs.max(1), Ordering::Relaxed);
        self.rekey_bytes.store(bytes.max(1), Ordering::Relaxed);
    }

    /// Starts a rekey with every connected peer whose keys are too old or have carried too much.
    pub(crate) async fn rekey_tick(self: &Arc<Self>) {
        let (max_age, max_bytes) = (
            Duration::from_secs(self.rekey_secs.load(Ordering::Relaxed)),
            self.rekey_bytes.load(Ordering::Relaxed),
        );
        let me = self.node_id();
        let due: Vec<(NodeId, u8)> = {
            let table = self.peers.read().await;
            table
                .iter()
                .filter(|p| p.state == PeerState::Connected && p.session.is_some())
                // Only one side initiates, otherwise both would propose at once.
                .filter(|p| me.0 < p.node_id.0)
                .filter(|p| {
                    p.epoch_since.elapsed() >= max_age
                        || p.tx_bytes
                            .load(Ordering::Relaxed)
                            .saturating_sub(p.tx_bytes_at_epoch)
                            >= max_bytes
                })
                .map(|p| (p.node_id, p.current_epoch()))
                .collect()
        };
        for (node, current) in due {
            let epoch = next_epoch(current);
            let eph = EphemeralKey::generate();
            let mut payload = vec![epoch];
            payload.extend_from_slice(&eph.public);
            {
                let Ok(mut pending) = self.pending_rekeys.lock() else {
                    continue;
                };
                if let Some((_, _, started)) = pending.get(&node) {
                    if started.elapsed() < PENDING_TIMEOUT {
                        continue;
                    }
                }
                pending.insert(node, (epoch, eph, Instant::now()));
            }
            let _ = self.send_packet(node, PacketType::Rekey, &payload).await;
        }
    }

    /// Responder side: answers under the old keys, then switches.
    pub(crate) async fn handle_rekey(
        self: &Arc<Self>,
        src: NodeId,
        plain: &[u8],
        remote: SocketAddr,
        link: &Option<crate::LinkTx>,
    ) {
        if plain.len() != 33 || plain[0] == 0 {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let epoch = plain[0];
        let mut remote_eph = [0u8; 32];
        remote_eph.copy_from_slice(&plain[1..]);

        let (peer_pub, old_keys) = {
            let table = self.peers.read().await;
            let Some(p) = table.get(&src) else { return };
            // Refuse to go back to an epoch we already used (replayed or stale proposal).
            if p.current_epoch() == epoch
                || p.prev_epoch.as_ref().map(|(e, _)| e.epoch) == Some(epoch)
            {
                return;
            }
            let (Some(pk), Some(k)) = (p.public_key, p.send_keys()) else {
                return;
            };
            (pk, k)
        };

        let eph = EphemeralKey::generate();
        let mut ack = vec![epoch];
        ack.extend_from_slice(&eph.public);
        let (old_epoch, old_session) = old_keys;
        let Ok(packet) = self.build_packet_epoch(
            PacketType::RekeyAck,
            src,
            Some(&old_session),
            old_epoch,
            &ack,
        ) else {
            return;
        };
        self.send_to_remote(remote, link, &packet.encode()).await;

        let keys = SessionKeys::derive_epoch(&self.identity, &peer_pub, eph, &remote_eph, epoch);
        let mut table = self.peers.write().await;
        if let Some(p) = table.get_mut(&src) {
            p.install_epoch(epoch, keys);
            info!("Session keys with {src} renewed (epoch {epoch})");
        }
    }

    /// Initiator side: the answer arrived, derive and switch.
    pub(crate) async fn handle_rekey_ack(self: &Arc<Self>, src: NodeId, plain: &[u8]) {
        if plain.len() != 33 {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let epoch = plain[0];
        let mut remote_eph = [0u8; 32];
        remote_eph.copy_from_slice(&plain[1..]);

        let eph = {
            let Ok(mut pending) = self.pending_rekeys.lock() else {
                return;
            };
            match pending.remove(&src) {
                Some((e, eph, _)) if e == epoch => eph,
                Some(other) => {
                    pending.insert(src, other);
                    return;
                }
                None => return,
            }
        };
        let mut table = self.peers.write().await;
        let Some(p) = table.get_mut(&src) else { return };
        let Some(peer_pub) = p.public_key else { return };
        let keys = SessionKeys::derive_epoch(&self.identity, &peer_pub, eph, &remote_eph, epoch);
        p.install_epoch(epoch, keys);
        info!("Session keys with {src} renewed (epoch {epoch})");
    }

    pub(crate) fn spawn_rekey_task(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                engine.rekey_tick().await;
            }
        });
    }
}
