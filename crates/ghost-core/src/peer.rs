use ghost_crypto::{IdentityKeypair, ReplayWindow, SessionKeys};
use ghost_protocol::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Keys of one rekey epoch (epoch 0 is the base session derived from the static identities).
#[derive(Debug, Clone)]
pub struct EpochKeys {
    pub epoch: u8,
    pub keys: Arc<SessionKeys>,
    pub replay: ReplayWindow,
}

/// How long the previous epoch keeps decrypting after a switch (packets still in flight).
pub const EPOCH_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a direct UDP packet keeps the direct path considered alive.
pub const DIRECT_FRESH: std::time::Duration = std::time::Duration::from_secs(25);

/// Outbound side of a TCP fallback link (length-prefixed packets handled by the engine).
pub type LinkTx = mpsc::Sender<Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    Punching,
    Connected,
    Relayed,
    /// Handshake attempts (UDP and TCP fallback) all went unanswered.
    Unreachable,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Punching => write!(f, "Punching NAT"),
            Self::Connected => write!(f, "Connected (Direct P2P)"),
            Self::Relayed => write!(f, "Relayed"),
            Self::Unreachable => write!(f, "Unreachable (no reply)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub node_id: NodeId,
    pub endpoint: SocketAddr,
    pub public_key: Option<[u8; 32]>,
    pub state: PeerState,
    pub last_seen: Instant,
    pub rtt_ms: Option<u32>,
    /// Packet protection keys, available once the peer's public key is known.
    pub session: Option<Arc<SessionKeys>>,
    pub replay: ReplayWindow,
    /// Set while the peer is reached through the TCP fallback instead of UDP.
    pub tcp: Option<LinkTx>,
    pub last_udp: Option<Instant>,
    /// Last authenticated packet that came through a relay.
    pub relay_seen: Option<Instant>,
    /// Current rekeyed session (None while the base session is in use).
    pub epoch: Option<EpochKeys>,
    pub prev_epoch: Option<(EpochKeys, Instant)>,
    pub epoch_since: Instant,
    /// Bytes sealed for this peer, and the counter value when the current epoch started.
    pub tx_bytes: Arc<std::sync::atomic::AtomicU64>,
    pub tx_bytes_at_epoch: u64,
}

impl Peer {
    pub fn new(node_id: NodeId, endpoint: SocketAddr) -> Self {
        Self {
            node_id,
            endpoint,
            public_key: None,
            state: PeerState::Disconnected,
            last_seen: Instant::now(),
            rtt_ms: None,
            session: None,
            replay: ReplayWindow::default(),
            tcp: None,
            last_udp: None,
            relay_seen: None,
            epoch: None,
            prev_epoch: None,
            epoch_since: Instant::now(),
            tx_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            tx_bytes_at_epoch: 0,
        }
    }

    /// A direct UDP packet arrived recently, so traffic can skip the relay.
    pub fn is_direct(&self) -> bool {
        self.last_udp
            .map(|t| t.elapsed() < DIRECT_FRESH)
            .unwrap_or(false)
    }

    /// Epoch number and keys to seal outgoing packets with.
    pub fn send_keys(&self) -> Option<(u8, Arc<SessionKeys>)> {
        match &self.epoch {
            Some(e) => Some((e.epoch, Arc::clone(&e.keys))),
            None => self.session.as_ref().map(|s| (0, Arc::clone(s))),
        }
    }

    /// Keys able to open a packet sealed in `epoch`, if that epoch is still accepted.
    pub fn keys_for_epoch(&self, epoch: u8) -> Option<Arc<SessionKeys>> {
        if epoch == 0 {
            return self.session.clone();
        }
        if let Some(e) = self.epoch.as_ref().filter(|e| e.epoch == epoch) {
            return Some(Arc::clone(&e.keys));
        }
        match &self.prev_epoch {
            Some((e, at)) if e.epoch == epoch && at.elapsed() < EPOCH_GRACE => {
                Some(Arc::clone(&e.keys))
            }
            _ => None,
        }
    }

    /// Anti-replay check in the window that belongs to `epoch`.
    pub fn accept_seq(&mut self, epoch: u8, seq: u64) -> bool {
        if epoch == 0 {
            return self.replay.accept(seq);
        }
        if let Some(e) = self.epoch.as_mut().filter(|e| e.epoch == epoch) {
            return e.replay.accept(seq);
        }
        match &mut self.prev_epoch {
            Some((e, _)) if e.epoch == epoch => e.replay.accept(seq),
            _ => false,
        }
    }

    /// Makes `keys` the current epoch; the old one keeps working briefly.
    pub fn install_epoch(&mut self, epoch: u8, keys: SessionKeys) {
        if let Some(old) = self.epoch.take() {
            self.prev_epoch = Some((old, Instant::now()));
        }
        self.epoch = Some(EpochKeys {
            epoch,
            keys: Arc::new(keys),
            replay: ReplayWindow::default(),
        });
        self.epoch_since = Instant::now();
        self.tx_bytes_at_epoch = self.tx_bytes.load(std::sync::atomic::Ordering::Relaxed);
    }

    pub fn current_epoch(&self) -> u8 {
        self.epoch.as_ref().map(|e| e.epoch).unwrap_or(0)
    }

    pub fn with_public_key(mut self, key: [u8; 32]) -> Self {
        self.public_key = Some(key);
        self
    }

    /// Stores the peer's public key and derives the packet protection keys from it.
    pub fn set_public_key(&mut self, local: &IdentityKeypair, key: [u8; 32]) {
        self.public_key = Some(key);
        self.session = Some(Arc::new(SessionKeys::derive(local, &key)));
    }
}

#[derive(Debug, Default)]
pub struct PeerTable {
    peers: HashMap<NodeId, Peer>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn insert(&mut self, peer: Peer) {
        self.peers.insert(peer.node_id, peer);
    }

    pub fn remove(&mut self, node_id: &NodeId) -> Option<Peer> {
        self.peers.remove(node_id)
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&Peer> {
        self.peers.get(node_id)
    }

    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut Peer> {
        self.peers.get_mut(node_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Peer> {
        self.peers.values_mut()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}
