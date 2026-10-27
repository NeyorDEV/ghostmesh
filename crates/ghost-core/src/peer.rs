use ghost_crypto::{IdentityKeypair, ReplayWindow, SessionKeys};
use ghost_protocol::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

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
        }
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
