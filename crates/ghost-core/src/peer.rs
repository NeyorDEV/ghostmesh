use ghost_protocol::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    Punching,
    Connected,
    Relayed,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Punching => write!(f, "Punching NAT"),
            Self::Connected => write!(f, "Connected (Direct P2P)"),
            Self::Relayed => write!(f, "Relayed"),
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
        }
    }

    pub fn with_public_key(mut self, key: [u8; 32]) -> Self {
        self.public_key = Some(key);
        self
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

    pub fn get(&self, node_id: &NodeId) -> Option<&Peer> {
        self.peers.get(node_id)
    }

    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut Peer> {
        self.peers.get_mut(node_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}
