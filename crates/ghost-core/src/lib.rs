pub mod peer;

pub use peer::{Peer, PeerState, PeerTable};

use ghost_crypto::IdentityKeypair;
use ghost_nat::DEFAULT_STUN_SERVER;
use ghost_protocol::{NodeId, Packet, PacketType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("NAT / STUN error: {0}")]
    Nat(#[from] ghost_nat::NatError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ghost_protocol::ProtocolError),
}

pub struct MeshEngine {
    pub identity: IdentityKeypair,
    pub socket: Arc<UdpSocket>,
    pub public_addr: SocketAddr,
    pub peers: Arc<RwLock<PeerTable>>,
}

impl MeshEngine {
    pub async fn bind(local_port: u16) -> Result<Self, EngineError> {
        let identity = IdentityKeypair::generate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let socket = UdpSocket::bind(format!("0.0.0.0:{local_port}")).await?;
        let socket = Arc::new(socket);

        info!("Local UDP socket bound on port {local_port}");

        let public_addr = match ghost_nat::discover_public_endpoint(
            &socket,
            DEFAULT_STUN_SERVER,
            Duration::from_secs(3),
        )
        .await
        {
            Ok(addr) => {
                info!("Public endpoint discovered via STUN: {addr}");
                addr
            }
            Err(e) => {
                warn!("STUN discovery failed ({e}), falling back to local socket addr");
                socket.local_addr()?
            }
        };

        let peers = Arc::new(RwLock::new(PeerTable::new()));

        Ok(Self {
            identity,
            socket,
            public_addr,
            peers,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub async fn add_peer(&self, node_id: NodeId, endpoint: SocketAddr) {
        let mut table = self.peers.write().await;
        table.insert(Peer::new(node_id, endpoint));
        info!("Added peer {node_id} at {endpoint}");
    }

    pub async fn send_packet(
        &self,
        dest_node: NodeId,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Result<(), EngineError> {
        let endpoint = {
            let table = self.peers.read().await;
            table.get(&dest_node).map(|p| p.endpoint)
        };

        if let Some(target_addr) = endpoint {
            let packet = Packet::new(
                packet_type,
                self.node_id(),
                dest_node,
                1,
                payload.to_vec(),
            );
            let encoded = packet.encode();
            self.socket.send_to(&encoded, target_addr).await?;
        } else {
            warn!("Peer {dest_node} not found in peer table");
        }

        Ok(())
    }

    pub async fn run_receive_loop(self: Arc<Self>) {
        let mut buf = [0u8; 65535];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, remote_addr)) => {
                    let raw = &buf[..len];
                    match Packet::decode(raw) {
                        Ok(packet) => {
                            info!(
                                "Received packet {:?} from {} (NodeId: {})",
                                packet.packet_type, remote_addr, packet.src_node
                            );
                            // Update or discover peer
                            let mut table = self.peers.write().await;
                            if let Some(peer) = table.get_mut(&packet.src_node) {
                                peer.endpoint = remote_addr;
                                peer.state = PeerState::Connected;
                            }
                        }
                        Err(e) => {
                            warn!("Malformed packet from {remote_addr}: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!("Socket recv error: {e}");
                    break;
                }
            }
        }
    }
}
