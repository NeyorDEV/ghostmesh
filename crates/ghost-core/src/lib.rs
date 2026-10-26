pub mod config;
pub mod peer;
pub mod relay;
pub mod sync;

use serde::{Deserialize, Serialize};

pub use config::{load_config, save_config, AppConfig, KnownPeer};
pub use peer::{Peer, PeerState, PeerTable};
pub use relay::RelayClient;
pub use sync::{GhostSyncEngine, SyncStatus};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PendingConnectionRequest {
    pub node_id: String,
    pub endpoint: String,
}

use ghost_crypto::IdentityKeypair;
use ghost_nat::DEFAULT_STUN_SERVER;
use ghost_protocol::{InviteTicket, NodeId, Packet, PacketType};
use ghost_tun::{Ipv4Header, VirtualAdapter};

use std::net::{Ipv4Addr, SocketAddr};
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
    #[error("TUN error: {0}")]
    Tun(#[from] ghost_tun::TunError),
}

pub struct MeshEngine {
    pub identity: IdentityKeypair,
    pub socket: Arc<UdpSocket>,
    pub public_addr: SocketAddr,
    pub peers: Arc<RwLock<PeerTable>>,
    pub adapter: Arc<RwLock<Option<Arc<VirtualAdapter>>>>,
    pub relay: Arc<RwLock<Option<RelayClient>>>,
    pub sync: Arc<GhostSyncEngine>,
    pub pending_request: Arc<RwLock<Option<PendingConnectionRequest>>>,
    pub chat_messages: Arc<RwLock<Vec<ChatMessageEntry>>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessageEntry {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub text: String,
    pub timestamp_secs: u64,
}

impl MeshEngine {
    pub async fn bind(local_port: u16) -> Result<Self, EngineError> {
        let mut cfg = load_config();
        let identity = if let (Some(priv_hex), Some(pub_hex)) = (&cfg.private_key_hex, &cfg.public_key_hex) {
            if let (Ok(priv_b), Ok(pub_b)) = (hex::decode(priv_hex), hex::decode(pub_hex)) {
                if priv_b.len() == 32 && pub_b.len() == 32 {
                    let mut priv_arr = [0u8; 32];
                    let mut pub_arr = [0u8; 32];
                    priv_arr.copy_from_slice(&priv_b);
                    pub_arr.copy_from_slice(&pub_b);
                    info!("Loaded persistent cryptographic identity: NodeId {}", hex::encode(&pub_arr[..16]));
                    IdentityKeypair::from_key_bytes(priv_arr, pub_arr)
                } else {
                    let gen = IdentityKeypair::generate()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                    cfg.private_key_hex = Some(hex::encode(gen.private));
                    cfg.public_key_hex = Some(hex::encode(gen.public));
                    let _ = save_config(&cfg);
                    gen
                }
            } else {
                let gen = IdentityKeypair::generate()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                cfg.private_key_hex = Some(hex::encode(gen.private));
                cfg.public_key_hex = Some(hex::encode(gen.public));
                let _ = save_config(&cfg);
                gen
            }
        } else {
            let gen = IdentityKeypair::generate()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            cfg.private_key_hex = Some(hex::encode(gen.private));
            cfg.public_key_hex = Some(hex::encode(gen.public));
            let _ = save_config(&cfg);
            gen
        };

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
        let adapter = Arc::new(RwLock::new(None));
        let relay = Arc::new(RwLock::new(None));
        let sync = Arc::new(GhostSyncEngine::new());
        let pending_request = Arc::new(RwLock::new(None));

        // Automatically attempt UPnP port mapping on domestic router in background
        if local_port > 0 {
            tokio::spawn(async move {
                match ghost_nat::forward_port_upnp(local_port, local_port).await {
                    Ok(_) => info!("UPnP: UDP port {local_port} automatically mapped on router"),
                    Err(e) => warn!("UPnP mapping skipped or unavailable: {e}"),
                }
            });
        }

        let chat_messages = Arc::new(RwLock::new(Vec::new()));

        Ok(Self {
            identity,
            socket,
            public_addr,
            peers,
            adapter,
            relay,
            sync,
            pending_request,
            chat_messages,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn create_invite(&self) -> InviteTicket {
        InviteTicket::new(self.node_id(), self.public_addr, self.identity.public)
    }

    pub async fn add_peer(&self, node_id: NodeId, endpoint: SocketAddr) {
        let mut table = self.peers.write().await;
        table.insert(Peer::new(node_id, endpoint));
        info!("Added peer {node_id} at {endpoint}");
    }

    pub async fn enable_virtual_interface(
        self: &Arc<Self>,
        virtual_ip: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<Arc<VirtualAdapter>, EngineError> {
        let adapter = Arc::new(VirtualAdapter::create("ghost0", virtual_ip, netmask)?);
        {
            let mut guard = self.adapter.write().await;
            *guard = Some(Arc::clone(&adapter));
        }

        // Spawn TUN reader loop
        let engine = Arc::clone(self);
        let adapter_read = Arc::clone(&adapter);
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match adapter_read.read_packet(&mut buf).await {
                    Ok(len) => {
                        let packet_bytes = &buf[..len];
                        match Ipv4Header::parse(packet_bytes) {
                            Ok(header) => {
                                let target_node = {
                                    let routes = adapter_read.routes.read().await;
                                    routes.get_node_by_ip(&header.dest)
                                };

                                if let Some(dest_node) = target_node {
                                    let _ = engine
                                        .send_packet(dest_node, PacketType::Data, packet_bytes)
                                        .await;
                                }
                            }
                            Err(_) => {
                                // Ignore non-IPv4 or malformed packets from OS
                            }
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {e}");
                        break;
                    }
                }
            }
        });

        Ok(adapter)
    }

    pub async fn map_peer_virtual_ip(&self, node_id: NodeId, virtual_ip: Ipv4Addr) {
        let guard = self.adapter.read().await;
        if let Some(adapter) = guard.as_ref() {
            let mut routes = adapter.routes.write().await;
            routes.insert(virtual_ip, node_id);
            info!("Mapped peer {node_id} to virtual mesh IP {virtual_ip}");
        }
    }

    pub async fn join_ticket(self: &Arc<Self>, ticket: InviteTicket) -> Result<(), EngineError> {
        let peer = Peer::new(ticket.node_id, ticket.endpoint)
            .with_public_key(ticket.public_key);
        {
            let mut table = self.peers.write().await;
            table.insert(peer);
        }

        info!("Starting UDP hole-punching towards {} (NodeId: {})...", ticket.endpoint, ticket.node_id);

        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut attempts = 0;
            while attempts < 20 {
                let is_connected = {
                    let table = engine.peers.read().await;
                    table.get(&ticket.node_id).map(|p| p.state == PeerState::Connected).unwrap_or(false)
                };

                if is_connected {
                    info!("Hole punching complete, peer {} is connected!", ticket.node_id);
                    break;
                }

                let _ = engine
                    .send_packet(ticket.node_id, PacketType::HandshakeInit, engine.identity.public.as_slice())
                    .await;

                attempts += 1;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });

        Ok(())
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

            if target_addr.ip().is_unspecified() {
                // Outbound UDP blocked or 0.0.0.0: route via TCP/HTTPS fallback relay
                let guard = self.relay.read().await;
                if let Some(relay_client) = guard.as_ref() {
                    let _ = relay_client.send_relayed_packet(&packet).await;
                } else {
                    warn!("Target peer has unspecified endpoint and no relay client is configured");
                }
            } else {
                self.socket.send_to(&encoded, target_addr).await?;
            }
        } else {
            warn!("Peer {dest_node} not found in peer table");
        }

        Ok(())
    }

    pub async fn send_chat_message(&self, dest_node: NodeId, text: &str) -> Result<(), EngineError> {
        self.send_packet(dest_node, PacketType::ChatMessage, text.as_bytes()).await?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut chat_guard = self.chat_messages.write().await;
        chat_guard.push(ChatMessageEntry {
            id: format!("{}-{}", self.node_id(), ts),
            sender: self.node_id().to_string(),
            recipient: dest_node.to_string(),
            text: text.to_string(),
            timestamp_secs: ts,
        });
        Ok(())
    }

    pub async fn start_background_tasks(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let peers_to_ping: Vec<(NodeId, SocketAddr)> = {
                    let table = engine.peers.read().await;
                    table
                        .iter()
                        .filter(|p| p.state == PeerState::Connected)
                        .map(|p| (p.node_id, p.endpoint))
                        .collect()
                };

                for (node_id, _) in peers_to_ping {
                    let _ = engine.send_packet(node_id, PacketType::KeepAlive, b"PING").await;
                }
            }
        });
    }

    pub async fn run_receive_loop(self: Arc<Self>) {
        let mut buf = [0u8; 65535];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, remote_addr)) => {
                    let raw = &buf[..len];
                    match Packet::decode(raw) {
                        Ok(packet) => {
                            // Multi-hop Mesh Routing: Forward packet if not destined for this node
                            if packet.dest_node != self.node_id() {
                                let table = self.peers.read().await;
                                if let Some(target_peer) = table.get(&packet.dest_node) {
                                    if target_peer.state == PeerState::Connected {
                                        info!(
                                            "Mesh Forwarder: routing packet (type {:?}) from {} towards {}",
                                            packet.packet_type, packet.src_node, packet.dest_node
                                        );
                                        let encoded = packet.encode();
                                        let _ = self.socket.send_to(&encoded, target_peer.endpoint).await;
                                        continue;
                                    }
                                }
                            }

                            let mut table = self.peers.write().await;
                            match packet.packet_type {
                                PacketType::HandshakeInit => {
                                    info!(
                                        "Received HandshakeInit from {} at {}",
                                        packet.src_node, remote_addr
                                    );
                                    let peer = table.get_mut(&packet.src_node);
                                    if let Some(p) = peer {
                                        p.endpoint = remote_addr;
                                        p.state = PeerState::Connected;
                                        p.last_seen = std::time::Instant::now();
                                    } else {
                                        let mut new_peer = Peer::new(packet.src_node, remote_addr);
                                        new_peer.state = PeerState::Connected;
                                        table.insert(new_peer);
                                    }

                                    drop(table);
                                    let _ = self
                                        .send_packet(
                                            packet.src_node,
                                            PacketType::HandshakeResp,
                                            self.identity.public.as_slice(),
                                        )
                                        .await;
                                }

                                PacketType::HandshakeResp => {
                                    info!(
                                        "Received HandshakeResp from {} at {}! Direct connection established.",
                                        packet.src_node, remote_addr
                                    );
                                    if let Some(p) = table.get_mut(&packet.src_node) {
                                        p.endpoint = remote_addr;
                                        p.state = PeerState::Connected;
                                        p.last_seen = std::time::Instant::now();
                                    }
                                }

                                PacketType::KeepAlive => {
                                    if let Some(p) = table.get_mut(&packet.src_node) {
                                        p.last_seen = std::time::Instant::now();
                                    }
                                }

                                PacketType::Data => {
                                    // Forward incoming raw IP packet directly to local TUN device
                                    let guard = self.adapter.read().await;
                                    if let Some(adapter) = guard.as_ref() {
                                        let _ = adapter.write_packet(&packet.payload).await;
                                    }
                                }

                                PacketType::PairRequest => {
                                    info!("Incoming connection request from {} at {}", packet.src_node, remote_addr);
                                    let mut req_guard = self.pending_request.write().await;
                                    *req_guard = Some(PendingConnectionRequest {
                                        node_id: packet.src_node.to_string(),
                                        endpoint: remote_addr.to_string(),
                                    });
                                }

                                PacketType::PairAccept => {
                                    info!("Connection request accepted by {} at {}", packet.src_node, remote_addr);
                                    let peer = table.get_mut(&packet.src_node);
                                    if let Some(p) = peer {
                                        p.endpoint = remote_addr;
                                        p.state = PeerState::Connected;
                                        p.last_seen = std::time::Instant::now();
                                    } else {
                                        let mut new_p = Peer::new(packet.src_node, remote_addr);
                                        new_p.state = PeerState::Connected;
                                        table.insert(new_p);
                                    }
                                }

                                PacketType::PairReject => {
                                    warn!("Connection request rejected by {} at {}", packet.src_node, remote_addr);
                                }

                                PacketType::ChatMessage => {
                                    if let Ok(text) = String::from_utf8(packet.payload.to_vec()) {
                                        info!("Chat message received from {}: {}", packet.src_node, text);
                                        let ts = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        let mut chat_guard = self.chat_messages.write().await;
                                        chat_guard.push(ChatMessageEntry {
                                            id: format!("{}-{}", packet.src_node, ts),
                                            sender: packet.src_node.to_string(),
                                            recipient: self.node_id().to_string(),
                                            text,
                                            timestamp_secs: ts,
                                        });
                                    }
                                }

                                PacketType::StunProbe => {}
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
