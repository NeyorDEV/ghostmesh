pub mod access;
pub mod config;
pub mod control;
pub mod dns;
pub mod keystore;
pub mod peer;
pub mod rekey;
pub mod relay;
pub mod rendezvous;
pub mod sync;
pub mod trust;
pub mod update;

use serde::{Deserialize, Serialize};

pub use config::{load_config, save_config, AppConfig, KnownPeer, RelayEndpoint};
pub use ghost_tun::filter::{AccessPolicy, PortRange, Profile};
pub use peer::{LinkTx, Peer, PeerState, PeerTable, DIRECT_FRESH};
pub use relay::{RelayClient, RELAY_REMOTE};
pub use sync::{GhostSyncEngine, SyncStatus};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PendingConnectionRequest {
    pub node_id: String,
    pub endpoint: String,
}

use ghost_crypto::{IdentityKeypair, SessionKeys};
use ghost_protocol::{InviteTicket, NodeId, Packet, PacketType};
use ghost_tun::{Ipv4Header, VirtualAdapter};

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
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
    pub lan_endpoints: Vec<SocketAddr>,
    pub peers: Arc<RwLock<PeerTable>>,
    pub adapter: Arc<RwLock<Option<Arc<VirtualAdapter>>>>,
    pub relay: Arc<RwLock<Option<RelayClient>>>,
    pub sync: Arc<GhostSyncEngine>,
    pub pending_request: Arc<RwLock<Option<PendingConnectionRequest>>>,
    pub chat_messages: Arc<RwLock<Vec<ChatMessageEntry>>>,
    pub last_clipboard: Arc<RwLock<Option<ClipboardEntry>>>,
    pub active_exit_node: Arc<RwLock<Option<String>>>,
    pub is_ephemeral: bool,
    pub local_udp_port: u16,
    pub tcp_port: Option<u16>,
    tcp_listener: std::sync::Mutex<Option<tokio::net::TcpListener>>,
    seq: AtomicU64,
    udp_enabled: AtomicBool,
    pub diag: Arc<Diagnostics>,
    rdv_servers: Arc<RwLock<Vec<String>>>,
    rdv_issued: AtomicU64,
    pub(crate) rekey_secs: AtomicU64,
    pub(crate) rekey_bytes: AtomicU64,
    pub(crate) pending_rekeys: std::sync::Mutex<
        std::collections::HashMap<NodeId, (u8, ghost_crypto::EphemeralKey, std::time::Instant)>,
    >,
    pub(crate) blocked: RwLock<std::collections::HashSet<NodeId>>,
    pub access: access::AccessControl,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClipboardEntry {
    pub sender: String,
    pub text: String,
    pub timestamp_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessageEntry {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub text: String,
    pub timestamp_secs: u64,
}

pub fn get_local_lan_endpoints(port: u16) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    // Always include IPv4 loopback for same-machine instances
    addrs.push(SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
    ));

    // Discover active outbound local interface IP via routing probe to public DNS
    for target in &["8.8.8.8:80", "1.1.1.1:80", "208.67.222.222:80"] {
        if let Ok(dummy) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if dummy.connect(target).is_ok() {
                if let Ok(local) = dummy.local_addr() {
                    let lan_sock = SocketAddr::new(local.ip(), port);
                    if !addrs.contains(&lan_sock)
                        && !local.ip().is_loopback()
                        && !local.ip().is_unspecified()
                    {
                        addrs.push(lan_sock);
                    }
                }
            }
        }
    }

    addrs
}

fn record_known_peer(node_id: &str, endpoint: &str) {
    // Packets delivered by a relay carry no usable address: keep the last real one.
    if endpoint == relay::RELAY_REMOTE.to_string() {
        return;
    }
    let mut cfg = load_config();
    if let Some(p) = cfg.known_peers.iter_mut().find(|p| p.node_id == node_id) {
        p.endpoint = endpoint.to_string();
        p.last_seen = "Just now".to_string();
        let _ = save_config(&cfg);
    } else {
        cfg.known_peers.push(KnownPeer {
            alias: format!("Peer-{}", &node_id[..6.min(node_id.len())]),
            node_id: node_id.to_string(),
            endpoint: endpoint.to_string(),
            last_seen: "Just now".to_string(),
            allow_rdp: true,
            allow_ghostdrop: true,
            temporary_session: false,
            revoked: false,
            expires_at: None,
            access: Default::default(),
        });
        let _ = save_config(&cfg);
    }
}

/// Connectivity counters shared with the receive paths (read by the diagnostics panel).
#[derive(Default)]
pub struct Diagnostics {
    pub udp_rx: AtomicU64,
    pub tcp_rx: AtomicU64,
    pub rejected: AtomicU64,
    pub last_rx_unix: AtomicU64,
    pub tcp_links: AtomicU64,
    pub stun_ok: AtomicBool,
    pub mapping: RwLock<Option<ghost_nat::MappingReport>>,
    pub nat: RwLock<Option<ghost_nat::NatReport>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiagnosticsSnapshot {
    pub node_id: String,
    pub public_endpoint: String,
    pub stun_ok: bool,
    pub udp_port: u16,
    pub tcp_port: Option<u16>,
    pub mapping_done: bool,
    pub mapping_method: Option<String>,
    pub upnp: String,
    pub natpmp: String,
    pub pcp: String,
    pub router_external_ip: Option<String>,
    pub tcp_external_ports: Vec<u16>,
    pub udp_packets_rx: u64,
    pub tcp_packets_rx: u64,
    pub rejected_packets: u64,
    pub last_packet_secs_ago: Option<u64>,
    pub tcp_links: usize,
    pub hints: Vec<String>,
    #[serde(default)]
    pub nat_type: String,
    #[serde(default)]
    pub stun_answers: usize,
    #[serde(default)]
    pub candidates: Vec<String>,
    #[serde(default)]
    pub relay: Option<String>,
    #[serde(default)]
    pub direct_peers: usize,
    #[serde(default)]
    pub relayed_peers: usize,
}

impl MeshEngine {
    pub async fn bind_ephemeral(local_port: u16) -> Result<Self, EngineError> {
        let identity =
            IdentityKeypair::generate().map_err(|e| std::io::Error::other(e.to_string()))?;
        Self::bind_with_identity(local_port, identity).await
    }

    pub async fn bind_with_identity(
        local_port: u16,
        identity: IdentityKeypair,
    ) -> Result<Self, EngineError> {
        let (socket, actual_port, _secondary) = Self::bind_udp(local_port).await?;
        info!("Local UDP socket bound on port {actual_port}");
        Self::finish_bind(socket, actual_port, identity, true).await
    }

    pub async fn bind(local_port: u16) -> Result<Self, EngineError> {
        let (socket, actual_port, is_secondary) = Self::bind_udp(local_port).await?;
        info!("Local UDP socket bound on port {actual_port} (secondary={is_secondary})");

        let mut cfg = load_config();
        let identity = if !is_secondary {
            match keystore::load_or_create_identity(&mut cfg) {
                Ok((id, backend, changed)) => {
                    if changed {
                        let _ = save_config(&cfg);
                    }
                    info!(
                        "Loaded persistent identity {} (key kept in: {backend})",
                        id.node_id()
                    );
                    id
                }
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "cannot load or create the identity key: {e}"
                    ))
                    .into());
                }
            }
        } else {
            // Secondary instance on the same PC: generate an independent ephemeral identity
            // so local multi-window instances have distinct NodeIds and can pair with each other!
            let gen =
                IdentityKeypair::generate().map_err(|e| std::io::Error::other(e.to_string()))?;
            info!(
                "Secondary instance: generated ephemeral NodeId {}",
                gen.node_id()
            );
            gen
        };

        Self::finish_bind(socket, actual_port, identity, false).await
    }

    /// Binds the UDP socket on `local_port`, falling back to +2/+4/+6 then any free port.
    async fn bind_udp(local_port: u16) -> Result<(UdpSocket, u16, bool), EngineError> {
        // Try primary port, then progressive fallbacks (+2, +4, +6) or dynamic port 0
        let ports_to_try = if local_port == 0 {
            vec![0]
        } else {
            vec![
                local_port,
                local_port + 2,
                local_port + 4,
                local_port + 6,
                0,
            ]
        };

        for (idx, p) in ports_to_try.iter().enumerate() {
            match UdpSocket::bind(format!("0.0.0.0:{p}")).await {
                Ok(s) => {
                    let port = s.local_addr()?.port();
                    return Ok((s, port, idx > 0));
                }
                Err(e) => {
                    warn!("UDP port {p} unavailable ({e}), trying next fallback port...");
                }
            }
        }

        Err(
            std::io::Error::new(std::io::ErrorKind::AddrInUse, "No available UDP port found")
                .into(),
        )
    }

    async fn finish_bind(
        socket: UdpSocket,
        actual_port: u16,
        identity: IdentityKeypair,
        is_ephemeral: bool,
    ) -> Result<Self, EngineError> {
        let socket = Arc::new(socket);

        let diag = Arc::new(Diagnostics::default());
        // Ask several STUN servers at once: the public address, and the NAT behaviour (cone / symmetric)
        let stun_servers = load_config().stun_servers;
        let nat = ghost_nat::detect_nat(&socket, &stun_servers, Duration::from_secs(3))
            .await
            .ok();
        let public_addr = match nat.as_ref().and_then(|n| n.primary()) {
            Some(addr) => {
                info!(
                    "Public endpoint discovered via STUN: {addr} (NAT: {})",
                    nat.as_ref()
                        .map(|n| n.nat_type.to_string())
                        .unwrap_or_default()
                );
                diag.stun_ok.store(true, Ordering::Relaxed);
                addr
            }
            None => {
                warn!("No STUN server answered, falling back to local socket addr");
                socket.local_addr()?
            }
        };
        *diag.nat.write().await = nat;

        // TCP fallback listener: same port number as UDP when free, otherwise any free port
        let tcp_listener = match tokio::net::TcpListener::bind(("0.0.0.0", actual_port)).await {
            Ok(l) => Some(l),
            Err(_) => tokio::net::TcpListener::bind(("0.0.0.0", 0)).await.ok(),
        };
        let tcp_port = tcp_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port());
        match tcp_port {
            Some(p) => info!("TCP fallback listener bound on port {p}"),
            None => warn!("TCP fallback listener unavailable"),
        }

        // Automatically open the ports on the domestic router (UPnP, then NAT-PMP, then PCP)
        if actual_port > 0 {
            let diag_map = Arc::clone(&diag);
            tokio::spawn(async move {
                let report = ghost_nat::map_ports(actual_port, tcp_port).await;
                match &report.method {
                    Some(m) => info!(
                        "{m}: UDP port {actual_port} automatically mapped on router (TCP external ports: {:?}, router WAN IP: {:?})",
                        report.tcp_ports, report.external_ip
                    ),
                    None => warn!(
                        "Router port mapping failed (UPnP: {}; NAT-PMP: {}; PCP: {})",
                        report.upnp, report.natpmp, report.pcp
                    ),
                }
                *diag_map.mapping.write().await = Some(report);
            });
        }

        let lan_endpoints = get_local_lan_endpoints(actual_port);
        let seq_base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Ok(Self {
            identity,
            socket,
            public_addr,
            lan_endpoints,
            peers: Arc::new(RwLock::new(PeerTable::new())),
            adapter: Arc::new(RwLock::new(None)),
            relay: Arc::new(RwLock::new(None)),
            sync: Arc::new(GhostSyncEngine::new()),
            pending_request: Arc::new(RwLock::new(None)),
            chat_messages: Arc::new(RwLock::new(Vec::new())),
            last_clipboard: Arc::new(RwLock::new(None)),
            active_exit_node: Arc::new(RwLock::new(None)),
            is_ephemeral,
            local_udp_port: actual_port,
            tcp_port,
            tcp_listener: std::sync::Mutex::new(tcp_listener),
            seq: AtomicU64::new(seq_base),
            udp_enabled: AtomicBool::new(true),
            diag,
            rdv_servers: Arc::new(RwLock::new(Vec::new())),
            rdv_issued: AtomicU64::new(0),
            rekey_secs: AtomicU64::new(rekey::DEFAULT_REKEY_SECS),
            rekey_bytes: AtomicU64::new(rekey::DEFAULT_REKEY_BYTES),
            pending_rekeys: std::sync::Mutex::new(std::collections::HashMap::new()),
            blocked: RwLock::new(std::collections::HashSet::new()),
            access: access::AccessControl::default(),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn create_invite(&self) -> InviteTicket {
        InviteTicket::new(self.node_id(), self.public_addr, self.identity.public)
            .with_lan_endpoints(self.lan_endpoints.clone())
    }

    pub async fn add_peer(&self, node_id: NodeId, endpoint: SocketAddr) {
        let mut table = self.peers.write().await;
        table.insert(Peer::new(node_id, endpoint));
        info!("Added peer {node_id} at {endpoint}");
    }

    pub async fn remove_peer(&self, node_id: NodeId) {
        let mut table = self.peers.write().await;
        table.remove(&node_id);
        info!("Removed peer {node_id}");
    }

    pub async fn enable_virtual_interface(
        self: &Arc<Self>,
        virtual_ip: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<Arc<VirtualAdapter>, EngineError> {
        let mtu = load_config().mtu.unwrap_or(ghost_tun::DEFAULT_MTU);
        // Dual stack when the system allows it; plain IPv4 otherwise (IPv6 disabled, old driver...)
        let adapter = match VirtualAdapter::create_dual(
            "ghost0",
            virtual_ip,
            netmask,
            Some(self.node_id().to_virtual_ipv6()),
            mtu,
        ) {
            Ok(a) => a,
            Err(e) => {
                warn!("Cannot enable IPv6 on the virtual interface ({e}), using IPv4 only");
                VirtualAdapter::create_dual("ghost0", virtual_ip, netmask, None, mtu)?
            }
        };
        let adapter = Arc::new(adapter);
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
                        let destination = match packet_bytes.first().map(|b| b >> 4) {
                            Some(4) => Ipv4Header::parse(packet_bytes)
                                .ok()
                                .map(|h| std::net::IpAddr::V4(h.dest)),
                            Some(6) if packet_bytes.len() >= 40 => {
                                let mut o = [0u8; 16];
                                o.copy_from_slice(&packet_bytes[24..40]);
                                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)))
                            }
                            _ => None,
                        };
                        match destination {
                            Some(dest) => {
                                let target_node = {
                                    let routes = adapter_read.routes.read().await;
                                    match dest {
                                        std::net::IpAddr::V4(v4) => routes.get_node_by_ip(&v4),
                                        std::net::IpAddr::V6(v6) => routes.get_node_by_ip6(&v6),
                                    }
                                };

                                if let Some(dest_node) = target_node {
                                    if !engine.admit_outbound_ip(dest_node, packet_bytes) {
                                        continue;
                                    }
                                    let _ = engine
                                        .send_packet(dest_node, PacketType::Data, packet_bytes)
                                        .await;
                                }
                            }
                            None => {
                                // Ignore malformed packets from the OS
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
            routes.insert_v6(node_id.to_virtual_ipv6(), node_id);
            info!("Mapped peer {node_id} to virtual mesh IP {virtual_ip}");
        }
    }
}

/// Maximum accepted TCP frame (an encoded packet); larger frames close the link.
const MAX_TCP_FRAME: usize = 70_000;
/// A TCP link that stays silent this long is closed (authenticated keep-alives run every 10 s).
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TCP_LINKS: usize = 64;
/// Plaintext carried inside handshake proofs.
const HANDSHAKE_PROOF: &[u8] = b"GM-HS";
/// After this long without any answer a joined peer is reported as unreachable.
const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn packet_aad(packet_type: PacketType, src: &NodeId, dest: &NodeId) -> [u8; 33] {
    let mut aad = [0u8; 33];
    aad[0] = packet_type as u8;
    aad[1..17].copy_from_slice(dest.as_bytes());
    aad[17..33].copy_from_slice(src.as_bytes());
    aad
}

/// Packet types whose payload is never encrypted: they exist to establish trust in the first place.
fn is_plain_type(packet_type: PacketType) -> bool {
    matches!(
        packet_type,
        PacketType::StunProbe
            | PacketType::PairRequest
            | PacketType::PairAccept
            | PacketType::PairReject
            | PacketType::HandshakeInit
            | PacketType::HandshakeResp
    )
}

fn key_from_payload(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() < 32 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&payload[..32]);
    Some(pk)
}

fn node_id_of(pk: &[u8; 32]) -> NodeId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&pk[..16]);
    NodeId::new(id)
}

/// Updates which transport reaches the peer after an authenticated packet arrived.
fn note_transport(peer: &mut Peer, remote: SocketAddr, link: &Option<LinkTx>) {
    if remote == RELAY_REMOTE {
        // Reached through the relay: the direct address and links are left untouched.
        peer.relay_seen = Some(std::time::Instant::now());
        return;
    }
    match link {
        None => {
            peer.endpoint = remote;
            peer.last_udp = Some(std::time::Instant::now());
            peer.tcp = None;
        }
        Some(tx) => {
            let udp_recent = peer
                .last_udp
                .map(|t| t.elapsed() < Duration::from_secs(20))
                .unwrap_or(false);
            if !udp_recent {
                if peer.last_udp.is_none() {
                    peer.endpoint = remote;
                }
                peer.tcp = Some(tx.clone());
            }
        }
    }
}

impl MeshEngine {
    pub fn set_udp_enabled(&self, enabled: bool) {
        self.udp_enabled.store(enabled, Ordering::Relaxed);
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Builds a protected packet. Handshake packets carry our public key (plus a proof of
    /// possession once the peer's key is known); every other data-bearing type is encrypted.
    fn build_packet(
        &self,
        packet_type: PacketType,
        dest: NodeId,
        session: Option<&SessionKeys>,
        plaintext: &[u8],
    ) -> Result<Packet, EngineError> {
        self.build_packet_epoch(packet_type, dest, session, 0, plaintext)
    }

    /// Like `build_packet`, for a given rekey epoch (carried in the top byte of the sequence number).
    fn build_packet_epoch(
        &self,
        packet_type: PacketType,
        dest: NodeId,
        session: Option<&SessionKeys>,
        epoch: u8,
        plaintext: &[u8],
    ) -> Result<Packet, EngineError> {
        let src = self.node_id();
        let seq = (self.next_seq() & rekey::SEQ_MASK) | (u64::from(epoch) << 56);
        let aad = packet_aad(packet_type, &src, &dest);

        let payload = match packet_type {
            PacketType::HandshakeInit | PacketType::HandshakeResp => {
                let mut p = self.identity.public.to_vec();
                if let Some(s) = session {
                    p.extend_from_slice(&s.seal(seq, &aad, HANDSHAKE_PROOF));
                }
                p
            }
            t if is_plain_type(t) => plaintext.to_vec(),
            _ => match session {
                Some(s) => s.seal(seq, &aad, plaintext),
                None => {
                    return Err(EngineError::Protocol(
                        ghost_protocol::ProtocolError::BufferError(format!(
                            "no session key for peer {dest} yet (handshake not completed)"
                        )),
                    ))
                }
            },
        };

        Ok(Packet::new(packet_type, src, dest, seq, payload))
    }

    /// Sends an already encoded packet to `remote` over the given link (TCP) or UDP.
    async fn send_to_remote(&self, remote: SocketAddr, link: &Option<LinkTx>, encoded: &[u8]) {
        if let Some(tx) = link {
            let _ = tx.send(encoded.to_vec()).await;
        } else if self.udp_enabled.load(Ordering::Relaxed) {
            let _ = self.socket.send_to(encoded, remote).await;
        }
    }

    pub async fn send_packet(
        &self,
        dest_node: NodeId,
        packet_type: PacketType,
        payload: &[u8],
    ) -> Result<(), EngineError> {
        let snapshot = {
            let table = self.peers.read().await;
            table.get(&dest_node).map(|p| {
                (
                    p.endpoint,
                    p.tcp.clone(),
                    p.send_keys(),
                    p.is_direct(),
                    Arc::clone(&p.tx_bytes),
                )
            })
        };

        let Some((target_addr, tcp, send_keys, direct, tx_bytes)) = snapshot else {
            warn!("Peer {dest_node} not found in peer table");
            return Ok(());
        };

        let (epoch, session) = match send_keys {
            Some((e, k)) => (e, Some(k)),
            None => (0, None),
        };
        let packet =
            self.build_packet_epoch(packet_type, dest_node, session.as_deref(), epoch, payload)?;
        let encoded = packet.encode();
        tx_bytes.fetch_add(encoded.len() as u64, Ordering::Relaxed);

        if let Some(tx) = tcp {
            if tx.send(encoded.to_vec()).await.is_ok() {
                return Ok(());
            }
            // TCP link died: forget it and fall back to UDP below
            let mut table = self.peers.write().await;
            if let Some(p) = table.get_mut(&dest_node) {
                p.tcp = None;
            }
        }

        // Direct UDP is used whenever it is known to work; otherwise the relay carries the packet.
        // Handshake / pairing packets also try UDP, which is how a direct path gets discovered.
        let relay = {
            let guard = self.relay.read().await;
            guard.as_ref().filter(|r| r.is_connected()).cloned()
        };
        let via_relay = match (&relay, direct) {
            (Some(r), false) => {
                let _ = r.send_relayed_packet(&packet).await;
                true
            }
            _ => false,
        };
        let try_udp = !via_relay || is_plain_type(packet_type);
        if try_udp && !target_addr.ip().is_unspecified() {
            if self.udp_enabled.load(Ordering::Relaxed) {
                self.socket.send_to(&encoded, target_addr).await?;
            }
        } else if !via_relay && target_addr.ip().is_unspecified() {
            warn!("Peer {dest_node} has no known address and no relay is connected");
        }

        Ok(())
    }

    pub async fn join_ticket(self: &Arc<Self>, ticket: InviteTicket) -> Result<(), EngineError> {
        if ticket.node_id == self.node_id() {
            return Err(EngineError::Protocol(
                ghost_protocol::ProtocolError::BufferError(
                    "Cannot join your own invite ticket".into(),
                ),
            ));
        }

        let mut all_endpoints = ticket.all_endpoints();
        let primary_endpoint = all_endpoints.first().copied().unwrap_or(ticket.endpoint);

        let mut peer = Peer::new(ticket.node_id, primary_endpoint);
        peer.set_public_key(&self.identity, ticket.public_key);
        peer.state = PeerState::Punching;
        {
            let mut table = self.peers.write().await;
            table.insert(peer);
        }

        info!(
            "Starting UDP hole-punching towards {} candidate endpoints {:?} (NodeId: {})...",
            all_endpoints.len(),
            all_endpoints,
            ticket.node_id
        );

        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let session = SessionKeys::derive(&engine.identity, &ticket.public_key);
            let started = std::time::Instant::now();
            let mut tcp_rounds = 0u32;
            // Addresses learned from the rendezvous servers while we are still trying to connect
            let learned: Arc<std::sync::Mutex<Vec<SocketAddr>>> =
                Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut next_lookup = Duration::ZERO;

            loop {
                let state = {
                    let table = engine.peers.read().await;
                    table.get(&ticket.node_id).map(|p| p.state)
                };
                match state {
                    None => break, // peer removed by the user
                    Some(PeerState::Connected) => {
                        info!(
                            "Hole punching complete, peer {} is connected!",
                            ticket.node_id
                        );
                        break;
                    }
                    _ => {}
                }

                let elapsed = started.elapsed();
                if elapsed > JOIN_TIMEOUT {
                    warn!(
                        "No reply from {} after {:?}: marking unreachable",
                        ticket.node_id, JOIN_TIMEOUT
                    );
                    let mut table = engine.peers.write().await;
                    if let Some(p) = table.get_mut(&ticket.node_id) {
                        if p.state != PeerState::Connected {
                            p.state = PeerState::Unreachable;
                        }
                    }
                    break;
                }

                if elapsed >= next_lookup {
                    next_lookup = elapsed + Duration::from_secs(8);
                    let servers = engine.rendezvous_servers().await;
                    if !servers.is_empty() {
                        let (e, learned, node) =
                            (Arc::clone(&engine), Arc::clone(&learned), ticket.node_id);
                        tokio::spawn(async move {
                            if let Some(rec) = e.lookup_rendezvous(&servers, &node).await {
                                if let Ok(mut l) = learned.lock() {
                                    *l = rec.addrs;
                                }
                            }
                        });
                    }
                }
                if let Ok(l) = learned.lock() {
                    for a in l.iter() {
                        if !a.ip().is_unspecified() && !all_endpoints.contains(a) {
                            all_endpoints.insert(0, *a);
                        }
                    }
                }

                if engine.udp_enabled.load(Ordering::Relaxed) {
                    if let Ok(packet) = engine.build_packet(
                        PacketType::HandshakeInit,
                        ticket.node_id,
                        Some(&session),
                        &[],
                    ) {
                        let encoded = packet.encode();
                        for &candidate in &all_endpoints {
                            if !candidate.ip().is_unspecified() {
                                let _ = engine.socket.send_to(&encoded, candidate).await;
                            }
                        }
                    }
                }

                // Also announce ourselves through the relay: it works when no direct route exists yet
                if elapsed > Duration::from_millis(500) {
                    let relay = engine
                        .relay
                        .read()
                        .await
                        .as_ref()
                        .filter(|r| r.is_connected())
                        .cloned();
                    if let Some(r) = relay {
                        if let Ok(packet) = engine.build_packet(
                            PacketType::HandshakeInit,
                            ticket.node_id,
                            Some(&session),
                            &[],
                        ) {
                            let _ = r.send_relayed_packet(&packet).await;
                        }
                    }
                }

                // UDP got no answer: also try the TCP fallback (at 4 s, then again at 25 s)
                let tcp_due = (tcp_rounds == 0
                    && (elapsed > Duration::from_secs(4)
                        || !engine.udp_enabled.load(Ordering::Relaxed)))
                    || (tcp_rounds == 1 && elapsed > Duration::from_secs(25));
                if tcp_due {
                    tcp_rounds += 1;
                    engine.spawn_tcp_attempts(&ticket, &session);
                }

                let pause = if elapsed < Duration::from_secs(5) {
                    250
                } else {
                    1000
                };
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }
        });

        Ok(())
    }

    /// Tries to reach the inviter over TCP (port 443 first, which corporate networks rarely filter).
    fn spawn_tcp_attempts(self: &Arc<Self>, ticket: &InviteTicket, session: &SessionKeys) {
        let mut candidates: Vec<SocketAddr> = Vec::new();
        let public = ticket.endpoint;
        candidates.push(SocketAddr::new(
            public.ip(),
            ghost_nat::TCP_FALLBACK_EXTERNAL_PORT,
        ));
        candidates.push(public);
        for lan in ticket.all_endpoints() {
            if !candidates.contains(&lan) && !lan.ip().is_unspecified() {
                candidates.push(lan);
            }
        }
        info!("UDP silent: trying TCP fallback towards {:?}", candidates);

        for addr in candidates {
            let engine = Arc::clone(self);
            let session = session.clone();
            let dest = ticket.node_id;
            tokio::spawn(async move {
                let connect =
                    tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await;
                let Ok(Ok(stream)) = connect else { return };

                let connected = {
                    let table = engine.peers.read().await;
                    table
                        .get(&dest)
                        .map(|p| p.state == PeerState::Connected)
                        .unwrap_or(true)
                };
                if connected {
                    return;
                }

                info!("TCP link established towards {addr}");
                let tx = engine.spawn_tcp_link(stream, addr);
                if let Ok(packet) =
                    engine.build_packet(PacketType::HandshakeInit, dest, Some(&session), &[])
                {
                    let _ = tx.send(packet.encode().to_vec()).await;
                }
            });
        }
    }

    /// Spawns the reader/writer tasks of one TCP link and returns its outbound channel.
    fn spawn_tcp_link(self: &Arc<Self>, stream: TcpStream, remote: SocketAddr) -> LinkTx {
        let _ = stream.set_nodelay(true);
        let (mut rd, mut wr) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        self.diag.tcp_links.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let len = (frame.len() as u32).to_be_bytes();
                if wr.write_all(&len).await.is_err() || wr.write_all(&frame).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        let engine = Arc::clone(self);
        let reader_tx = tx.clone();
        tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            loop {
                let header =
                    tokio::time::timeout(TCP_IDLE_TIMEOUT, rd.read_exact(&mut len_buf)).await;
                if !matches!(header, Ok(Ok(_))) {
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len == 0 || len > MAX_TCP_FRAME {
                    break;
                }
                let mut frame = vec![0u8; len];
                if rd.read_exact(&mut frame).await.is_err() {
                    break;
                }
                if let Ok(packet) = Packet::decode(&frame) {
                    engine.diag.tcp_rx.fetch_add(1, Ordering::Relaxed);
                    engine
                        .diag
                        .last_rx_unix
                        .store(unix_secs(), Ordering::Relaxed);
                    engine
                        .handle_packet(packet, remote, Some(reader_tx.clone()))
                        .await;
                }
            }

            engine.diag.tcp_links.fetch_sub(1, Ordering::Relaxed);
            let mut table = engine.peers.write().await;
            for p in table.iter_mut() {
                if p.tcp
                    .as_ref()
                    .map(|t| t.same_channel(&reader_tx))
                    .unwrap_or(false)
                {
                    p.tcp = None;
                    if p.state == PeerState::Connected && p.last_udp.is_none() {
                        p.state = PeerState::Disconnected;
                    }
                }
            }
        });

        tx
    }

    async fn run_tcp_accept(self: Arc<Self>) {
        let listener = self.tcp_listener.lock().ok().and_then(|mut g| g.take());
        let Some(listener) = listener else { return };
        loop {
            match listener.accept().await {
                Ok((stream, remote)) => {
                    if self.diag.tcp_links.load(Ordering::Relaxed) >= MAX_TCP_LINKS as u64 {
                        continue;
                    }
                    info!("Incoming TCP link from {remote}");
                    self.spawn_tcp_link(stream, remote);
                }
                Err(e) => {
                    warn!("TCP accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Full snapshot of connectivity state for the diagnostics panel.
    pub async fn diagnostics(&self) -> DiagnosticsSnapshot {
        let d = &self.diag;
        let report = d.mapping.read().await.clone();
        let nat = d.nat.read().await.clone();
        let relay_in_use = self
            .relay
            .read()
            .await
            .as_ref()
            .and_then(|r| r.current_relay());
        let (direct_peers, relayed_peers) = {
            let table = self.peers.read().await;
            let connected = || table.iter().filter(|p| p.state == PeerState::Connected);
            (
                connected()
                    .filter(|p| p.is_direct() || p.tcp.is_some())
                    .count(),
                connected()
                    .filter(|p| !p.is_direct() && p.tcp.is_none() && p.relay_seen.is_some())
                    .count(),
            )
        };
        let (peers_waiting, tcp_peers) = {
            let table = self.peers.read().await;
            (
                table
                    .iter()
                    .filter(|p| matches!(p.state, PeerState::Punching | PeerState::Unreachable))
                    .count(),
                table.iter().filter(|p| p.tcp.is_some()).count(),
            )
        };

        let udp_rx = d.udp_rx.load(Ordering::Relaxed);
        let tcp_rx = d.tcp_rx.load(Ordering::Relaxed);
        let last = d.last_rx_unix.load(Ordering::Relaxed);
        let stun_ok = d.stun_ok.load(Ordering::Relaxed);

        let mut hints = Vec::new();
        if !stun_ok {
            hints.push(
                "STUN server unreachable: public IP unknown, internet access may be restricted."
                    .to_string(),
            );
        }
        match &report {
            None => hints.push("Router port mapping still in progress...".to_string()),
            Some(r) => {
                if !r.udp_mapped {
                    hints.push(format!(
                        "Router did not open UDP {} automatically (UPnP / NAT-PMP / PCP all failed). Forward UDP {} (and TCP 443) to this PC manually.",
                        self.local_udp_port, self.local_udp_port
                    ));
                }
                if let Some(router_ip) = r.external_ip {
                    let public = stun_ok.then_some(self.public_addr.ip());
                    if router_ip.is_private() || router_ip.is_link_local() {
                        hints.push(format!(
                            "Your router is itself behind another router (its WAN address is {router_ip}, a private address). The automatic port opening only reaches the inner router: forward UDP {p} and TCP 443 on the OUTER box (usually your ISP box) to {router_ip}, or set the inner router in bridge / DMZ mode.",
                            p = self.local_udp_port
                        ));
                    } else if public
                        .map(|ip| ip.to_string() != router_ip.to_string())
                        .unwrap_or(false)
                    {
                        hints.push(format!(
                            "Carrier-grade NAT suspected (router WAN {router_ip} differs from public IP {}). Inbound connections cannot reach this PC: ask your ISP for a public IP, or connect from this PC to the other one instead.",
                            public.unwrap()
                        ));
                    }
                }
            }
        }
        if let Some(n) = &nat {
            match n.nat_type {
                ghost_nat::NatType::Symmetric => hints.push(
                    "Symmetric NAT detected (each destination gets a different public port): direct connections only work towards a peer with a cone NAT. Otherwise traffic goes through the relay.".to_string(),
                ),
                ghost_nat::NatType::Unknown => hints.push(
                    "Only one STUN server answered, so the NAT type is unknown. Add more servers with `ghostmesh stun add`.".to_string(),
                ),
                ghost_nat::NatType::Blocked => hints.push(
                    "No STUN server answered: UDP is probably filtered. Only the TCP fallback and the relay can work.".to_string(),
                ),
                _ => {}
            }
            if let Some(p) = n.primary() {
                if ghost_nat::traversal::is_non_public(p.ip()) {
                    hints.push(format!("The address seen by STUN ({}) is not public: you are behind carrier-grade NAT. Direct inbound connections are impossible; use a relay.", p.ip()));
                }
            }
        }
        if relayed_peers > 0 {
            hints.push(format!("{relayed_peers} peer(s) currently go through the relay; the direct path is probed every few seconds and used as soon as it works."));
        }
        if peers_waiting > 0 && udp_rx == 0 && tcp_rx == 0 {
            hints.push("A peer is waiting but no packet was ever received: the remote network probably blocks UDP, or the router is not forwarding the port. The TCP 443 fallback is being tried.".to_string());
        }
        if tcp_peers > 0 {
            hints.push(
                "Some peers are connected through the TCP fallback (UDP is blocked on the path)."
                    .to_string(),
            );
        }

        DiagnosticsSnapshot {
            node_id: self.node_id().to_string(),
            public_endpoint: self.public_addr.to_string(),
            stun_ok,
            udp_port: self.local_udp_port,
            tcp_port: self.tcp_port,
            mapping_done: report.is_some(),
            mapping_method: report.as_ref().and_then(|r| r.method.clone()),
            upnp: report.as_ref().map(|r| r.upnp.clone()).unwrap_or_default(),
            natpmp: report
                .as_ref()
                .map(|r| r.natpmp.clone())
                .unwrap_or_default(),
            pcp: report.as_ref().map(|r| r.pcp.clone()).unwrap_or_default(),
            router_external_ip: report
                .as_ref()
                .and_then(|r| r.external_ip.map(|i| i.to_string())),
            tcp_external_ports: report
                .as_ref()
                .map(|r| r.tcp_ports.clone())
                .unwrap_or_default(),
            udp_packets_rx: udp_rx,
            tcp_packets_rx: tcp_rx,
            rejected_packets: d.rejected.load(Ordering::Relaxed),
            last_packet_secs_ago: if last == 0 {
                None
            } else {
                Some(unix_secs().saturating_sub(last))
            },
            tcp_links: d.tcp_links.load(Ordering::Relaxed) as usize,
            hints,
            nat_type: nat
                .as_ref()
                .map(|n| n.nat_type.to_string())
                .unwrap_or_else(|| "Unknown".into()),
            stun_answers: nat.as_ref().map(|n| n.observations.len()).unwrap_or(0),
            candidates: self
                .current_candidates()
                .iter()
                .map(|a| a.to_string())
                .collect(),
            relay: relay_in_use,
            direct_peers,
            relayed_peers,
        }
    }

    pub async fn send_chat_message(
        &self,
        dest_node: NodeId,
        text: &str,
    ) -> Result<(), EngineError> {
        self.send_packet(dest_node, PacketType::ChatMessage, text.as_bytes())
            .await?;
        let ts = unix_secs();
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

    pub async fn send_clipboard(&self, dest_node: NodeId, text: &str) -> Result<(), EngineError> {
        self.send_packet(dest_node, PacketType::ClipboardSync, text.as_bytes())
            .await
    }

    pub async fn start_background_tasks(self: &Arc<Self>) {
        if !self.is_ephemeral {
            let cfg = load_config();
            self.start_relays(cfg.relays).await;
            self.start_rendezvous(cfg.rendezvous).await;
        }

        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let peers_to_ping: Vec<NodeId> = {
                    let table = engine.peers.read().await;
                    table
                        .iter()
                        .filter(|p| p.state == PeerState::Connected)
                        .map(|p| p.node_id)
                        .collect()
                };

                for node_id in peers_to_ping {
                    let _ = engine
                        .send_packet(node_id, PacketType::KeepAlive, b"PING")
                        .await;
                }
            }
        });

        self.spawn_rekey_task();
        if !self.is_ephemeral {
            self.spawn_trust_task();
        }

        // While a peer is only reachable through the relay, keep probing the direct path.
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                if !engine.udp_enabled.load(Ordering::Relaxed) {
                    continue;
                }
                let targets: Vec<(NodeId, SocketAddr, Arc<SessionKeys>)> = {
                    let table = engine.peers.read().await;
                    table
                        .iter()
                        .filter(|p| {
                            p.state == PeerState::Connected && p.tcp.is_none() && !p.is_direct()
                        })
                        .filter(|p| !p.endpoint.ip().is_unspecified())
                        .filter_map(|p| p.session.clone().map(|s| (p.node_id, p.endpoint, s)))
                        .collect()
                };
                for (node_id, endpoint, session) in targets {
                    if let Ok(packet) = engine.build_packet(
                        PacketType::KeepAlive,
                        node_id,
                        Some(&session),
                        b"PROBE",
                    ) {
                        let _ = engine.socket.send_to(&packet.encode(), endpoint).await;
                    }
                }
            }
        });
    }

    /// Updates the address used to reach a known peer (for example after a rendezvous lookup).
    pub async fn set_peer_endpoint(&self, node_id: NodeId, endpoint: SocketAddr) {
        let mut table = self.peers.write().await;
        if let Some(p) = table.get_mut(&node_id) {
            p.endpoint = endpoint;
        }
    }

    fn note_relay_rx(&self) {
        self.diag.last_rx_unix.store(unix_secs(), Ordering::Relaxed);
    }

    pub async fn run_receive_loop(self: Arc<Self>) {
        tokio::spawn(Arc::clone(&self).run_tcp_accept());

        let mut buf = [0u8; 65535];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, remote_addr)) => {
                    if !self.udp_enabled.load(Ordering::Relaxed) {
                        continue;
                    }
                    match Packet::decode(&buf[..len]) {
                        Ok(packet) => {
                            self.diag.udp_rx.fetch_add(1, Ordering::Relaxed);
                            self.diag.last_rx_unix.store(unix_secs(), Ordering::Relaxed);
                            self.handle_packet(packet, remote_addr, None).await;
                        }
                        Err(e) => {
                            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
                            warn!("Malformed packet from {remote_addr}: {e}");
                        }
                    }
                }
                Err(e) => {
                    // On Windows, ICMP Port Unreachable returns WSAECONNRESET (10054).
                    // In connectionless UDP, candidate probing causes transient errors that must NEVER break the loop!
                    warn!("Socket recv error (non-fatal, continuing): {e}");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            }
        }
    }

    /// Processes one decoded packet received over UDP (`link == None`) or a TCP link.
    async fn handle_packet(
        self: &Arc<Self>,
        packet: Packet,
        remote: SocketAddr,
        link: Option<LinkTx>,
    ) {
        // 1. Ignore any packet from ourselves (loopback reflection)
        if packet.src_node == self.node_id() {
            return;
        }
        // Revoked or expired devices are dropped before anything else
        if self.blocked.read().await.contains(&packet.src_node) {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // 2. Multi-hop Mesh Routing: forward packets that are not for this node (payloads stay sealed end to end)
        if packet.dest_node != self.node_id() {
            let target = {
                let table = self.peers.read().await;
                table
                    .get(&packet.dest_node)
                    .filter(|p| p.state == PeerState::Connected)
                    .map(|p| (p.endpoint, p.tcp.clone()))
            };
            if let Some((endpoint, tcp)) = target {
                info!(
                    "Mesh Forwarder: routing packet (type {:?}) from {} towards {}",
                    packet.packet_type, packet.src_node, packet.dest_node
                );
                self.send_to_remote(endpoint, &tcp, &packet.encode()).await;
            }
            return;
        }

        match packet.packet_type {
            PacketType::StunProbe => {}
            PacketType::HandshakeInit => self.handle_handshake_init(packet, remote, link).await,
            PacketType::HandshakeResp => self.handle_handshake_resp(packet, remote, link).await,

            PacketType::PairRequest => {
                info!(
                    "Incoming connection request from {} at {}",
                    packet.src_node, remote
                );
                let mut req_guard = self.pending_request.write().await;
                *req_guard = Some(PendingConnectionRequest {
                    node_id: packet.src_node.to_string(),
                    endpoint: remote.to_string(),
                });
            }

            PacketType::PairAccept => {
                info!(
                    "Connection request accepted by {} at {}",
                    packet.src_node, remote
                );
                // Only meaningful for a request we sent: the peer must already be in our table.
                let known = {
                    let mut table = self.peers.write().await;
                    match table.get_mut(&packet.src_node) {
                        Some(p) => {
                            if remote != RELAY_REMOTE {
                                p.endpoint = remote;
                            }
                            if p.state != PeerState::Connected {
                                p.state = PeerState::Punching;
                            }
                            p.last_seen = std::time::Instant::now();
                            p.session.clone()
                        }
                        None => return,
                    }
                };
                // Exchange keys so traffic can be authenticated and encrypted
                if let Ok(p) = self.build_packet(
                    PacketType::HandshakeInit,
                    packet.src_node,
                    known.as_deref(),
                    &[],
                ) {
                    self.send_to_remote(remote, &link, &p.encode()).await;
                }
            }

            PacketType::PairReject => {
                warn!(
                    "Connection request rejected by {} at {}",
                    packet.src_node, remote
                );
            }

            PacketType::Data
            | PacketType::KeepAlive
            | PacketType::ChatMessage
            | PacketType::ClipboardSync
            | PacketType::ExitNodeRoute
            | PacketType::Rekey
            | PacketType::RekeyAck
            | PacketType::Revoke => self.handle_sealed(packet, remote, link).await,
        }
    }

    async fn handle_handshake_init(
        self: &Arc<Self>,
        packet: Packet,
        remote: SocketAddr,
        link: Option<LinkTx>,
    ) {
        let src = packet.src_node;
        info!("Received HandshakeInit from {src} at {remote}");

        let Some(pk) = key_from_payload(&packet.payload) else {
            return;
        };
        if node_id_of(&pk) != src {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            warn!("HandshakeInit from {remote} rejected: NodeId does not match its public key");
            return;
        }

        let session = Arc::new(SessionKeys::derive(&self.identity, &pk));
        let aad = packet_aad(PacketType::HandshakeInit, &src, &packet.dest_node);
        let proven = if packet.payload.len() > 32 {
            match session.open(packet.sequence, &aad, &packet.payload[32..]) {
                Some(plain) if plain == HANDSHAKE_PROOF => true,
                _ => {
                    self.diag.rejected.fetch_add(1, Ordering::Relaxed);
                    warn!("HandshakeInit from {remote} rejected: invalid proof of key possession");
                    return;
                }
            }
        } else {
            false
        };

        {
            let mut table = self.peers.write().await;
            match table.get_mut(&src) {
                Some(p) => {
                    if let Some(existing) = p.public_key {
                        if existing != pk {
                            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
                            warn!("HandshakeInit from {remote} rejected: public key differs from the known one");
                            return;
                        }
                    } else {
                        p.set_public_key(&self.identity, pk);
                    }
                    if proven {
                        if !p.replay.accept(packet.sequence) {
                            return; // duplicate of a probe already answered
                        }
                        note_transport(p, remote, &link);
                        p.state = PeerState::Connected;
                        p.last_seen = std::time::Instant::now();
                    }
                }
                None => {
                    let mut new_peer = Peer::new(src, remote);
                    new_peer.set_public_key(&self.identity, pk);
                    if proven {
                        new_peer.replay.accept(packet.sequence);
                        new_peer.state = PeerState::Connected;
                        note_transport(&mut new_peer, remote, &link);
                    } else {
                        new_peer.state = PeerState::Punching;
                    }
                    table.insert(new_peer);
                }
            }
        }

        if proven && !self.is_ephemeral {
            record_known_peer(&src.to_string(), &remote.to_string());
        }

        // Answer straight to the address the packet came from (this also punches our side of the NAT)
        if let Ok(resp) = self.build_packet(PacketType::HandshakeResp, src, Some(&session), &[]) {
            self.send_to_remote(remote, &link, &resp.encode()).await;
        }
    }

    async fn handle_handshake_resp(
        self: &Arc<Self>,
        packet: Packet,
        remote: SocketAddr,
        link: Option<LinkTx>,
    ) {
        let src = packet.src_node;
        let Some(pk) = key_from_payload(&packet.payload) else {
            return;
        };
        if node_id_of(&pk) != src || packet.payload.len() <= 32 {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let session = Arc::new(SessionKeys::derive(&self.identity, &pk));
        let aad = packet_aad(PacketType::HandshakeResp, &src, &packet.dest_node);
        match session.open(packet.sequence, &aad, &packet.payload[32..]) {
            Some(plain) if plain == HANDSHAKE_PROOF => {}
            _ => {
                self.diag.rejected.fetch_add(1, Ordering::Relaxed);
                warn!("HandshakeResp from {remote} rejected: invalid proof of key possession");
                return;
            }
        }

        let first_key = {
            let mut table = self.peers.write().await;
            let Some(p) = table.get_mut(&src) else { return }; // we never asked this node
            let first_key = p.public_key.is_none();
            if let Some(existing) = p.public_key {
                if existing != pk {
                    self.diag.rejected.fetch_add(1, Ordering::Relaxed);
                    warn!("HandshakeResp from {remote} rejected: public key differs from the known one");
                    return;
                }
            } else {
                p.set_public_key(&self.identity, pk);
            }
            if !p.replay.accept(packet.sequence) {
                return;
            }
            note_transport(p, remote, &link);
            p.state = PeerState::Connected;
            p.last_seen = std::time::Instant::now();
            first_key
        };

        info!(
            "Received HandshakeResp from {src} at {remote}! Authenticated connection established."
        );
        if !self.is_ephemeral {
            record_known_peer(&src.to_string(), &remote.to_string());
        }

        if first_key {
            // The other side has not yet seen a proof from us: a sealed packet completes the exchange
            let _ = self.send_packet(src, PacketType::KeepAlive, b"HELLO").await;
        }
    }

    /// Decrypts and dispatches Data / KeepAlive / Chat / Clipboard / ExitNodeRoute packets.
    async fn handle_sealed(
        self: &Arc<Self>,
        packet: Packet,
        remote: SocketAddr,
        link: Option<LinkTx>,
    ) {
        let src = packet.src_node;
        let epoch = (packet.sequence >> 56) as u8;
        let session = {
            let table = self.peers.read().await;
            table.get(&src).and_then(|p| p.keys_for_epoch(epoch))
        };
        let Some(session) = session else {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            return; // unknown peer: no key, nothing to authenticate against
        };

        let aad = packet_aad(packet.packet_type, &src, &packet.dest_node);
        let Some(plain) = session.open(packet.sequence, &aad, &packet.payload) else {
            self.diag.rejected.fetch_add(1, Ordering::Relaxed);
            return; // forged, corrupted or tampered packet
        };

        {
            let mut table = self.peers.write().await;
            let Some(p) = table.get_mut(&src) else { return };
            if !p.accept_seq(epoch, packet.sequence) {
                self.diag.rejected.fetch_add(1, Ordering::Relaxed);
                return; // replayed packet
            }
            // A fresh base-epoch packet long after a rekey means the peer restarted: follow it back to the base keys
            if epoch == 0 && p.epoch.is_some() && p.epoch_since.elapsed() > peer::EPOCH_GRACE {
                p.epoch = None;
                p.prev_epoch = None;
                p.epoch_since = std::time::Instant::now();
            }
            note_transport(p, remote, &link);
            p.state = PeerState::Connected;
            p.last_seen = std::time::Instant::now();
        }

        match packet.packet_type {
            PacketType::KeepAlive => {}

            PacketType::Data => {
                // Forward incoming raw IP packet to the local TUN device, if the peer's profile allows it
                if !self.admit_inbound_ip(src, &plain).await {
                    return;
                }
                let guard = self.adapter.read().await;
                if let Some(adapter) = guard.as_ref() {
                    let _ = adapter.write_packet(&plain).await;
                }
            }

            PacketType::ChatMessage => {
                if let Ok(text) = String::from_utf8(plain) {
                    info!("Chat message received from {}: {}", src, text);
                    let ts = unix_secs();
                    let mut chat_guard = self.chat_messages.write().await;
                    chat_guard.push(ChatMessageEntry {
                        id: format!("{}-{}", src, ts),
                        sender: src.to_string(),
                        recipient: self.node_id().to_string(),
                        text,
                        timestamp_secs: ts,
                    });
                }
            }

            PacketType::ClipboardSync => {
                if let Ok(text) = String::from_utf8(plain) {
                    info!("Clipboard received from {}: {} chars", src, text.len());
                    let mut clip_guard = self.last_clipboard.write().await;
                    *clip_guard = Some(ClipboardEntry {
                        sender: src.to_string(),
                        text,
                        timestamp_secs: unix_secs(),
                    });
                }
            }

            PacketType::ExitNodeRoute => {
                info!("Exit node routing notification from {}", src);
            }

            PacketType::Rekey => self.handle_rekey(src, &plain, remote, &link).await,
            PacketType::RekeyAck => self.handle_rekey_ack(src, &plain).await,
            PacketType::Revoke => self.handle_revoke(src, &plain).await,

            _ => {}
        }
    }
}
