//! Rendezvous client: publishes this node's signed address record and looks up other nodes'.
//! The servers only ever see public keys, addresses and signatures.

use crate::{get_local_lan_endpoints, load_config, MeshEngine, PeerState};
use ghost_crypto::{xeddsa_sign, xeddsa_verify};
use ghost_protocol::rendezvous::{RdvFrame, RendezvousRecord, SignedRecord, MAX_SIGNED_RECORD};
use ghost_protocol::{InviteTicket, NodeId};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Lifetime of a published record; it is refreshed every third of it.
pub const RECORD_TTL_SECS: u32 = 600;
const TICK: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn request(server: &str, frame: &RdvFrame) -> std::io::Result<RdvFrame> {
    let work = async {
        let mut stream = TcpStream::connect(server).await?;
        let body = frame.encode();
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        stream.write_all(&out).await?;

        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let len = u16::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_SIGNED_RECORD + 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad answer length",
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        RdvFrame::decode(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    };
    tokio::time::timeout(REQUEST_TIMEOUT, work)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "rendezvous server timeout")
        })?
}

/// Returns the record only when it really belongs to `node`, is signed by it and has not expired.
pub fn verify_record(node: &NodeId, signed: &SignedRecord) -> Option<RendezvousRecord> {
    let record = signed.record().ok()?;
    if record.node_id() != *node {
        return None;
    }
    if !xeddsa_verify(&record.node_public, &signed.body, &signed.signature) {
        return None;
    }
    if record.issued_at + u64::from(record.ttl_secs) <= unix_now() {
        return None;
    }
    Some(record)
}

impl MeshEngine {
    /// Addresses at which this node can currently be reached, best first: what STUN saw, the port
    /// opened on the router, a few predicted ports when the NAT is symmetric, then the LAN addresses.
    /// Loopback is excluded.
    pub fn current_candidates(&self) -> Vec<SocketAddr> {
        fn push(out: &mut Vec<SocketAddr>, a: SocketAddr) {
            if !a.ip().is_unspecified() && !a.ip().is_loopback() && !out.contains(&a) {
                out.push(a);
            }
        }
        let mut out = Vec::new();
        push(&mut out, self.public_addr);
        if let Ok(nat) = self.diag.nat.try_read() {
            if let Some(n) = nat.as_ref() {
                for a in n.distinct_addresses() {
                    push(&mut out, a);
                }
                if n.nat_type == ghost_nat::NatType::Symmetric {
                    let ports: Vec<u16> = n.observations.iter().map(|(_, a)| a.port()).collect();
                    if let Some(ip) = n.primary().map(|a| a.ip()) {
                        for p in ghost_nat::predict_ports(&ports) {
                            push(&mut out, SocketAddr::new(ip, p));
                        }
                    }
                }
            }
        }
        if let Ok(map) = self.diag.mapping.try_read() {
            if let Some(r) = map.as_ref().filter(|r| r.udp_mapped) {
                if let Some(ip) = r.external_ip {
                    push(
                        &mut out,
                        SocketAddr::new(std::net::IpAddr::V4(ip), self.local_udp_port),
                    );
                }
            }
        }
        for a in get_local_lan_endpoints(self.local_udp_port) {
            push(&mut out, a);
        }
        out.truncate(ghost_protocol::rendezvous::MAX_ADDRS);
        out
    }

    /// Signs and publishes a record listing `endpoints`. Returns how many servers accepted it.
    pub async fn publish_rendezvous(
        &self,
        servers: &[String],
        endpoints: Vec<SocketAddr>,
    ) -> usize {
        // Strictly increasing issue time, even for several publications within one second.
        let issued_at = {
            let now = unix_now();
            let mut prev = self.rdv_issued.load(Ordering::Relaxed);
            loop {
                let next = now.max(prev + 1);
                match self.rdv_issued.compare_exchange(
                    prev,
                    next,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break next,
                    Err(p) => prev = p,
                }
            }
        };
        let body = RendezvousRecord {
            node_public: self.identity.public,
            issued_at,
            ttl_secs: RECORD_TTL_SECS,
            addrs: endpoints,
        }
        .encode();
        let signature = xeddsa_sign(&self.identity.private, &body);
        let frame = RdvFrame::Publish(SignedRecord { body, signature });

        let mut ok = 0;
        for server in servers {
            match request(server, &frame).await {
                Ok(RdvFrame::Ok) => ok += 1,
                Ok(other) => warn!("rendezvous {server} refused the record: {other:?}"),
                Err(e) => warn!("rendezvous {server} unreachable: {e}"),
            }
        }
        ok
    }

    /// Looks `node` up on every server and returns the newest valid record.
    pub async fn lookup_rendezvous(
        &self,
        servers: &[String],
        node: &NodeId,
    ) -> Option<RendezvousRecord> {
        let mut best: Option<RendezvousRecord> = None;
        for server in servers {
            if let Ok(RdvFrame::Record(signed)) = request(server, &RdvFrame::Lookup(*node)).await {
                if let Some(rec) = verify_record(node, &signed) {
                    if best
                        .as_ref()
                        .map(|b| rec.issued_at > b.issued_at)
                        .unwrap_or(true)
                    {
                        best = Some(rec);
                    }
                }
            }
        }
        best
    }

    pub async fn rendezvous_servers(&self) -> Vec<String> {
        self.rdv_servers.read().await.clone()
    }

    pub async fn set_rendezvous_servers(&self, servers: Vec<String>) {
        *self.rdv_servers.write().await = servers;
    }

    /// Sets the servers and starts publishing / reconnecting in the background.
    pub async fn start_rendezvous(self: &Arc<Self>, servers: Vec<String>) {
        if servers.is_empty() {
            return;
        }
        self.set_rendezvous_servers(servers).await;
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut last_published: Vec<SocketAddr> = Vec::new();
            let mut last_time = std::time::Instant::now() - Duration::from_secs(86_400);
            loop {
                let servers = engine.rendezvous_servers().await;
                let candidates = engine.current_candidates();
                let due = candidates != last_published
                    || last_time.elapsed() >= Duration::from_secs(u64::from(RECORD_TTL_SECS / 3));
                if due && !candidates.is_empty() {
                    let ok = engine
                        .publish_rendezvous(&servers, candidates.clone())
                        .await;
                    if ok > 0 {
                        info!(
                            "published {} address(es) to {ok} rendezvous server(s)",
                            candidates.len()
                        );
                        last_published = candidates;
                        last_time = std::time::Instant::now();
                    }
                }
                engine.reconnect_known_peers().await;
                tokio::time::sleep(TICK).await;
            }
        });
    }

    /// Asks rendezvous for the address of every known device we are not talking to.
    async fn reconnect_known_peers(self: &Arc<Self>) {
        if self.is_ephemeral {
            return;
        }
        for kp in load_config().known_peers {
            let Ok(node) = kp.node_id.parse::<NodeId>() else {
                continue;
            };
            let idle = {
                let table = self.peers.read().await;
                match table.get(&node) {
                    None => true,
                    Some(p) => matches!(p.state, PeerState::Unreachable | PeerState::Disconnected),
                }
            };
            if idle {
                self.connect_known(node).await;
            }
        }
    }

    /// Reconnects to a device we already know, without any ticket, using its rendezvous record.
    pub async fn connect_known(self: &Arc<Self>, node: NodeId) -> bool {
        let servers = self.rendezvous_servers().await;
        let Some(rec) = self.lookup_rendezvous(&servers, &node).await else {
            return false;
        };
        let mut addrs = rec
            .addrs
            .iter()
            .copied()
            .filter(|a| !a.ip().is_unspecified());
        let Some(first) = addrs.next() else {
            return false;
        };
        let ticket =
            InviteTicket::new(node, first, rec.node_public).with_lan_endpoints(addrs.collect());
        self.join_ticket(ticket).await.is_ok()
    }
}
