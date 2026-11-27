//! GhostMesh relay server.
//!
//! A node connects, proves it owns the private key of its NodeId (challenge answered with an
//! X25519-derived proof, see `ghost_crypto::relay_proof`), then hands over already sealed packets.
//! The relay forwards each packet to the registered connection of the destination NodeId. It keeps
//! no persistent state and never has the keys to read a payload.

use ghost_crypto::{ct_eq32, relay_proof, IdentityKeypair};
use ghost_protocol::relay::{packet_route, RelayFrame, MAX_RELAY_FRAME, RELAY_VERSION};
use ghost_protocol::NodeId;
use rand::RngCore;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub mod rendezvous;

/// Error codes sent in `RelayFrame::Error` before the connection is closed.
pub const ERR_BAD_PROOF: u8 = 1;
pub const ERR_BUSY: u8 = 3;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub max_connections: usize,
    pub max_per_ip: usize,
    /// Sustained forwarding rate per connection, in bytes per second.
    pub rate_bytes_per_sec: u64,
    /// Short bursts above the sustained rate are allowed up to this many bytes.
    pub burst_bytes: u64,
    pub register_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_connections: 4096,
            max_per_ip: 16,
            rate_bytes_per_sec: 8 * 1024 * 1024,
            burst_bytes: 2 * 1024 * 1024,
            register_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
        }
    }
}

#[derive(Default)]
pub struct RelayStats {
    pub forwarded: AtomicU64,
    pub dropped: AtomicU64,
    pub registered_total: AtomicU64,
    pub rejected_proofs: AtomicU64,
}

struct Route {
    conn_id: u64,
    tx: mpsc::Sender<Vec<u8>>,
}

pub struct RelayServer {
    identity: IdentityKeypair,
    cfg: RelayConfig,
    routes: Mutex<HashMap<NodeId, Route>>,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    total: AtomicUsize,
    next_conn: AtomicU64,
    pub stats: RelayStats,
}

/// Releases the connection slots taken at admission, whatever way the connection ends.
struct Admission {
    server: Arc<RelayServer>,
    ip: IpAddr,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.server.total.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut m) = self.server.per_ip.lock() {
            if let Some(n) = m.get_mut(&self.ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(&self.ip);
                }
            }
        }
    }
}

struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            tokens: burst as f64,
            rate: rate as f64,
            burst: burst as f64,
            last: Instant::now(),
        }
    }

    fn take(&mut self, n: usize) -> bool {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(rd: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    rd.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_RELAY_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad frame length",
        ));
    }
    let mut body = vec![0u8; len];
    rd.read_exact(&mut body).await?;
    Ok(body)
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    wr: &mut W,
    body: &[u8],
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    wr.write_all(&out).await
}

impl RelayServer {
    pub fn new(identity: IdentityKeypair, cfg: RelayConfig) -> Arc<Self> {
        Arc::new(Self {
            identity,
            cfg,
            routes: Mutex::new(HashMap::new()),
            per_ip: Mutex::new(HashMap::new()),
            total: AtomicUsize::new(0),
            next_conn: AtomicU64::new(1),
            stats: RelayStats::default(),
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public
    }

    pub fn connected_nodes(&self) -> usize {
        self.routes.lock().map(|r| r.len()).unwrap_or(0)
    }

    fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<Admission> {
        if self.total.load(Ordering::Relaxed) >= self.cfg.max_connections {
            return None;
        }
        let mut m = self.per_ip.lock().ok()?;
        let n = m.entry(ip).or_insert(0);
        if *n >= self.cfg.max_per_ip {
            return None;
        }
        *n += 1;
        self.total.fetch_add(1, Ordering::Relaxed);
        Some(Admission {
            server: Arc::clone(self),
            ip,
        })
    }

    /// Accepts connections forever on `listener`.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let _ = stream.set_nodelay(true);
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle(stream, addr.ip()).await {
                            debug!("connection from {addr} ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!("accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Serves one connection on any byte stream (plain TCP today, a TLS stream later).
    pub async fn handle<S>(self: &Arc<Self>, stream: S, ip: IpAddr) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);

        let Some(_admission) = self.admit(ip) else {
            let _ = write_frame(&mut wr, &RelayFrame::Error(ERR_BUSY).encode()).await;
            return Err(std::io::Error::other("connection limit reached"));
        };

        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        let hello = RelayFrame::Hello {
            version: RELAY_VERSION,
            challenge,
            relay_public: self.identity.public,
        };
        write_frame(&mut wr, &hello.encode()).await?;

        let body = tokio::time::timeout(self.cfg.register_timeout, read_frame(&mut rd))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "registration timeout")
            })??;
        let Ok(RelayFrame::Register { node_public, proof }) = RelayFrame::decode(&body) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected Register",
            ));
        };

        let expected = relay_proof(
            &self.identity.private,
            &node_public,
            &challenge,
            &node_public,
            &self.identity.public,
        );
        if !expected.map(|e| ct_eq32(&e, &proof)).unwrap_or(false) {
            self.stats.rejected_proofs.fetch_add(1, Ordering::Relaxed);
            let _ = write_frame(&mut wr, &RelayFrame::Error(ERR_BAD_PROOF).encode()).await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid proof of key possession",
            ));
        }

        let mut id = [0u8; 16];
        id.copy_from_slice(&node_public[..16]);
        let node = NodeId::new(id);

        write_frame(&mut wr, &RelayFrame::Registered.encode()).await?;
        self.stats.registered_total.fetch_add(1, Ordering::Relaxed);

        let conn_id = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        if let Ok(mut routes) = self.routes.lock() {
            // A newer authenticated connection of the same node replaces the older one.
            routes.insert(node, Route { conn_id, tx });
        }
        info!(
            "node {node} registered (connections: {})",
            self.connected_nodes()
        );

        let writer = tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if write_frame(&mut wr, &body).await.is_err() {
                    break;
                }
            }
        });

        let mut bucket = Bucket::new(self.cfg.rate_bytes_per_sec, self.cfg.burst_bytes);
        let result = self.read_loop(&mut rd, node, &mut bucket).await;

        writer.abort();
        if let Ok(mut routes) = self.routes.lock() {
            if routes.get(&node).map(|r| r.conn_id) == Some(conn_id) {
                routes.remove(&node);
            }
        }
        result
    }

    async fn read_loop<R: AsyncRead + Unpin>(
        &self,
        rd: &mut R,
        node: NodeId,
        bucket: &mut Bucket,
    ) -> std::io::Result<()> {
        loop {
            let body = tokio::time::timeout(self.cfg.idle_timeout, read_frame(rd))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))??;
            match RelayFrame::decode(&body) {
                Ok(RelayFrame::Ping) => {}
                Ok(RelayFrame::Packet(raw)) => {
                    // Only the header is inspected; the sender must be the registered node.
                    let Some((src, dest)) = packet_route(&raw) else {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if src != node || !bucket.take(raw.len()) {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let target = self
                        .routes
                        .lock()
                        .ok()
                        .and_then(|r| r.get(&dest).map(|x| x.tx.clone()));
                    match target {
                        Some(tx) if tx.try_send(RelayFrame::Packet(raw).encode()).is_ok() => {
                            self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected frame",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn connect(server: &Arc<RelayServer>, id: &IdentityKeypair) -> tokio::io::DuplexStream {
        let (client, srv) = duplex(64 * 1024);
        let s = Arc::clone(server);
        tokio::spawn(async move {
            let _ = s.handle(srv, "127.0.0.1".parse().unwrap()).await;
        });
        let mut client = client;
        let body = read_frame(&mut client).await.unwrap();
        let RelayFrame::Hello {
            challenge,
            relay_public,
            ..
        } = RelayFrame::decode(&body).unwrap()
        else {
            panic!("expected hello")
        };
        let proof = relay_proof(
            &id.private,
            &relay_public,
            &challenge,
            &id.public,
            &relay_public,
        )
        .unwrap();
        write_frame(
            &mut client,
            &RelayFrame::Register {
                node_public: id.public,
                proof,
            }
            .encode(),
        )
        .await
        .unwrap();
        client
    }

    fn pkt(src: &IdentityKeypair, dest: &IdentityKeypair, payload: &[u8]) -> Vec<u8> {
        ghost_protocol::Packet::new(
            ghost_protocol::PacketType::Data,
            src.node_id(),
            dest.node_id(),
            1,
            payload.to_vec(),
        )
        .encode()
        .to_vec()
    }

    #[tokio::test]
    async fn forwards_between_registered_nodes_and_refuses_spoofing() {
        let server = RelayServer::new(IdentityKeypair::generate().unwrap(), RelayConfig::default());
        let a = IdentityKeypair::generate().unwrap();
        let b = IdentityKeypair::generate().unwrap();
        let mut ca = connect(&server, &a).await;
        let mut cb = connect(&server, &b).await;
        assert_eq!(
            RelayFrame::decode(&read_frame(&mut ca).await.unwrap()).unwrap(),
            RelayFrame::Registered
        );
        assert_eq!(
            RelayFrame::decode(&read_frame(&mut cb).await.unwrap()).unwrap(),
            RelayFrame::Registered
        );

        // A spoofed source is dropped, a genuine packet goes through.
        let spoof = pkt(&b, &a, b"spoofed");
        write_frame(&mut ca, &RelayFrame::Packet(spoof).encode())
            .await
            .unwrap();
        let good = pkt(&a, &b, b"sealed-bytes");
        write_frame(&mut ca, &RelayFrame::Packet(good.clone()).encode())
            .await
            .unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut cb))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(RelayFrame::decode(&got).unwrap(), RelayFrame::Packet(good));
        assert_eq!(server.stats.dropped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn wrong_key_is_rejected() {
        let server = RelayServer::new(IdentityKeypair::generate().unwrap(), RelayConfig::default());
        let real = IdentityKeypair::generate().unwrap();
        let eve = IdentityKeypair::generate().unwrap();
        // Eve claims the identity of `real` but proves with her own key.
        let (mut client, srv) = duplex(64 * 1024);
        let s = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = s.handle(srv, "127.0.0.1".parse().unwrap()).await;
        });
        let body = read_frame(&mut client).await.unwrap();
        let RelayFrame::Hello {
            challenge,
            relay_public,
            ..
        } = RelayFrame::decode(&body).unwrap()
        else {
            panic!()
        };
        let proof = relay_proof(
            &eve.private,
            &relay_public,
            &challenge,
            &real.public,
            &relay_public,
        )
        .unwrap();
        write_frame(
            &mut client,
            &RelayFrame::Register {
                node_public: real.public,
                proof,
            }
            .encode(),
        )
        .await
        .unwrap();
        let reply = RelayFrame::decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(reply, RelayFrame::Error(ERR_BAD_PROOF));
        assert_eq!(server.connected_nodes(), 0);
    }

    #[tokio::test]
    async fn per_ip_limit() {
        let cfg = RelayConfig {
            max_per_ip: 1,
            ..Default::default()
        };
        let server = RelayServer::new(IdentityKeypair::generate().unwrap(), cfg);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let first = server.admit(ip);
        assert!(first.is_some());
        assert!(server.admit(ip).is_none());
        drop(first);
        assert!(server.admit(ip).is_some());
    }

    #[test]
    fn bucket_limits_bursts() {
        let mut b = Bucket::new(1000, 2000);
        assert!(b.take(1500));
        assert!(!b.take(1500));
    }
}
