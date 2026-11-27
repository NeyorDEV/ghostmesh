//! Rendezvous server: stores the latest signed address record of each node, in memory only.
//!
//! It checks the signature and freshness of what it stores, refuses replays, and answers lookups
//! for one known NodeId at a time. It cannot list nodes and cannot forge or alter a record
//! (consumers verify the node's own signature).

use crate::{read_frame, write_frame};
use ghost_crypto::xeddsa_verify;
use ghost_protocol::rendezvous::{
    RdvFrame, SignedRecord, ERR_FULL, ERR_INVALID, ERR_RATE, ERR_STALE,
};
use ghost_protocol::NodeId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct RendezvousConfig {
    pub max_records: usize,
    pub max_connections: usize,
    pub publishes_per_minute: u32,
    pub lookups_per_minute: u32,
    /// How far in the future a record's issue time may be (clock skew allowance).
    pub max_future_skew_secs: u64,
    pub request_timeout: Duration,
}

impl Default for RendezvousConfig {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            max_connections: 1024,
            publishes_per_minute: 30,
            lookups_per_minute: 120,
            max_future_skew_secs: 300,
            request_timeout: Duration::from_secs(5),
        }
    }
}

struct Stored {
    signed: SignedRecord,
    issued_at: u64,
    expires: Instant,
}

struct Window {
    started: Instant,
    publishes: u32,
    lookups: u32,
}

pub struct RendezvousServer {
    cfg: RendezvousConfig,
    records: Mutex<HashMap<NodeId, Stored>>,
    windows: Mutex<HashMap<IpAddr, Window>>,
    active: AtomicUsize,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl RendezvousServer {
    pub fn new(cfg: RendezvousConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            records: Mutex::new(HashMap::new()),
            windows: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
        })
    }

    pub fn record_count(&self) -> usize {
        self.records.lock().map(|r| r.len()).unwrap_or(0)
    }

    fn rate_ok(&self, ip: IpAddr, publish: bool) -> bool {
        let Ok(mut w) = self.windows.lock() else {
            return false;
        };
        if w.len() > 50_000 {
            w.retain(|_, v| v.started.elapsed() < Duration::from_secs(60));
        }
        let win = w.entry(ip).or_insert(Window {
            started: Instant::now(),
            publishes: 0,
            lookups: 0,
        });
        if win.started.elapsed() >= Duration::from_secs(60) {
            *win = Window {
                started: Instant::now(),
                publishes: 0,
                lookups: 0,
            };
        }
        if publish {
            win.publishes += 1;
            win.publishes <= self.cfg.publishes_per_minute
        } else {
            win.lookups += 1;
            win.lookups <= self.cfg.lookups_per_minute
        }
    }

    pub fn publish(&self, ip: IpAddr, signed: SignedRecord) -> Result<(), u8> {
        if !self.rate_ok(ip, true) {
            return Err(ERR_RATE);
        }
        let record = signed.record().map_err(|_| ERR_INVALID)?;
        if !xeddsa_verify(&record.node_public, &signed.body, &signed.signature) {
            return Err(ERR_INVALID);
        }
        let now = unix_now();
        if record.issued_at > now + self.cfg.max_future_skew_secs
            || record.issued_at + u64::from(record.ttl_secs) <= now
        {
            return Err(ERR_STALE);
        }
        let id = record.node_id();
        let mut map = self.records.lock().map_err(|_| ERR_FULL)?;
        if let Some(old) = map.get(&id) {
            // Anti-replay: only strictly newer records replace what is stored.
            if old.expires > Instant::now() && record.issued_at <= old.issued_at {
                return Err(ERR_STALE);
            }
        }
        if map.len() >= self.cfg.max_records && !map.contains_key(&id) {
            map.retain(|_, s| s.expires > Instant::now());
            if map.len() >= self.cfg.max_records {
                return Err(ERR_FULL);
            }
        }
        let remaining = (record.issued_at + u64::from(record.ttl_secs)).saturating_sub(now);
        map.insert(
            id,
            Stored {
                signed,
                issued_at: record.issued_at,
                expires: Instant::now() + Duration::from_secs(remaining),
            },
        );
        Ok(())
    }

    pub fn lookup(&self, ip: IpAddr, id: &NodeId) -> Result<Option<SignedRecord>, u8> {
        if !self.rate_ok(ip, false) {
            return Err(ERR_RATE);
        }
        let mut map = self.records.lock().map_err(|_| ERR_FULL)?;
        match map.get(id) {
            Some(s) if s.expires > Instant::now() => Ok(Some(s.signed.clone())),
            Some(_) => {
                map.remove(id);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    if self.active.load(Ordering::Relaxed) >= self.cfg.max_connections {
                        continue;
                    }
                    self.active.fetch_add(1, Ordering::Relaxed);
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle(stream, addr.ip()).await {
                            debug!("rendezvous request from {addr} failed: {e}");
                        }
                        server.active.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    warn!("rendezvous accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Answers one request on any byte stream.
    pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        ip: IpAddr,
    ) -> std::io::Result<()> {
        let body = tokio::time::timeout(self.cfg.request_timeout, read_frame(&mut stream))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request timeout"))??;
        let answer = match RdvFrame::decode(&body) {
            Ok(RdvFrame::Publish(signed)) => match self.publish(ip, signed) {
                Ok(()) => RdvFrame::Ok,
                Err(code) => RdvFrame::Error(code),
            },
            Ok(RdvFrame::Lookup(id)) => match self.lookup(ip, &id) {
                Ok(Some(r)) => RdvFrame::Record(r),
                Ok(None) => RdvFrame::NotFound,
                Err(code) => RdvFrame::Error(code),
            },
            _ => RdvFrame::Error(ERR_INVALID),
        };
        write_frame(&mut stream, &answer.encode()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_crypto::{xeddsa_sign, IdentityKeypair};
    use ghost_protocol::rendezvous::RendezvousRecord;

    fn signed(id: &IdentityKeypair, issued_at: u64, ttl: u32, addr: &str) -> SignedRecord {
        let body = RendezvousRecord {
            node_public: id.public,
            issued_at,
            ttl_secs: ttl,
            addrs: vec![addr.parse().unwrap()],
        }
        .encode();
        let signature = xeddsa_sign(&id.private, &body);
        SignedRecord { body, signature }
    }

    const IP: &str = "198.51.100.7";

    #[test]
    fn publish_lookup_and_replay() {
        let srv = RendezvousServer::new(RendezvousConfig::default());
        let ip: IpAddr = IP.parse().unwrap();
        let id = IdentityKeypair::generate().unwrap();
        let now = unix_now();

        let first = signed(&id, now, 600, "203.0.113.1:4242");
        assert_eq!(srv.publish(ip, first.clone()), Ok(()));
        assert_eq!(srv.lookup(ip, &id.node_id()).unwrap(), Some(first.clone()));

        // Replaying the same or an older record is refused.
        assert_eq!(srv.publish(ip, first), Err(ERR_STALE));
        assert_eq!(
            srv.publish(ip, signed(&id, now - 5, 600, "203.0.113.9:1")),
            Err(ERR_STALE)
        );

        // A newer record replaces it.
        let newer = signed(&id, now + 1, 600, "203.0.113.2:4242");
        assert_eq!(srv.publish(ip, newer.clone()), Ok(()));
        assert_eq!(srv.lookup(ip, &id.node_id()).unwrap(), Some(newer));
    }

    #[test]
    fn rejects_forgery_expiry_and_unknown_nodes() {
        let srv = RendezvousServer::new(RendezvousConfig::default());
        let ip: IpAddr = IP.parse().unwrap();
        let id = IdentityKeypair::generate().unwrap();
        let eve = IdentityKeypair::generate().unwrap();
        let now = unix_now();

        // Signed by someone else but claiming id's key.
        let mut forged = signed(&id, now, 600, "203.0.113.1:1");
        forged.signature = signed(&eve, now, 600, "203.0.113.1:1").signature;
        assert_eq!(srv.publish(ip, forged), Err(ERR_INVALID));
        // Tampered body.
        let mut tampered = signed(&id, now, 600, "203.0.113.1:1");
        let last = tampered.body.len() - 1;
        tampered.body[last] ^= 1;
        assert_eq!(srv.publish(ip, tampered), Err(ERR_INVALID));
        // Expired and far-future records.
        assert_eq!(
            srv.publish(ip, signed(&id, now - 1000, 600, "203.0.113.1:1")),
            Err(ERR_STALE)
        );
        assert_eq!(
            srv.publish(ip, signed(&id, now + 10_000, 600, "203.0.113.1:1")),
            Err(ERR_STALE)
        );

        assert_eq!(srv.lookup(ip, &id.node_id()).unwrap(), None);
        assert_eq!(srv.record_count(), 0);
    }

    #[test]
    fn rate_limit_per_ip() {
        let cfg = RendezvousConfig {
            lookups_per_minute: 3,
            ..Default::default()
        };
        let srv = RendezvousServer::new(cfg);
        let ip: IpAddr = IP.parse().unwrap();
        let id = NodeId::new([1; 16]);
        for _ in 0..3 {
            assert!(srv.lookup(ip, &id).is_ok());
        }
        assert_eq!(srv.lookup(ip, &id), Err(ERR_RATE));
        let other: IpAddr = "198.51.100.8".parse().unwrap();
        assert!(srv.lookup(other, &id).is_ok());
    }

    #[tokio::test]
    async fn garbage_requests_get_an_error_not_a_panic() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let srv = RendezvousServer::new(RendezvousConfig::default());
        let (mut client, server_side) = tokio::io::duplex(4096);
        let s = Arc::clone(&srv);
        tokio::spawn(async move {
            let _ = s.handle(server_side, IP.parse().unwrap()).await;
        });
        client.write_all(&[0, 3, 0xFF, 0xEE, 0xDD]).await.unwrap();
        let mut out = vec![0u8; 8];
        let n = client.read(&mut out).await.unwrap();
        assert!(n >= 4);
        assert_eq!(
            RdvFrame::decode(&out[2..n]).unwrap(),
            RdvFrame::Error(ERR_INVALID)
        );
    }
}
