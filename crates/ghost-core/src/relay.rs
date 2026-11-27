//! Relay client: keeps one authenticated connection to a relay server (trying the configured
//! relays in turn, with growing back-off), writes outgoing sealed packets to it and injects every
//! packet it receives into the engine. Relayed packets are checked exactly like direct ones.

use crate::config::RelayEndpoint;
use crate::MeshEngine;
use ghost_crypto::{ct_eq32, relay_proof};
use ghost_protocol::relay::{RelayFrame, MAX_RELAY_FRAME, RELAY_VERSION};
use ghost_protocol::{NodeId, Packet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub const DEFAULT_RELAY_PORT: u16 = 8443;

/// Placeholder "remote address" attached to packets delivered by the relay.
pub const RELAY_REMOTE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

const MAX_BACKOFF: Duration = Duration::from_secs(60);
const PING_EVERY: Duration = Duration::from_secs(25);
/// A session that lasted this long resets the back-off.
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// Handle used by the engine to push sealed packets towards the relay.
#[derive(Clone)]
pub struct RelayClient {
    connected: Arc<AtomicBool>,
    current: Arc<Mutex<Option<String>>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl RelayClient {
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Address of the relay currently in use, if connected.
    pub fn current_relay(&self) -> Option<String> {
        self.current.lock().ok().and_then(|g| g.clone())
    }

    /// Outbound channel carrying raw encoded packets (used as the "link" of relayed packets).
    pub(crate) fn link(&self) -> mpsc::Sender<Vec<u8>> {
        self.tx.clone()
    }

    pub async fn send_relayed_packet(&self, packet: &Packet) -> Result<(), String> {
        if !self.is_connected() {
            return Err("Relay client is not connected".into());
        }
        self.tx
            .try_send(packet.encode().to_vec())
            .map_err(|e| format!("Failed to queue relayed packet: {e}"))
    }
}

async fn read_frame<R: AsyncRead + Unpin>(rd: &mut R) -> std::io::Result<Vec<u8>> {
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

async fn write_frame<W: AsyncWrite + Unpin>(wr: &mut W, frame: &RelayFrame) -> std::io::Result<()> {
    let body = frame.encode();
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    wr.write_all(&out).await
}

fn io_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

impl MeshEngine {
    /// Starts the relay client with the given relays (tried in order, then round-robin).
    /// Does nothing when the list is empty.
    pub async fn start_relays(self: &Arc<Self>, relays: Vec<RelayEndpoint>) {
        if relays.is_empty() {
            return;
        }
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let client = RelayClient {
            connected: Arc::new(AtomicBool::new(false)),
            current: Arc::new(Mutex::new(None)),
            tx,
        };
        *self.relay.write().await = Some(client.clone());
        tokio::spawn(run(Arc::clone(self), relays, rx, client));
    }
}

async fn run(
    engine: Arc<MeshEngine>,
    relays: Vec<RelayEndpoint>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    client: RelayClient,
) {
    let mut backoff = Duration::from_secs(1);
    let mut index = 0usize;
    loop {
        let relay = &relays[index % relays.len()];
        index += 1;
        let started = Instant::now();
        match session(&engine, relay, &mut rx, &client).await {
            Ok(()) => info!("relay {} closed the connection", relay.addr),
            Err(e) => warn!("relay {} unavailable: {e}", relay.addr),
        }
        client.connected.store(false, Ordering::Relaxed);
        if let Ok(mut g) = client.current.lock() {
            *g = None;
        }
        // Whatever was queued for the dead connection is stale: sealed packets are re-sent by the sender.
        while rx.try_recv().is_ok() {}

        if started.elapsed() >= STABLE_AFTER {
            backoff = Duration::from_secs(1);
        }
        let jitter = Duration::from_millis(u64::from(rand_u8()) * 4);
        tokio::time::sleep(backoff + jitter).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn rand_u8() -> u8 {
    use rand::RngCore;
    (rand::thread_rng().next_u32() & 0xFF) as u8
}

async fn session(
    engine: &Arc<MeshEngine>,
    relay: &RelayEndpoint,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    client: &RelayClient,
) -> std::io::Result<()> {
    let pinned = relay.key_bytes().map_err(io_err)?;
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&relay.addr))
        .await
        .map_err(|_| io_err("connect timeout"))??;
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();

    let hello = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut rd))
        .await
        .map_err(|_| io_err("no hello from relay"))??;
    let Ok(RelayFrame::Hello {
        version,
        challenge,
        relay_public,
    }) = RelayFrame::decode(&hello)
    else {
        return Err(io_err("relay did not send a hello"));
    };
    if version != RELAY_VERSION {
        return Err(io_err(format!(
            "unsupported relay protocol version {version}"
        )));
    }
    if !ct_eq32(&relay_public, &pinned) {
        return Err(io_err("relay public key does not match the pinned key"));
    }
    let me = &engine.identity;
    let proof = relay_proof(
        &me.private,
        &relay_public,
        &challenge,
        &me.public,
        &relay_public,
    )
    .ok_or_else(|| io_err("cannot derive relay proof"))?;
    write_frame(
        &mut wr,
        &RelayFrame::Register {
            node_public: me.public,
            proof,
        },
    )
    .await?;

    let reply = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut rd))
        .await
        .map_err(|_| io_err("relay did not answer the registration"))??;
    match RelayFrame::decode(&reply) {
        Ok(RelayFrame::Registered) => {}
        Ok(RelayFrame::Error(code)) => {
            return Err(io_err(format!(
                "relay refused the registration (code {code})"
            )))
        }
        _ => return Err(io_err("unexpected answer to registration")),
    }

    client.connected.store(true, Ordering::Relaxed);
    if let Ok(mut g) = client.current.lock() {
        *g = Some(relay.addr.clone());
    }
    info!("registered with relay {}", relay.addr);

    let link = client.link();
    let reader_engine = Arc::clone(engine);
    let mut reader = tokio::spawn(async move {
        loop {
            let body = read_frame(&mut rd).await?;
            match RelayFrame::decode(&body) {
                Ok(RelayFrame::Packet(raw)) => {
                    if let Ok(packet) = Packet::decode(&raw) {
                        reader_engine.note_relay_rx();
                        reader_engine
                            .handle_packet(packet, RELAY_REMOTE, Some(link.clone()))
                            .await;
                    }
                }
                Ok(RelayFrame::Error(code)) => return Err(io_err(format!("relay error {code}"))),
                _ => {}
            }
        }
    });

    let mut ping = tokio::time::interval(PING_EVERY);
    let result: std::io::Result<()> = loop {
        tokio::select! {
            r = &mut reader => {
                break match r {
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(())) | Err(_) => Ok(()),
                };
            }
            data = rx.recv() => {
                let Some(raw) = data else { break Ok(()) };
                if let Err(e) = write_frame(&mut wr, &RelayFrame::Packet(raw)).await {
                    break Err(e);
                }
            }
            _ = ping.tick() => {
                if let Err(e) = write_frame(&mut wr, &RelayFrame::Ping).await {
                    break Err(e);
                }
            }
        }
    };
    reader.abort();
    result
}

/// NodeId helper kept here so callers of the relay API do not need ghost-protocol internals.
pub fn node_of_public(public: &[u8; 32]) -> NodeId {
    let mut id = [0u8; 16];
    id.copy_from_slice(&public[..16]);
    NodeId::new(id)
}
