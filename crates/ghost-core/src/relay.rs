use ghost_protocol::{NodeId, Packet};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

pub const DEFAULT_RELAY_PORT: u16 = 8443;

/// Lightweight relay client fallback used when UDP is strictly blocked (e.g. corporate firewalls).
#[derive(Clone)]
pub struct RelayClient {
    pub relay_addr: String,
    pub is_connected: Arc<RwLock<bool>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl RelayClient {
    pub async fn start(
        relay_addr: String,
        local_node: NodeId,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        let is_connected = Arc::new(RwLock::new(false));
        let is_conn_clone = Arc::clone(&is_connected);

        let addr = relay_addr.clone();
        tokio::spawn(async move {
            info!("Relay client attempting connection to fallback relay {addr}...");
            match TcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    // Handshake registration with relay
                    let mut reg_msg = Vec::with_capacity(20);
                    reg_msg.extend_from_slice(b"GREL"); // Ghost Relay Magic
                    reg_msg.extend_from_slice(local_node.as_bytes());

                    if let Err(e) = stream.write_all(&reg_msg).await {
                        error!("Failed to register with relay: {e}");
                        return;
                    }

                    {
                        let mut guard = is_conn_clone.write().await;
                        *guard = true;
                    }
                    info!("Registered with fallback relay at {addr}. Relay tunnel active.");

                    // Outbound worker
                    while let Some(data) = rx.recv().await {
                        let len = (data.len() as u32).to_be_bytes();
                        if let Err(e) = stream.write_all(&len).await {
                            error!("Relay write error: {e}");
                            break;
                        }
                        if let Err(e) = stream.write_all(&data).await {
                            error!("Relay write payload error: {e}");
                            break;
                        }
                    }

                    let mut guard = is_conn_clone.write().await;
                    *guard = false;
                }
                Err(e) => {
                    warn!("Fallback relay unreachable at {addr}: {e}");
                }
            }
        });

        Ok(Self {
            relay_addr,
            is_connected,
            tx,
        })
    }

    pub async fn send_relayed_packet(&self, packet: &Packet) -> Result<(), String> {
        let is_conn = *self.is_connected.read().await;
        if !is_conn {
            return Err("Relay client is not connected".into());
        }

        let encoded = packet.encode();
        self.tx
            .send(encoded.to_vec())
            .await
            .map_err(|e| format!("Failed to queue relayed packet: {e}"))
    }
}
