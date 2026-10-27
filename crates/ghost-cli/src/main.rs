use clap::{Parser, Subcommand};
use ghost_core::MeshEngine;
use ghost_crypto::IdentityKeypair;
use ghost_nat::DEFAULT_STUN_SERVER;
use ghost_protocol::{InviteTicket, NodeId, PacketType};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

const GHOSTDROP_MAGIC: &[u8; 4] = b"GD01";
const DEFAULT_GHOSTDROP_PORT: u16 = 4243;
const CHUNK_SIZE: usize = 128 * 1024;

#[derive(Parser, Debug)]
#[command(name = "ghostmesh")]
#[command(author = "NeyorDEV")]
#[command(version = "0.1.3")]
#[command(about = "Decentralized P2P Encrypted Mesh Overlay & Direct File Transfer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a fresh cryptographic identity keypair (Curve25519)
    Keygen,

    /// Query public STUN server to discover local NAT reflexive endpoint
    Discover {
        #[arg(short, long, default_value_t = 0)]
        port: u16,
        #[arg(short, long, default_value = DEFAULT_STUN_SERVER)]
        stun: String,
    },

    /// Generate an invitation ticket and wait for incoming P2P connection
    Invite {
        #[arg(short, long, default_value_t = 4242)]
        port: u16,
        /// Virtual mesh IP to assign (e.g. 10.42.0.1)
        #[arg(long)]
        ip: Option<Ipv4Addr>,
    },

    /// Join a remote peer using an invitation ticket (UDP hole punching)
    Join {
        /// The invite ticket string starting with gm1_
        ticket: String,
        #[arg(short, long, default_value_t = 0)]
        port: u16,
        /// Virtual mesh IP to assign (e.g. 10.42.0.2)
        #[arg(long)]
        ip: Option<Ipv4Addr>,
    },

    /// Run the GhostMesh node engine
    Up {
        #[arg(short, long, default_value_t = 4242)]
        port: u16,
        /// Virtual mesh IP to assign (e.g. 10.42.0.1)
        #[arg(long)]
        ip: Option<Ipv4Addr>,
    },

    /// Send a file directly to a peer via GhostDrop P2P streaming
    Send {
        /// Target peer address (IP or IP:Port)
        target: String,
        /// Path to the local file to send
        file: String,
        /// Custom GhostDrop port (default: 4243)
        #[arg(short, long, default_value_t = DEFAULT_GHOSTDROP_PORT)]
        port: u16,
    },

    /// Receive files using the GhostDrop P2P listener
    Receive {
        /// Listening port (default: 4243)
        #[arg(short, long, default_value_t = DEFAULT_GHOSTDROP_PORT)]
        port: u16,
        /// Destination directory for received files
        #[arg(short, long)]
        dir: Option<String>,
    },

    /// Continuously watch and synchronize a local folder with connected peers
    Sync {
        /// Local folder path to watch and synchronize
        dir: String,
        /// Optional target peer address to sync with
        #[arg(short, long)]
        target: Option<String>,
        /// GhostDrop port (default: 4243)
        #[arg(short, long, default_value_t = DEFAULT_GHOSTDROP_PORT)]
        port: u16,
    },

    /// Ping a remote peer directly over UDP
    Ping {
        #[arg(short, long)]
        target_id: String,
        #[arg(short, long)]
        endpoint: SocketAddr,
        #[arg(short, long, default_value_t = 4242)]
        local_port: u16,
    },
}

fn get_default_transfers_dir() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(profile).join("Downloads").join("GhostMesh-Transfers");
        let _ = std::fs::create_dir_all(&p);
        p
    } else {
        let p = PathBuf::from("GhostMesh-Transfers");
        let _ = std::fs::create_dir_all(&p);
        p
    }
}

async fn try_setup_tun(engine: &Arc<MeshEngine>, virtual_ip: Option<Ipv4Addr>) {
    if let Some(ip) = virtual_ip {
        let netmask = Ipv4Addr::new(255, 255, 0, 0);
        match engine.enable_virtual_interface(ip, netmask).await {
            Ok(_) => {
                println!("[NET] Virtual Adapter Active: ghost0 -> {}/16", ip);
            }
            Err(e) => {
                warn!("Could not activate virtual TUN device: {e}");
                println!("[NOTE] Run terminal as Administrator to enable Wintun virtual network adapter.");
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let keypair = IdentityKeypair::generate()?;
            println!("[GHOSTMESH] Cryptographic Identity Generated");
            println!("----------------------------------------------------------------------------");
            println!("Node ID    : {}", keypair.node_id());
            println!("Public Key : {}", keypair.public_hex());
            println!("----------------------------------------------------------------------------");
            println!("Keep your private keys secure!");
        }

        Commands::Discover { port, stun } => {
            let socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
            let local_addr = socket.local_addr()?;
            info!("Bound local socket on {local_addr}");
            info!("Querying STUN server {stun}...");

            match ghost_nat::discover_public_endpoint(&socket, &stun, Duration::from_secs(3)).await {
                Ok(public_endpoint) => {
                    println!("\n[OK] NAT Traversal Discovery Success");
                    println!("----------------------------------------------------------------------------");
                    println!("Local Socket   : {local_addr}");
                    println!("Public Endpoint: {public_endpoint}");
                    println!("----------------------------------------------------------------------------");
                }
                Err(e) => {
                    error!("STUN discovery failed: {e}");
                }
            }
        }

        Commands::Invite { port, ip } => {
            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            let ticket = engine.create_invite();
            let ticket_str = ticket.to_ticket_string();

            println!("\n[GHOSTMESH] Invitation Ready");
            println!("----------------------------------------------------------------------------");
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            if let Some(vip) = ip {
                println!("Mesh Virtual IP: {} (10.42.0.0/16)", vip);
            }
            println!("\nShare this ticket with your peer:");
            println!("\x1b[1;36m{}\x1b[0m", ticket_str);
            println!("----------------------------------------------------------------------------");
            println!("Run the following command on the other machine to connect:");
            println!("  ghostmesh join {}", ticket_str);
            println!("\nListening for incoming direct P2P connection... (Ctrl+C to quit)\n");

            let engine_clone = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_clone.run_receive_loop().await;
            });

            engine.start_background_tasks().await;
            tokio::signal::ctrl_c().await?;
            info!("Shutting down invite listener.");
        }

        Commands::Join { ticket, port, ip } => {
            let parsed_ticket: InviteTicket = ticket.parse()
                .map_err(|e| anyhow::anyhow!("Invalid invite ticket: {e}"))?;

            println!("\nConnecting to GhostMesh Peer...");
            println!("----------------------------------------------------------------------------");
            println!("Target Node ID : {}", parsed_ticket.node_id);
            println!("Target Endpoint: {}", parsed_ticket.endpoint);
            println!("----------------------------------------------------------------------------");

            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            engine.map_peer_virtual_ip(parsed_ticket.node_id, Ipv4Addr::new(10, 42, 0, 1)).await;

            let engine_recv = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_recv.run_receive_loop().await;
            });

            engine.start_background_tasks().await;
            engine.join_ticket(parsed_ticket).await?;

            println!("[OK] UDP hole-punching probes dispatched. Direct tunnel negotiation active.\n");

            tokio::signal::ctrl_c().await?;
            info!("Exiting GhostMesh.");
        }

        Commands::Up { port, ip } => {
            info!("Starting GhostMesh daemon on port {port}...");
            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            println!("\n[GHOSTMESH] Node Running");
            println!("----------------------------------------------------------------------------");
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            println!("Local Port     : {port}");
            if let Some(vip) = ip {
                println!("Mesh Virtual IP: {} (10.42.0.0/16)", vip);
            }
            println!("----------------------------------------------------------------------------");
            println!("Press Ctrl+C to terminate.\n");

            let engine_clone = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_clone.run_receive_loop().await;
            });

            engine.start_background_tasks().await;
            tokio::signal::ctrl_c().await?;
            info!("Shutting down GhostMesh node.");
        }

        Commands::Send { target, file, port } => {
            let path = Path::new(&file);
            if !path.exists() {
                anyhow::bail!("File not found: {file}");
            }

            let metadata = tokio::fs::metadata(path).await?;
            let total_size = metadata.len();
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?
                .to_string();

            let target_addr = if target.contains(':') {
                target
            } else {
                format!("{target}:{port}")
            };

            println!("\n[GHOSTDROP] Preparing high-speed P2P transfer");
            println!("----------------------------------------------------------------------------");
            println!("File     : {} ({:.2} MB)", filename, total_size as f64 / 1_000_000.0);
            println!("Target   : {}", target_addr);
            println!("Connecting...");

            let mut socket = TcpStream::connect(&target_addr).await
                .map_err(|e| anyhow::anyhow!("Failed to connect to {target_addr}: {e}"))?;

            socket.write_all(GHOSTDROP_MAGIC).await?;
            socket.write_u64(total_size).await?;
            let fn_bytes = filename.as_bytes();
            socket.write_u16(fn_bytes.len() as u16).await?;
            socket.write_all(fn_bytes).await?;

            let mut f = tokio::fs::File::open(path).await?;
            let mut buffer = vec![0u8; CHUNK_SIZE];
            let mut transferred = 0u64;
            let start = Instant::now();
            let mut last_log = Instant::now();
            let mut bytes_since = 0u64;

            while transferred < total_size {
                let n = f.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                socket.write_all(&buffer[..n]).await?;
                transferred += n as u64;
                bytes_since += n as u64;

                if last_log.elapsed().as_millis() >= 250 || transferred == total_size {
                    let sec = last_log.elapsed().as_secs_f64().max(0.001);
                    let mbps = (bytes_since as f64 / 1_000_000.0) / sec;
                    let pct = (transferred as f64 / total_size as f64) * 100.0;
                    let cur_mb = transferred as f64 / 1_000_000.0;
                    let tot_mb = total_size as f64 / 1_000_000.0;

                    let bar_len: usize = 30;
                    let filled = ((pct / 100.0) * bar_len as f64).round() as usize;
                    let empty = bar_len.saturating_sub(filled);
                    let bar = format!("[{}{}]", "=".repeat(filled), " ".repeat(empty));

                    print!("\rSending: {} {:.1}% ({:.1}/{:.1} MB) - {:.1} MB/s  ", bar, pct, cur_mb, tot_mb, mbps);
                    let _ = std::io::stdout().flush();

                    last_log = Instant::now();
                    bytes_since = 0;
                }
            }

            socket.flush().await?;
            let elapsed = start.elapsed().as_secs_f64().max(0.001);
            let avg_speed = (transferred as f64 / 1_000_000.0) / elapsed;

            println!("\n----------------------------------------------------------------------------");
            println!("[OK] File '{}' sent successfully in {:.1}s (avg {:.1} MB/s)\n", filename, elapsed, avg_speed);
        }

        Commands::Receive { port, dir } => {
            let out_dir = match dir {
                Some(d) => {
                    let p = PathBuf::from(d);
                    let _ = std::fs::create_dir_all(&p);
                    p
                }
                None => get_default_transfers_dir(),
            };

            let bind_addr = format!("0.0.0.0:{port}");
            let listener = TcpListener::bind(&bind_addr).await
                .map_err(|e| anyhow::anyhow!("Failed to bind on {bind_addr}: {e}"))?;

            println!("\n[GHOSTDROP] Receiver daemon active");
            println!("----------------------------------------------------------------------------");
            println!("Listening on : {}", bind_addr);
            println!("Saving to    : {:?}", out_dir);
            println!("Waiting for incoming P2P transfers... (Ctrl+C to quit)\n");

            loop {
                let (mut socket, peer_addr) = listener.accept().await?;
                let out_dir_clone = out_dir.clone();

                tokio::spawn(async move {
                    println!("[GHOSTDROP] Incoming connection from {}", peer_addr);
                    let mut magic = [0u8; 4];
                    if let Err(e) = socket.read_exact(&mut magic).await {
                        eprintln!("[ERROR] Read error: {e}");
                        return;
                    }
                    if &magic != GHOSTDROP_MAGIC {
                        eprintln!("[ERROR] Invalid magic header from {peer_addr}");
                        return;
                    }

                    let total_size = match socket.read_u64().await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[ERROR] Size read error: {e}");
                            return;
                        }
                    };

                    let fn_len = match socket.read_u16().await {
                        Ok(l) => l as usize,
                        Err(e) => {
                            eprintln!("[ERROR] Filename length read error: {e}");
                            return;
                        }
                    };

                    let mut fn_bytes = vec![0u8; fn_len];
                    if let Err(e) = socket.read_exact(&mut fn_bytes).await {
                        eprintln!("[ERROR] Filename read error: {e}");
                        return;
                    }
                    let raw_fn = String::from_utf8_lossy(&fn_bytes).to_string();
                    let safe_fn = Path::new(&raw_fn)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("received_file.bin")
                        .to_string();

                    let dest = out_dir_clone.join(&safe_fn);
                    println!("Receiving '{}' ({:.2} MB) from {}...", safe_fn, total_size as f64 / 1_000_000.0, peer_addr);

                    let mut out_file = match tokio::fs::File::create(&dest).await {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("[ERROR] Cannot create file {:?}: {e}", dest);
                            return;
                        }
                    };

                    let mut buffer = vec![0u8; CHUNK_SIZE];
                    let mut transferred = 0u64;
                    let start = Instant::now();

                    while transferred < total_size {
                        let to_read = std::cmp::min(buffer.len() as u64, total_size - transferred) as usize;
                        let n = match socket.read(&mut buffer[..to_read]).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("[ERROR] Read error: {e}");
                                break;
                            }
                        };
                        if let Err(e) = out_file.write_all(&buffer[..n]).await {
                            eprintln!("[ERROR] Write error: {e}");
                            break;
                        }
                        transferred += n as u64;
                    }

                    let _ = out_file.flush().await;
                    let elapsed = start.elapsed().as_secs_f64().max(0.001);
                    let avg = (transferred as f64 / 1_000_000.0) / elapsed;
                    println!("[OK] Finished receiving '{}' in {:.1}s (avg {:.1} MB/s). Saved to {:?}", safe_fn, elapsed, avg, dest);
                });
            }
        }

        Commands::Sync { dir, target, port: _ } => {
            let sync_engine = ghost_core::GhostSyncEngine::new();
            sync_engine.set_watched_directory(&dir).await.map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("\n[GHOSTSYNC] Real-time folder synchronization active");
            println!("----------------------------------------------------------------------------");
            println!("Watching folder : {}", dir);
            if let Some(ref t) = target {
                println!("Target peer     : {}", t);
            }
            println!("Monitoring file modifications... (Press Ctrl+C to terminate)\n");

            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                let changed = sync_engine.scan_and_detect_changes().await;
                for file_path in changed {
                    println!("[SYNC] File changed: {:?} (Ready for P2P sync)", file_path);
                }
            }
        }

        Commands::Ping {
            target_id,
            endpoint,
            local_port,
        } => {
            let dest_node: NodeId = target_id.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let engine = Arc::new(MeshEngine::bind(local_port).await?);
            engine.add_peer(dest_node, endpoint).await;

            info!("Sending handshake probe to {dest_node} at {endpoint}...");
            engine
                .send_packet(dest_node, PacketType::HandshakeInit, &[])
                .await?;

            println!("[OK] Handshake probe dispatched successfully to {endpoint}");
        }
    }

    Ok(())
}
