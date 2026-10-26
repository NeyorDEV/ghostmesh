use clap::{Parser, Subcommand};
use ghost_core::MeshEngine;
use ghost_crypto::IdentityKeypair;
use ghost_nat::DEFAULT_STUN_SERVER;
use ghost_protocol::{InviteTicket, NodeId, PacketType};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ghostmesh")]
#[command(author = "NeyorDEV")]
#[command(version = "0.1.0")]
#[command(about = "Decentralized P2P Encrypted Mesh Overlay", long_about = None)]
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

async fn try_setup_tun(engine: &Arc<MeshEngine>, virtual_ip: Option<Ipv4Addr>) {
    if let Some(ip) = virtual_ip {
        let netmask = Ipv4Addr::new(255, 255, 0, 0);
        match engine.enable_virtual_interface(ip, netmask).await {
            Ok(_) => {
                println!("🌐 Virtual Adapter Active: ghost0 -> {}/16", ip);
            }
            Err(e) => {
                warn!("Could not activate virtual TUN device: {e}");
                println!("⚠️ Note: Run terminal as Administrator to enable Wintun virtual network adapter.");
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
            println!("👻 GhostMesh Cryptographic Identity Generated");
            println!("──────────────────────────────────────────────");
            println!("Node ID    : {}", keypair.node_id());
            println!("Public Key : {}", keypair.public_hex());
            println!("──────────────────────────────────────────────");
            println!("Keep your private keys secure!");
        }

        Commands::Discover { port, stun } => {
            let socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
            let local_addr = socket.local_addr()?;
            info!("Bound local socket on {local_addr}");
            info!("Querying STUN server {stun}...");

            match ghost_nat::discover_public_endpoint(&socket, &stun, Duration::from_secs(3)).await {
                Ok(public_endpoint) => {
                    println!("\n✅ NAT Traversal Discovery Success");
                    println!("──────────────────────────────────────────────");
                    println!("Local Socket   : {local_addr}");
                    println!("Public Endpoint: {public_endpoint}");
                    println!("──────────────────────────────────────────────");
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

            println!("\n👻 GhostMesh Invitation Ready");
            println!("────────────────────────────────────────────────────────────────────────────");
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            if let Some(vip) = ip {
                println!("Mesh Virtual IP: {} (10.42.0.0/16)", vip);
            }
            println!("\n📋 Share this ticket with your peer:");
            println!("\x1b[1;36m{}\x1b[0m", ticket_str);
            println!("────────────────────────────────────────────────────────────────────────────");
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

            println!("\n👻 Connecting to GhostMesh Peer...");
            println!("────────────────────────────────────────────────────────────────────────────");
            println!("Target Node ID : {}", parsed_ticket.node_id);
            println!("Target Endpoint: {}", parsed_ticket.endpoint);
            println!("────────────────────────────────────────────────────────────────────────────");

            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            // Map target peer's default virtual IP if known (e.g. 10.42.0.1 for host)
            engine.map_peer_virtual_ip(parsed_ticket.node_id, Ipv4Addr::new(10, 42, 0, 1)).await;

            let engine_recv = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_recv.run_receive_loop().await;
            });

            engine.start_background_tasks().await;
            engine.join_ticket(parsed_ticket).await?;

            println!("🚀 UDP hole-punching probes dispatched. Direct tunnel negotiation active.\n");

            tokio::signal::ctrl_c().await?;
            info!("Exiting GhostMesh.");
        }

        Commands::Up { port, ip } => {
            info!("Starting GhostMesh daemon on port {port}...");
            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            println!("\n👻 GhostMesh Node Running");
            println!("──────────────────────────────────────────────");
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            println!("Local Port     : {port}");
            if let Some(vip) = ip {
                println!("Mesh Virtual IP: {} (10.42.0.0/16)", vip);
            }
            println!("──────────────────────────────────────────────");
            println!("Press Ctrl+C to terminate.\n");

            let engine_clone = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_clone.run_receive_loop().await;
            });

            engine.start_background_tasks().await;
            tokio::signal::ctrl_c().await?;
            info!("Shutting down GhostMesh node.");
        }

        Commands::Ping {
            target_id,
            endpoint,
            local_port,
        } => {
            let dest_node: NodeId = target_id.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let engine = Arc::new(MeshEngine::bind(local_port).await?);
            engine.add_peer(dest_node, endpoint).await;

            info!("Sending ping packet to {dest_node} at {endpoint}...");
            engine
                .send_packet(dest_node, PacketType::KeepAlive, b"GHOST_PING")
                .await?;

            println!("✅ Ping packet dispatched successfully to {endpoint}");
        }
    }

    Ok(())
}
