use clap::{Parser, Subcommand};
use ghost_core::MeshEngine;
use ghost_crypto::IdentityKeypair;
use ghost_nat::DEFAULT_STUN_SERVER;
use ghost_protocol::{NodeId, PacketType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

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

    /// Run the GhostMesh node engine
    Up {
        #[arg(short, long, default_value_t = 4242)]
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
                    println!("Local Socket  : {local_addr}");
                    println!("Public Endpoint: {public_endpoint}");
                    println!("──────────────────────────────────────────────");
                }
                Err(e) => {
                    error!("STUN discovery failed: {e}");
                }
            }
        }

        Commands::Up { port } => {
            info!("Starting GhostMesh daemon on port {port}...");
            let engine = Arc::new(MeshEngine::bind(port).await?);
            println!("\n👻 GhostMesh Node Running");
            println!("──────────────────────────────────────────────");
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            println!("Local Port     : {port}");
            println!("──────────────────────────────────────────────");
            println!("Press Ctrl+C to terminate.\n");

            let engine_clone = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_clone.run_receive_loop().await;
            });

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
