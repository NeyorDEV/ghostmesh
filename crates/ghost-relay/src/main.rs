use anyhow::{Context, Result};
use clap::Parser;
use ghost_crypto::IdentityKeypair;
use ghost_relay::{RelayConfig, RelayServer};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "ghost-relay", version, about = "GhostMesh relay server")]
struct Args {
    /// Address to listen on (use 0.0.0.0:443 behind a TLS-passing setup, or any free port)
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,
    /// File holding the relay's private key (hex). Created on first start.
    #[arg(long, default_value = "ghost-relay.key")]
    key_file: PathBuf,
    /// Address of the rendezvous service (address records lookup/publish)
    #[arg(long, default_value = "0.0.0.0:8444")]
    rendezvous_listen: String,
    /// Disable the rendezvous service
    #[arg(long)]
    no_rendezvous: bool,
    #[arg(long, default_value_t = 4096)]
    max_connections: usize,
    #[arg(long, default_value_t = 16)]
    max_per_ip: usize,
    /// Sustained forwarding rate per connection, in KiB/s
    #[arg(long, default_value_t = 8192)]
    rate_kib: u64,
}

fn load_or_create_key(path: &PathBuf) -> Result<IdentityKeypair> {
    if let Ok(text) = std::fs::read_to_string(path) {
        let bytes = hex::decode(text.trim()).context("key file is not hex")?;
        let private: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
        let secret = x25519_public(&private);
        return Ok(IdentityKeypair::from_key_bytes(private, secret));
    }
    let id = IdentityKeypair::generate()?;
    std::fs::write(path, hex::encode(id.private)).context("cannot write key file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(id)
}

fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    ghost_crypto::public_from_private(private)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let identity = load_or_create_key(&args.key_file)?;
    let cfg = RelayConfig {
        max_connections: args.max_connections,
        max_per_ip: args.max_per_ip,
        rate_bytes_per_sec: args.rate_kib * 1024,
        burst_bytes: args.rate_kib * 1024 * 2,
        ..Default::default()
    };
    let server = RelayServer::new(identity, cfg);
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("cannot bind {}", args.listen))?;
    info!(
        "relay listening on {} - public key: {}",
        args.listen,
        hex::encode(server.public_key())
    );
    info!(
        "clients pin it with: <host:port>#{}",
        hex::encode(server.public_key())
    );

    if !args.no_rendezvous {
        let rdv = ghost_relay::rendezvous::RendezvousServer::new(Default::default());
        let l = TcpListener::bind(&args.rendezvous_listen)
            .await
            .with_context(|| format!("cannot bind {}", args.rendezvous_listen))?;
        info!("rendezvous listening on {}", args.rendezvous_listen);
        tokio::spawn(rdv.serve(l));
    }

    let s = server.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            info!(
                "stats: nodes={} forwarded={} dropped={}",
                s.connected_nodes(),
                s.stats.forwarded.load(std::sync::atomic::Ordering::Relaxed),
                s.stats.dropped.load(std::sync::atomic::Ordering::Relaxed)
            );
        }
    });
    server.serve(listener).await;
    Ok(())
}
