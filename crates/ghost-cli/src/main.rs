mod service;

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
#[command(version = "0.3.0")]
#[command(about = "Decentralized P2P Encrypted Mesh Overlay & Direct File Transfer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Start `ghostmesh up` automatically (systemd unit, launchd job or Windows logon task)
    Install {
        #[arg(short, long, default_value_t = 4242)]
        port: u16,
    },
    /// Remove it
    Uninstall,
}

#[derive(Subcommand, Debug)]
enum DnsAction {
    /// Answer `<name>.ghost` queries on this machine's virtual IP (port 53)
    Run,
    /// Make the operating system send `.ghost` lookups to that resolver (needs administrator rights)
    Install,
    /// Remove that system setting
    Uninstall,
}

#[derive(Subcommand, Debug)]
enum CaAction {
    /// Print the path of the authority certificate to install on your devices
    Path,
    /// Print the authority certificate (PEM)
    Show,
}

#[derive(Subcommand, Debug)]
enum ListAction {
    /// Add an entry (host:port)
    Add { value: String },
    /// Remove an entry
    Remove { value: String },
    /// List entries
    List,
}

#[derive(Subcommand, Debug)]
enum RelayAction {
    /// Add a relay: host:port#<relay public key in hex>
    Add { relay: String },
    /// Remove a relay by its host:port
    Remove { addr: String },
    /// List configured relays
    List,
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

    /// Show connectivity: NAT type, candidate addresses, relay, per-path peer counts
    Status {
        #[arg(short, long, default_value_t = 0)]
        port: u16,
    },

    /// Manage rendezvous servers (they let known devices find each other after an address change)
    Rendezvous {
        #[command(subcommand)]
        action: ListAction,
    },

    /// Manage STUN servers used to detect the public address and the NAT type
    Stun {
        #[command(subcommand)]
        action: ListAction,
    },

    /// Choose what a paired device may reach on this PC (profiles: full, phone, web, rdp, blocked)
    Access {
        node_id: String,
        profile: String,
        /// TCP ports opened by the phone profile, e.g. 8765,5173 or 8000-8100
        #[arg(long, value_delimiter = ',')]
        ports: Vec<String>,
    },

    /// Run the node in the background at startup
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Expose a local web port over HTTPS at https://<name>.ghost (valid certificate, microphone allowed)
    Serve {
        /// Local port of the service, e.g. 5173
        local_port: u16,
        /// HTTPS port to listen on
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Name to serve (defaults to the device name)
        #[arg(long)]
        name: Option<String>,
        /// Address to listen on (defaults to this node's virtual IP)
        #[arg(long)]
        bind: Option<std::net::IpAddr>,
    },

    /// Local certificate authority used by `serve`
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },

    /// `.ghost` names: resolver and system integration
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },

    /// Revoke a device: it is blocked here and on every other connected paired device
    Revoke { node_id: String },

    /// Give a paired device a lifetime in hours (use 0 to remove the limit)
    Expire { node_id: String, hours: u64 },

    /// List paired devices with their status
    Devices,

    /// Manage relay servers used when no direct route exists
    Relay {
        #[command(subcommand)]
        action: RelayAction,
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
        let p = PathBuf::from(profile)
            .join("Downloads")
            .join("GhostMesh-Transfers");
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

fn print_diagnostics(d: &ghost_core::DiagnosticsSnapshot) {
    println!("Node ID         : {}", d.node_id);
    println!("NAT type        : {}", d.nat_type);
    println!("STUN answers    : {}", d.stun_answers);
    println!("Public endpoint : {}", d.public_endpoint);
    println!(
        "Router mapping  : {} (UPnP: {}; NAT-PMP: {}; PCP: {})",
        d.mapping_method.as_deref().unwrap_or("none"),
        d.upnp,
        d.natpmp,
        d.pcp
    );
    println!("Candidates      : {}", d.candidates.join(", "));
    println!("Relay           : {}", d.relay.as_deref().unwrap_or("none"));
    println!(
        "Peers           : {} direct, {} via relay",
        d.direct_peers, d.relayed_peers
    );
    for h in &d.hints {
        println!("! {h}");
    }
}

fn run_all(commands: Vec<Vec<String>>) -> anyhow::Result<()> {
    for c in commands {
        println!("> {}", c.join(" "));
        let status = std::process::Command::new(&c[0]).args(&c[1..]).status()?;
        if !status.success() {
            anyhow::bail!("command failed ({status}); run it from an administrator / root shell");
        }
    }
    Ok(())
}

/// Name of this machine on the mesh: the configured one, else the computer name.
fn device_name(cfg: &ghost_core::AppConfig) -> String {
    cfg.device_name
        .clone()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "ghostmesh".to_string())
}

fn edit_list(list: &mut Vec<String>, action: ListAction) {
    match action {
        ListAction::Add { value } => {
            if !list.contains(&value) {
                list.push(value);
            }
        }
        ListAction::Remove { value } => list.retain(|v| *v != value),
        ListAction::List => {
            for v in list.iter() {
                println!("{v}");
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
        Commands::Rendezvous { action } => {
            let mut cfg = ghost_core::load_config();
            edit_list(&mut cfg.rendezvous, action);
            ghost_core::save_config(&cfg).map_err(|e| anyhow::anyhow!(e))?;
        }

        Commands::Stun { action } => {
            let mut cfg = ghost_core::load_config();
            edit_list(&mut cfg.stun_servers, action);
            ghost_core::save_config(&cfg).map_err(|e| anyhow::anyhow!(e))?;
        }

        Commands::Service { action } => {
            let exe = std::env::current_exe()?;
            match action {
                ServiceAction::Install { port } => match service::install_plan(&exe, port) {
                    service::Install::File {
                        path,
                        content,
                        then,
                    } => {
                        std::fs::write(&path, content)?;
                        println!("Wrote {}", path.display());
                        run_all(then)?;
                    }
                    service::Install::Commands(c) => run_all(c)?,
                },
                ServiceAction::Uninstall => run_all(service::uninstall_plan())?,
            }
        }

        Commands::Status { port } => {
            // A running node answers directly: no second engine, no second identity.
            if let Ok(resp) =
                ghost_core::control::send_request(&ghost_core::control::ControlRequest::Status)
                    .await
            {
                if resp.ok {
                    if let Ok(d) =
                        serde_json::from_value::<ghost_core::DiagnosticsSnapshot>(resp.data)
                    {
                        print_diagnostics(&d);
                        return Ok(());
                    }
                }
            }
            let engine = Arc::new(MeshEngine::bind_ephemeral(port).await?);
            tokio::spawn(Arc::clone(&engine).run_receive_loop());
            engine.start_background_tasks().await;
            tokio::time::sleep(Duration::from_secs(4)).await;
            let d = engine.diagnostics().await;
            print_diagnostics(&d);
        }

        Commands::Access {
            node_id,
            profile,
            ports,
        } => {
            let profile: ghost_core::Profile =
                profile.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let ports = ports
                .iter()
                .map(|p| p.parse::<ghost_core::PortRange>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!(e))?;
            if profile == ghost_core::Profile::Phone && ports.is_empty() {
                anyhow::bail!("the phone profile needs at least one port: --ports 8765,5173");
            }
            let mut cfg = ghost_core::load_config();
            let peer = cfg
                .known_peers
                .iter_mut()
                .find(|k| k.node_id == node_id)
                .ok_or_else(|| anyhow::anyhow!("unknown device: see `ghostmesh devices`"))?;
            peer.access = ghost_core::AccessPolicy {
                profile,
                ports,
                rules: Vec::new(),
            };
            ghost_core::save_config(&cfg).map_err(|e| anyhow::anyhow!(e))?;
            println!("Access updated (a running GhostMesh applies it within 30 s).");
        }

        Commands::Ca { action } => {
            let (ca, created) = ghost_pki::load_or_create_authority()?;
            match action {
                CaAction::Path => {
                    println!("{}", ghost_pki::ca_cert_path().display());
                    if created {
                        println!("(just created)");
                    }
                }
                CaAction::Show => print!("{}", ca.cert_pem()),
            }
        }

        Commands::Serve {
            local_port,
            port,
            name,
            bind,
        } => {
            let mut cfg = ghost_core::load_config();
            let (identity, _, _) = ghost_core::keystore::load_or_create_identity(&mut cfg)
                .map_err(|e| anyhow::anyhow!(e))?;
            let name = name.unwrap_or_else(|| device_name(&cfg));
            let (ca, created) = ghost_pki::load_or_create_authority()?;
            if created {
                println!("Certificate authority created. Install this file on the devices that will open the page:");
                println!("  {}", ghost_pki::ca_cert_path().display());
            }
            let host = ghost_pki::full_name(&name)?;
            let bind = bind.unwrap_or(std::net::IpAddr::V4(identity.node_id().to_virtual_ip()));
            let listener = TcpListener::bind((bind, port))
                .await
                .map_err(|e| anyhow::anyhow!("cannot listen on {bind}:{port}: {e} (is the mesh up, and do you have the rights for this port?)"))?;
            let tls = ca.server_config(&name)?;
            println!(
                "Serving https://{host}{} -> 127.0.0.1:{local_port} (listening on {bind}:{port})",
                if port == 443 {
                    String::new()
                } else {
                    format!(":{port}")
                }
            );
            ghost_pki::serve_https(
                listener,
                SocketAddr::from(([127, 0, 0, 1], local_port)),
                tls,
            )
            .await?;
        }

        Commands::Dns { action } => {
            let mut cfg = ghost_core::load_config();
            let (identity, _, _) = ghost_core::keystore::load_or_create_identity(&mut cfg)
                .map_err(|e| anyhow::anyhow!(e))?;
            let dns_ip = identity.node_id().to_virtual_ip();
            match action {
                DnsAction::Run => {
                    let names: ghost_core::dns::NameTable = Default::default();
                    let socket = tokio::net::UdpSocket::bind((dns_ip, 53))
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("cannot listen on {dns_ip}:53: {e} (is the mesh up?)")
                        })?;
                    let table = Arc::clone(&names);
                    let me = identity.node_id();
                    tokio::spawn(async move {
                        loop {
                            let cfg = ghost_core::load_config();
                            *table.write().await =
                                ghost_core::dns::build_names(&cfg, me, &device_name(&cfg));
                            tokio::time::sleep(Duration::from_secs(15)).await;
                        }
                    });
                    println!("Resolving .ghost names on {dns_ip}:53");
                    ghost_core::dns::serve(socket, names).await;
                }
                DnsAction::Install | DnsAction::Uninstall => {
                    let commands = if matches!(action, DnsAction::Install) {
                        ghost_core::dns::os_install_commands(dns_ip, "ghost0")
                    } else {
                        ghost_core::dns::os_uninstall_commands("ghost0")
                    };
                    for c in commands {
                        println!("> {}", c.join(" "));
                        let status = std::process::Command::new(&c[0]).args(&c[1..]).status()?;
                        if !status.success() {
                            anyhow::bail!("command failed ({status}); run it from an administrator / root shell");
                        }
                    }
                }
            }
        }

        Commands::Devices => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for k in ghost_core::load_config().known_peers {
                let status = if k.revoked {
                    "REVOKED".to_string()
                } else {
                    match k.expires_at {
                        Some(t) if t <= now => "EXPIRED".to_string(),
                        Some(t) => format!("expires in {} h", (t - now) / 3600),
                        None => "active".to_string(),
                    }
                };
                let ports: Vec<String> = k.access.ports.iter().map(|p| p.to_string()).collect();
                println!(
                    "{}  {}  {}  access={:?} {}",
                    k.node_id,
                    k.alias,
                    status,
                    k.access.profile,
                    ports.join(",")
                );
            }
        }

        Commands::Revoke { node_id } => {
            let node: NodeId = node_id.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let engine = Arc::new(MeshEngine::bind(0).await?);
            engine.revoke_peer(node).await;
            println!("Device {node} revoked. A running GhostMesh applies it within 30 s and tells the other connected devices.");
        }

        Commands::Expire { node_id, hours } => {
            let node: NodeId = node_id.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let engine = Arc::new(MeshEngine::bind(0).await?);
            let hours = if hours == 0 { None } else { Some(hours) };
            if engine.set_device_expiry(node, hours).await {
                println!("Expiry updated.");
            } else {
                println!("Unknown device.");
            }
        }

        Commands::Relay { action } => {
            let mut cfg = ghost_core::load_config();
            match action {
                RelayAction::Add { relay } => {
                    let ep: ghost_core::RelayEndpoint =
                        relay.parse().map_err(|e: String| anyhow::anyhow!(e))?;
                    cfg.relays.retain(|r| r.addr != ep.addr);
                    cfg.relays.push(ep);
                    ghost_core::save_config(&cfg).map_err(|e| anyhow::anyhow!(e))?;
                    println!("Relay added.");
                }
                RelayAction::Remove { addr } => {
                    cfg.relays.retain(|r| r.addr != addr);
                    ghost_core::save_config(&cfg).map_err(|e| anyhow::anyhow!(e))?;
                    println!("Relay removed.");
                }
                RelayAction::List => {
                    for r in &cfg.relays {
                        println!("{}#{}", r.addr, r.public_key);
                    }
                }
            }
        }

        Commands::Keygen => {
            let keypair = IdentityKeypair::generate()?;
            println!("[GHOSTMESH] Cryptographic Identity Generated");
            println!(
                "----------------------------------------------------------------------------"
            );
            println!("Node ID    : {}", keypair.node_id());
            println!("Public Key : {}", keypair.public_hex());
            println!(
                "----------------------------------------------------------------------------"
            );
            println!("Keep your private keys secure!");
        }

        Commands::Discover { port, stun } => {
            let socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{port}")).await?;
            let local_addr = socket.local_addr()?;
            info!("Bound local socket on {local_addr}");
            info!("Querying STUN server {stun}...");

            match ghost_nat::discover_public_endpoint(&socket, &stun, Duration::from_secs(3)).await
            {
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
            println!(
                "----------------------------------------------------------------------------"
            );
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            if let Some(vip) = ip {
                println!("Mesh Virtual IP: {} (10.42.0.0/16)", vip);
            }
            println!("\nShare this ticket with your peer:");
            println!("\x1b[1;36m{}\x1b[0m", ticket_str);
            println!(
                "----------------------------------------------------------------------------"
            );
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
            let parsed_ticket: InviteTicket = ticket
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid invite ticket: {e}"))?;

            println!("\nConnecting to GhostMesh Peer...");
            println!(
                "----------------------------------------------------------------------------"
            );
            println!("Target Node ID : {}", parsed_ticket.node_id);
            println!("Target Endpoint: {}", parsed_ticket.endpoint);
            println!(
                "----------------------------------------------------------------------------"
            );

            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            engine
                .map_peer_virtual_ip(parsed_ticket.node_id, Ipv4Addr::new(10, 42, 0, 1))
                .await;

            let engine_recv = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_recv.run_receive_loop().await;
            });

            engine.start_background_tasks().await;
            engine.join_ticket(parsed_ticket).await?;

            println!(
                "[OK] UDP hole-punching probes dispatched. Direct tunnel negotiation active.\n"
            );

            tokio::signal::ctrl_c().await?;
            info!("Exiting GhostMesh.");
        }

        Commands::Up { port, ip } => {
            info!("Starting GhostMesh daemon on port {port}...");
            let engine = Arc::new(MeshEngine::bind(port).await?);
            try_setup_tun(&engine, ip).await;

            println!("\n[GHOSTMESH] Node Running");
            println!(
                "----------------------------------------------------------------------------"
            );
            println!("Node ID        : {}", engine.node_id());
            println!("Public Endpoint: {}", engine.public_addr);
            println!("Local Port     : {port}");
            if let Some(vip) = ip {
                println!("Mesh Virtual IP: {} (10.42.0.0/16)", vip);
            }
            println!(
                "----------------------------------------------------------------------------"
            );
            println!("Press Ctrl+C to terminate.\n");

            let engine_clone = Arc::clone(&engine);
            tokio::spawn(async move {
                engine_clone.run_receive_loop().await;
            });

            engine.start_background_tasks().await;

            // The CLI and the GUI talk to the running node through this local channel.
            let shutdown = Arc::new(tokio::sync::Notify::new());
            let control = Arc::clone(&engine);
            let stop = Arc::clone(&shutdown);
            tokio::spawn(async move {
                if let Err(e) = ghost_core::control::serve_control(control, stop).await {
                    warn!("Control channel unavailable: {e}");
                }
            });
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = shutdown.notified() => {}
            }
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
            println!(
                "----------------------------------------------------------------------------"
            );
            println!(
                "File     : {} ({:.2} MB)",
                filename,
                total_size as f64 / 1_000_000.0
            );
            println!("Target   : {}", target_addr);
            println!("Connecting...");

            let mut socket = TcpStream::connect(&target_addr)
                .await
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

                    print!(
                        "\rSending: {} {:.1}% ({:.1}/{:.1} MB) - {:.1} MB/s  ",
                        bar, pct, cur_mb, tot_mb, mbps
                    );
                    let _ = std::io::stdout().flush();

                    last_log = Instant::now();
                    bytes_since = 0;
                }
            }

            socket.flush().await?;
            let elapsed = start.elapsed().as_secs_f64().max(0.001);
            let avg_speed = (transferred as f64 / 1_000_000.0) / elapsed;

            println!(
                "\n----------------------------------------------------------------------------"
            );
            println!(
                "[OK] File '{}' sent successfully in {:.1}s (avg {:.1} MB/s)\n",
                filename, elapsed, avg_speed
            );
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
            let listener = TcpListener::bind(&bind_addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to bind on {bind_addr}: {e}"))?;

            println!("\n[GHOSTDROP] Receiver daemon active");
            println!(
                "----------------------------------------------------------------------------"
            );
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
                    println!(
                        "Receiving '{}' ({:.2} MB) from {}...",
                        safe_fn,
                        total_size as f64 / 1_000_000.0,
                        peer_addr
                    );

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
                        let to_read =
                            std::cmp::min(buffer.len() as u64, total_size - transferred) as usize;
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
                    println!(
                        "[OK] Finished receiving '{}' in {:.1}s (avg {:.1} MB/s). Saved to {:?}",
                        safe_fn, elapsed, avg, dest
                    );
                });
            }
        }

        Commands::Sync {
            dir,
            target,
            port: _,
        } => {
            let sync_engine = ghost_core::GhostSyncEngine::new();
            sync_engine
                .set_watched_directory(&dir)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("\n[GHOSTSYNC] Real-time folder synchronization active");
            println!(
                "----------------------------------------------------------------------------"
            );
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
