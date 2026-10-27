mod ghostdrop;

use ghost_core::MeshEngine;
use ghost_protocol::InviteTicket;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tauri::{Manager, State};
use tokio::sync::RwLock;

pub struct GuiState {
    pub engine: Arc<RwLock<Option<Arc<MeshEngine>>>>,
    pub virtual_ip: Arc<RwLock<Option<Ipv4Addr>>>,
    pub transfer_status: Arc<RwLock<Option<ghostdrop::TransferStatus>>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeStatus {
    pub node_id: String,
    pub public_endpoint: String,
    pub virtual_ip: Option<String>,
    pub is_active: bool,
    pub peers_count: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub endpoint: String,
    pub state: String,
    pub last_seen_secs: u64,
}

#[tauri::command]
async fn get_node_status(state: State<'_, GuiState>) -> Result<NodeStatus, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;

    let peers_count = {
        let table = engine.peers.read().await;
        table.len()
    };

    let vip = state.virtual_ip.read().await;

    Ok(NodeStatus {
        node_id: engine.node_id().to_string(),
        public_endpoint: engine.public_addr.to_string(),
        virtual_ip: vip.map(|ip| format!("{ip}/16")),
        is_active: true,
        peers_count,
    })
}

#[tauri::command]
async fn create_invite(state: State<'_, GuiState>) -> Result<String, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let ticket = engine.create_invite();
    Ok(ticket.to_ticket_string())
}

#[tauri::command]
async fn join_peer(ticket: String, state: State<'_, GuiState>) -> Result<String, String> {
    let parsed: InviteTicket = ticket.parse().map_err(|e| format!("Invalid ticket: {e}"))?;
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;

    if parsed.node_id == engine.node_id() {
        return Err("Cannot join your own invite ticket. Paste this ticket into another GhostMesh instance on another device.".into());
    }

    engine.join_ticket(parsed).await.map_err(|e| e.to_string())?;
    Ok("Hole-punching probes dispatched".into())
}

#[tauri::command]
async fn disconnect_peer(node_id: String, state: State<'_, GuiState>) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let target: ghost_protocol::NodeId = node_id.parse().map_err(|e| format!("{e}"))?;
    engine.remove_peer(target).await;
    Ok(())
}

#[tauri::command]
async fn get_peers(state: State<'_, GuiState>) -> Result<Vec<PeerInfo>, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;

    let table = engine.peers.read().await;
    let now = std::time::Instant::now();

    let list = table
        .iter()
        .map(|p| PeerInfo {
            node_id: p.node_id.to_string(),
            endpoint: p.endpoint.to_string(),
            state: p.state.to_string(),
            last_seen_secs: now.duration_since(p.last_seen).as_secs(),
        })
        .collect();

    Ok(list)
}

#[tauri::command]
async fn ghostdrop_send(
    target: String,
    file_path: String,
    state: State<'_, GuiState>,
) -> Result<String, String> {
    let status_clone = Arc::clone(&state.transfer_status);
    tokio::spawn(async move {
        if let Err(e) = ghostdrop::send_file(&target, &file_path, status_clone).await {
            eprintln!("GhostDrop send error: {e}");
        }
    });
    Ok("Transfer initiated".into())
}

#[tauri::command]
async fn ghostdrop_get_status(
    state: State<'_, GuiState>,
) -> Result<Option<ghostdrop::TransferStatus>, String> {
    let guard = state.transfer_status.read().await;
    Ok(guard.clone())
}

#[tauri::command]
fn generate_ticket_qr(ticket: String) -> Result<String, String> {
    use qrcode::QrCode;
    use qrcode::render::svg;

    let code = QrCode::new(ticket.as_bytes()).map_err(|e| e.to_string())?;
    let svg = code
        .render::<svg::Color>()
        .min_dimensions(180, 180)
        .dark_color(svg::Color("#06b6d4"))
        .light_color(svg::Color("#050811"))
        .build();
    Ok(svg)
}

#[tauri::command]
async fn ghostsync_set_dir(dir: String, state: State<'_, GuiState>) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    engine.sync.set_watched_directory(&dir).await
}

#[tauri::command]
async fn ghostsync_get_status(state: State<'_, GuiState>) -> Result<ghost_core::SyncStatus, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    Ok(engine.sync.get_status().await)
}

#[tauri::command]
fn get_known_devices() -> Result<Vec<ghost_core::KnownPeer>, String> {
    let cfg = ghost_core::load_config();
    Ok(cfg.known_peers)
}

#[tauri::command]
fn remove_known_device(node_id: String) -> Result<(), String> {
    let mut cfg = ghost_core::load_config();
    cfg.known_peers.retain(|p| p.node_id != node_id);
    ghost_core::save_config(&cfg)
}

#[tauri::command]
fn update_device_permissions(
    node_id: String,
    allow_rdp: bool,
    allow_ghostdrop: bool,
    temporary_session: bool,
) -> Result<(), String> {
    let mut cfg = ghost_core::load_config();
    if let Some(peer) = cfg.known_peers.iter_mut().find(|p| p.node_id == node_id) {
        peer.allow_rdp = allow_rdp;
        peer.allow_ghostdrop = allow_ghostdrop;
        peer.temporary_session = temporary_session;
    }
    ghost_core::save_config(&cfg)
}

#[tauri::command]
async fn send_chat_message(
    target_node_id: String,
    text: String,
    state: State<'_, GuiState>,
) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let dest_node: ghost_protocol::NodeId = target_node_id.parse().map_err(|e| format!("{e}"))?;
    engine
        .send_chat_message(dest_node, &text)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_chat_messages(
    target_node_id: String,
    state: State<'_, GuiState>,
) -> Result<Vec<ghost_core::ChatMessageEntry>, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let msgs = engine.chat_messages.read().await;
    let filtered = msgs
        .iter()
        .filter(|m| m.sender == target_node_id || m.recipient == target_node_id)
        .cloned()
        .collect();
    Ok(filtered)
}

#[tauri::command]
fn get_autostart() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "GhostMesh"])
            .output();
        if let Ok(out) = output {
            return Ok(out.status.success());
        }
    }
    let cfg = ghost_core::load_config();
    Ok(cfg.autostart)
}

#[tauri::command]
fn set_autostart(enable: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if enable {
            if let Ok(exe_path) = std::env::current_exe() {
                let val = format!("\"{}\" --silent", exe_path.to_str().unwrap_or("GhostMesh.exe"));
                let _ = std::process::Command::new("reg")
                    .args([
                        "add",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v",
                        "GhostMesh",
                        "/t",
                        "REG_SZ",
                        "/d",
                        &val,
                        "/f",
                    ])
                    .output();
            }
        } else {
            let _ = std::process::Command::new("reg")
                .args([
                    "delete",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "GhostMesh",
                    "/f",
                ])
                .output();
        }
    }
    let mut cfg = ghost_core::load_config();
    cfg.autostart = enable;
    ghost_core::save_config(&cfg)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExitNodeStatus {
    pub is_active: bool,
    pub target_node_id: Option<String>,
    pub target_virtual_ip: Option<String>,
    pub allow_sharing: bool,
}

#[tauri::command]
async fn send_clipboard_to_peer(
    target_node_id: String,
    text: String,
    state: State<'_, GuiState>,
) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let dest_node: ghost_protocol::NodeId = target_node_id.parse().map_err(|e| format!("{e}"))?;
    engine.send_clipboard(dest_node, &text).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_incoming_clipboard(
    state: State<'_, GuiState>,
) -> Result<Option<ghost_core::ClipboardEntry>, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let mut clip_guard = engine.last_clipboard.write().await;
    let item = clip_guard.take();
    Ok(item)
}

#[tauri::command]
fn get_auto_clipboard() -> Result<bool, String> {
    let cfg = ghost_core::load_config();
    Ok(cfg.auto_clipboard)
}

#[tauri::command]
fn set_auto_clipboard(enable: bool) -> Result<(), String> {
    let mut cfg = ghost_core::load_config();
    cfg.auto_clipboard = enable;
    ghost_core::save_config(&cfg)
}

#[tauri::command]
async fn set_exit_node(
    target_node_id: Option<String>,
    state: State<'_, GuiState>,
) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("route")
            .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
            .output();
        let _ = std::process::Command::new("route")
            .args(["delete", "128.0.0.0", "mask", "128.0.0.0"])
            .output();

        if let Some(ref nid_str) = target_node_id {
            if let Ok(nid) = nid_str.parse::<ghost_protocol::NodeId>() {
                let vip = nid.to_virtual_ip().to_string();
                let _ = std::process::Command::new("route")
                    .args(["add", "0.0.0.0", "mask", "128.0.0.0", &vip, "metric", "10"])
                    .output();
                let _ = std::process::Command::new("route")
                    .args(["add", "128.0.0.0", "mask", "128.0.0.0", &vip, "metric", "10"])
                    .output();
                let _ = engine
                    .send_packet(nid, ghost_protocol::PacketType::ExitNodeRoute, b"ROUTE_REQ")
                    .await;
            }
        }
    }

    let mut exit_guard = engine.active_exit_node.write().await;
    *exit_guard = target_node_id;
    Ok(())
}

#[tauri::command]
async fn get_exit_node_status(
    state: State<'_, GuiState>,
) -> Result<ExitNodeStatus, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let exit_guard = engine.active_exit_node.read().await;
    let cfg = ghost_core::load_config();

    let target_vip = exit_guard.as_ref().and_then(|nid_str| {
        nid_str
            .parse::<ghost_protocol::NodeId>()
            .ok()
            .map(|nid| nid.to_virtual_ip().to_string())
    });

    Ok(ExitNodeStatus {
        is_active: exit_guard.is_some(),
        target_node_id: exit_guard.clone(),
        target_virtual_ip: target_vip,
        allow_sharing: cfg.allow_exit_node,
    })
}

#[tauri::command]
fn set_allow_exit_node(allow: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if allow {
            let _ = std::process::Command::new("powershell")
                .args([
                    "-Command",
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1 -ErrorAction SilentlyContinue",
                ])
                .output();
        }
    }
    let mut cfg = ghost_core::load_config();
    cfg.allow_exit_node = allow;
    ghost_core::save_config(&cfg)
}

#[tauri::command]
async fn request_device_connect(
    target_node_id: String,
    target_endpoint: String,
    state: State<'_, GuiState>,
) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let dest_node: ghost_protocol::NodeId = target_node_id.parse().map_err(|e| format!("{e}"))?;
    let dest_addr: std::net::SocketAddr = target_endpoint.parse().map_err(|e| format!("{e}"))?;

    engine.add_peer(dest_node, dest_addr).await;
    engine
        .send_packet(dest_node, ghost_protocol::PacketType::PairRequest, b"CONNECT_REQUEST")
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_pending_connection_request(
    state: State<'_, GuiState>,
) -> Result<Option<ghost_core::PendingConnectionRequest>, String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let req = engine.pending_request.read().await;
    Ok(req.clone())
}

#[tauri::command]
async fn respond_connection_request(
    node_id: String,
    accept: bool,
    state: State<'_, GuiState>,
) -> Result<(), String> {
    let guard = state.engine.read().await;
    let engine = guard.as_ref().ok_or("Engine not started")?;
    let dest_node: ghost_protocol::NodeId = node_id.parse().map_err(|e| format!("{e}"))?;

    let packet_type = if accept {
        ghost_protocol::PacketType::PairAccept
    } else {
        ghost_protocol::PacketType::PairReject
    };

    let _ = engine.send_packet(dest_node, packet_type, b"").await;

    // Clear pending request
    let mut req_guard = engine.pending_request.write().await;
    *req_guard = None;

    Ok(())
}

#[tauri::command]
fn launch_rdp(virtual_ip: String, node_id: Option<String>) -> Result<(), String> {
    if let Some(ref nid) = node_id {
        let cfg = ghost_core::load_config();
        if let Some(peer) = cfg.known_peers.iter().find(|p| &p.node_id == nid) {
            if !peer.allow_rdp {
                return Err("Remote Desktop is blocked by policy for this device.".into());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let ip = if let Some((clean_ip, _)) = virtual_ip.split_once('/') {
            clean_ip
        } else {
            &virtual_ip
        };
        let _ = std::process::Command::new("mstsc")
            .arg(format!("/v:{}", ip))
            .spawn();
    }
    Ok(())
}

#[tauri::command]
async fn ghostdrop_open_folder() -> Result<(), String> {
    let folder = ghostdrop::get_transfers_dir();
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer").arg(&folder).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&folder).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(&folder).spawn();
    }
    Ok(())
}

pub fn run() {
    let transfer_status = Arc::new(RwLock::new(None));

    tauri::Builder::default()
        .manage(GuiState {
            engine: Arc::new(RwLock::new(None)),
            virtual_ip: Arc::new(RwLock::new(None)),
            transfer_status: Arc::clone(&transfer_status),
        })
        .setup(|app| {
            let is_silent = std::env::args().any(|a| a == "--silent" || a == "--minimized");
            if let Some(win) = app.get_webview_window("main") {
                if let Some(icon) = app.default_window_icon() {
                    let _ = win.set_icon(icon.clone());
                }
                if !is_silent {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }

            let handle = app.handle().clone();

            tauri::async_runtime::spawn(async move {
                match MeshEngine::bind(4242).await {
                    Ok(engine) => {
                        let arc_engine = Arc::new(engine);
                        let state = handle.state::<GuiState>();

                        // Deterministic virtual IP derived cryptographically from NodeId
                        let node_vip = arc_engine.node_id().to_virtual_ip();
                        {
                            let mut vip_guard = state.virtual_ip.write().await;
                            *vip_guard = Some(node_vip);
                        }

                        {
                            let mut guard = state.engine.write().await;
                            *guard = Some(Arc::clone(&arc_engine));
                        }

                        let engine_recv = Arc::clone(&arc_engine);
                        tokio::spawn(async move {
                            engine_recv.run_receive_loop().await;
                        });

                        arc_engine.start_background_tasks().await;

                        // Start periodic GhostSync change detector
                        let sync_engine = Arc::clone(&arc_engine.sync);
                        tokio::spawn(async move {
                            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
                            loop {
                                interval.tick().await;
                                let _ = sync_engine.scan_and_detect_changes().await;
                            }
                        });

                        // Start GhostDrop TCP transfer listener on port 4243
                        let transfer_status_clone = Arc::clone(&state.transfer_status);
                        tokio::spawn(async move {
                            ghostdrop::start_ghostdrop_server(transfer_status_clone).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to bind mesh engine: {e}");
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_node_status,
            create_invite,
            join_peer,
            disconnect_peer,
            get_peers,
            ghostdrop_send,
            ghostdrop_get_status,
            ghostdrop_open_folder,
            generate_ticket_qr,
            ghostsync_set_dir,
            ghostsync_get_status,
            get_known_devices,
            remove_known_device,
            update_device_permissions,
            request_device_connect,
            get_pending_connection_request,
            respond_connection_request,
            launch_rdp,
            send_chat_message,
            get_chat_messages,
            get_autostart,
            set_autostart,
            send_clipboard_to_peer,
            get_incoming_clipboard,
            get_auto_clipboard,
            set_auto_clipboard,
            set_exit_node,
            get_exit_node_status,
            set_allow_exit_node
        ])
        .run(tauri::generate_context!())
        .expect("error while running GhostMesh desktop application");
}
