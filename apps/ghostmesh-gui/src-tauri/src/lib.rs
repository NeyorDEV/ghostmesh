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

    engine.join_ticket(parsed).await.map_err(|e| e.to_string())?;
    Ok("Hole-punching probes dispatched".into())
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
            if let Some(win) = app.get_webview_window("main") {
                if let Some(icon) = app.default_window_icon() {
                    let _ = win.set_icon(icon.clone());
                }
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
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
            get_peers,
            ghostdrop_send,
            ghostdrop_get_status,
            ghostdrop_open_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running GhostMesh desktop application");
}
