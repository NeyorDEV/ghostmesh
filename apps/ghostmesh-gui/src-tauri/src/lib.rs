use ghost_core::MeshEngine;
use ghost_protocol::InviteTicket;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tauri::{Manager, State, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::RwLock;



pub struct GuiState {
    pub engine: Arc<RwLock<Option<Arc<MeshEngine>>>>,
    pub virtual_ip: Arc<RwLock<Option<Ipv4Addr>>>,
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

pub fn run() {
    tauri::Builder::default()

        .manage(GuiState {

            engine: Arc::new(RwLock::new(None)),
            virtual_ip: Arc::new(RwLock::new(Some(Ipv4Addr::new(10, 42, 0, 1)))),
        })
        .setup(|app| {
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("GhostMesh - Encrypted Mesh Overlay")
                .inner_size(880.0, 640.0)
                .min_inner_size(720.0, 500.0)
                .center()
                .resizable(true)
                .build()?;

            let _ = window.show();
            let _ = window.set_focus();

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {

                match MeshEngine::bind(4242).await {
                    Ok(engine) => {
                        let arc_engine = Arc::new(engine);
                        let state = handle.state::<GuiState>();
                        {
                            let mut guard = state.engine.write().await;
                            *guard = Some(Arc::clone(&arc_engine));
                        }

                        let engine_recv = Arc::clone(&arc_engine);
                        tokio::spawn(async move {
                            engine_recv.run_receive_loop().await;
                        });

                        arc_engine.start_background_tasks().await;
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
            get_peers
        ])
        .run(tauri::generate_context!())
        .expect("error while running GhostMesh desktop application");
}
