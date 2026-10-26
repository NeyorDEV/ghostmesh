use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const GHOSTDROP_MAGIC: &[u8; 4] = b"GD01";
pub const GHOSTDROP_PORT: u16 = 4243;
const CHUNK_SIZE: usize = 128 * 1024; // 128 KB buffer

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferStatus {
    pub is_active: bool,
    pub direction: String, // "sending" or "receiving"
    pub filename: String,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub percent: f32,
    pub speed_mbps: f64,
    pub status_message: String,
    pub is_completed: bool,
    pub error: Option<String>,
}

pub fn get_transfers_dir() -> PathBuf {
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

pub async fn start_ghostdrop_server(status_state: Arc<RwLock<Option<TransferStatus>>>) {
    let bind_addr = format!("0.0.0.0:{GHOSTDROP_PORT}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => {
            info!("GhostDrop TCP file transfer server listening on {bind_addr}");
            l
        }
        Err(e) => {
            warn!("Failed to bind GhostDrop TCP server on {bind_addr}: {e}");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut socket, peer_addr)) => {
                info!("GhostDrop incoming connection from {peer_addr}");
                let state_clone = Arc::clone(&status_state);
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming_transfer(&mut socket, state_clone).await {
                        error!("GhostDrop transfer error from {peer_addr}: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("GhostDrop accept error: {e}");
            }
        }
    }
}

async fn handle_incoming_transfer(
    socket: &mut TcpStream,
    status_state: Arc<RwLock<Option<TransferStatus>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut magic = [0u8; 4];
    socket.read_exact(&mut magic).await?;
    if &magic != GHOSTDROP_MAGIC {
        return Err("Invalid GhostDrop magic header".into());
    }

    let total_size = socket.read_u64().await?;
    let filename_len = socket.read_u16().await? as usize;
    let mut filename_bytes = vec![0u8; filename_len];
    socket.read_exact(&mut filename_bytes).await?;
    let raw_filename = String::from_utf8(filename_bytes)?;

    // Sanitize filename to prevent directory traversal
    let safe_filename = Path::new(&raw_filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("received_file.bin")
        .to_string();

    let out_dir = get_transfers_dir();
    let dest_path = out_dir.join(&safe_filename);
    let mut out_file = tokio::fs::File::create(&dest_path).await?;

    info!("Receiving GhostDrop file '{safe_filename}' ({total_size} bytes) to {:?}", dest_path);

    {
        let mut guard = status_state.write().await;
        *guard = Some(TransferStatus {
            is_active: true,
            direction: "receiving".into(),
            filename: safe_filename.clone(),
            total_bytes: total_size,
            transferred_bytes: 0,
            percent: 0.0,
            speed_mbps: 0.0,
            status_message: format!("Receiving {safe_filename}..."),
            is_completed: false,
            error: None,
        });
    }

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut transferred: u64 = 0;
    let start_time = Instant::now();
    let mut last_speed_calc = Instant::now();
    let mut bytes_since_last = 0u64;

    while transferred < total_size {
        let to_read = std::cmp::min(buffer.len() as u64, total_size - transferred) as usize;
        let n = socket.read(&mut buffer[..to_read]).await?;
        if n == 0 {
            break; // Unexpected EOF
        }

        out_file.write_all(&buffer[..n]).await?;
        transferred += n as u64;
        bytes_since_last += n as u64;

        if last_speed_calc.elapsed().as_millis() >= 400 {
            let elapsed_sec = last_speed_calc.elapsed().as_secs_f64();
            let current_speed = (bytes_since_last as f64 / 1_000_000.0) / elapsed_sec;
            last_speed_calc = Instant::now();
            bytes_since_last = 0;

            let pct = (transferred as f32 / total_size as f32) * 100.0;
            let mut guard = status_state.write().await;
            if let Some(ref mut st) = *guard {
                st.transferred_bytes = transferred;
                st.percent = pct;
                st.speed_mbps = current_speed;
            }
        }
    }

    out_file.flush().await?;

    let total_time = start_time.elapsed().as_secs_f64().max(0.001);
    let avg_speed = (transferred as f64 / 1_000_000.0) / total_time;

    {
        let mut guard = status_state.write().await;
        *guard = Some(TransferStatus {
            is_active: false,
            direction: "receiving".into(),
            filename: safe_filename.clone(),
            total_bytes: total_size,
            transferred_bytes: transferred,
            percent: 100.0,
            speed_mbps: avg_speed,
            status_message: format!("Finished! Saved '{safe_filename}' to Transfers"),
            is_completed: true,
            error: None,
        });
    }

    info!("GhostDrop reception completed: {safe_filename} ({transferred}/{total_size} bytes, avg {avg_speed:.1} MB/s)");
    Ok(())
}

pub async fn send_file(
    target_host: &str,
    file_path_str: &str,
    status_state: Arc<RwLock<Option<TransferStatus>>>,
) -> Result<(), String> {
    let path = Path::new(file_path_str);
    if !path.exists() {
        return Err(format!("File does not exist: {file_path_str}"));
    }

    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("Failed to read metadata: {e}"))?;
    let total_size = metadata.len();

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "Invalid filename".to_string())?
        .to_string();

    let target_ip = if let Some((ip, _)) = target_host.split_once(':') {
        ip
    } else {
        target_host
    };

    let target_addr = format!("{target_ip}:{GHOSTDROP_PORT}");
    info!("Connecting to GhostDrop receiver at {target_addr} to send '{filename}' ({total_size} bytes)");

    {
        let mut guard = status_state.write().await;
        *guard = Some(TransferStatus {
            is_active: true,
            direction: "sending".into(),
            filename: filename.clone(),
            total_bytes: total_size,
            transferred_bytes: 0,
            percent: 0.0,
            speed_mbps: 0.0,
            status_message: format!("Connecting to {target_addr}..."),
            is_completed: false,
            error: None,
        });
    }

    let mut socket = TcpStream::connect(&target_addr)
        .await
        .map_err(|e| format!("Failed to connect to {target_addr}: {e}"))?;

    // Send magic
    socket.write_all(GHOSTDROP_MAGIC).await.map_err(|e| e.to_string())?;

    // Send size
    socket.write_u64(total_size).await.map_err(|e| e.to_string())?;

    // Send filename
    let fn_bytes = filename.as_bytes();
    socket.write_u16(fn_bytes.len() as u16).await.map_err(|e| e.to_string())?;
    socket.write_all(fn_bytes).await.map_err(|e| e.to_string())?;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("Failed to open file: {e}"))?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut transferred: u64 = 0;
    let start_time = Instant::now();
    let mut last_speed_calc = Instant::now();
    let mut bytes_since_last = 0u64;

    loop {
        let n = file.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }

        socket.write_all(&buffer[..n]).await.map_err(|e| e.to_string())?;
        transferred += n as u64;
        bytes_since_last += n as u64;

        if last_speed_calc.elapsed().as_millis() >= 400 {
            let elapsed_sec = last_speed_calc.elapsed().as_secs_f64();
            let current_speed = (bytes_since_last as f64 / 1_000_000.0) / elapsed_sec;
            last_speed_calc = Instant::now();
            bytes_since_last = 0;

            let pct = (transferred as f32 / total_size as f32) * 100.0;
            let mut guard = status_state.write().await;
            if let Some(ref mut st) = *guard {
                st.transferred_bytes = transferred;
                st.percent = pct;
                st.speed_mbps = current_speed;
                st.status_message = format!("Sending {filename}... ({pct:.0}%)");
            }
        }
    }

    socket.flush().await.map_err(|e| e.to_string())?;

    let total_time = start_time.elapsed().as_secs_f64().max(0.001);
    let avg_speed = (transferred as f64 / 1_000_000.0) / total_time;

    {
        let mut guard = status_state.write().await;
        *guard = Some(TransferStatus {
            is_active: false,
            direction: "sending".into(),
            filename: filename.clone(),
            total_bytes: total_size,
            transferred_bytes: transferred,
            percent: 100.0,
            speed_mbps: avg_speed,
            status_message: format!("Sent '{filename}' successfully ({avg_speed:.1} MB/s)!"),
            is_completed: true,
            error: None,
        });
    }

    info!("GhostDrop send completed: {filename} ({transferred}/{total_size} bytes, avg {avg_speed:.1} MB/s)");
    Ok(())
}
