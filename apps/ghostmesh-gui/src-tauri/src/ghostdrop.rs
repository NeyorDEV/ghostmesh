use serde::{Deserialize, Serialize};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const GHOSTDROP_MAGIC: &[u8; 4] = b"GD02"; // Version 2 with Resume & Folder support
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

    // Resume logic: check existing partial file
    let mut resume_offset: u64 = 0;
    if dest_path.exists() {
        if let Ok(meta) = tokio::fs::metadata(&dest_path).await {
            let existing_size = meta.len();
            if existing_size > 0 && existing_size < total_size {
                resume_offset = existing_size;
                info!("GhostDrop resuming '{safe_filename}' from byte offset {resume_offset}/{total_size}");
            }
        }
    }

    // Acknowledge resume offset to sender
    socket.write_u64(resume_offset).await?;

    let mut out_file = if resume_offset > 0 {
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&dest_path)
            .await?
    } else {
        tokio::fs::File::create(&dest_path).await?
    };

    info!("Receiving GhostDrop file '{safe_filename}' ({total_size} bytes, offset {resume_offset}) to {:?}", dest_path);

    {
        let mut guard = status_state.write().await;
        let pct = if total_size > 0 {
            (resume_offset as f32 / total_size as f32) * 100.0
        } else {
            0.0
        };
        *guard = Some(TransferStatus {
            is_active: true,
            direction: "receiving".into(),
            filename: safe_filename.clone(),
            total_bytes: total_size,
            transferred_bytes: resume_offset,
            percent: pct,
            speed_mbps: 0.0,
            status_message: if resume_offset > 0 {
                format!("Resuming {safe_filename} from {pct:.0}%...")
            } else {
                format!("Receiving {safe_filename}...")
            },
            is_completed: false,
            error: None,
        });
    }

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut transferred: u64 = resume_offset;
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
        return Err(format!("Path does not exist: {file_path_str}"));
    }

    // Auto-detect and compress directories into a zip archive on the fly
    let (real_path, filename, is_temp) = if path.is_dir() {
        let base_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("folder");
        let zip_name = format!("{base_name}.zip");
        let temp_zip = std::env::temp_dir().join(&zip_name);

        info!("GhostDrop auto-zipping folder {:?} to {:?}", path, temp_zip);
        #[cfg(target_os = "windows")]
        {
            let parent_dir = path.parent().unwrap_or(path);
            let _ = std::process::Command::new("tar")
                .args([
                    "-a",
                    "-cf",
                    temp_zip.to_str().unwrap(),
                    "-C",
                    parent_dir.to_str().unwrap(),
                    base_name,
                ])
                .output();
        }

        (temp_zip, zip_name, true)
    } else {
        let fn_str = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "Invalid filename".to_string())?
            .to_string();
        (path.to_path_buf(), fn_str, false)
    };

    let metadata = tokio::fs::metadata(&real_path)
        .await
        .map_err(|e| format!("Failed to read metadata: {e}"))?;
    let total_size = metadata.len();

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

    // Read resume offset from receiver
    let resume_offset = socket.read_u64().await.map_err(|e| e.to_string())?;

    let mut file = tokio::fs::File::open(&real_path)
        .await
        .map_err(|e| format!("Failed to open file: {e}"))?;

    if resume_offset > 0 {
        file.seek(SeekFrom::Start(resume_offset))
            .await
            .map_err(|e| e.to_string())?;
        info!("Resuming upload for '{filename}' from offset {resume_offset}/{total_size}");
    }

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut transferred: u64 = resume_offset;
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

    if is_temp {
        let _ = tokio::fs::remove_file(&real_path).await;
    }

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
