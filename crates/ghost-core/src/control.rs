//! Local control channel between a running node (daemon) and the CLI / GUI.
//!
//! One JSON object per line over a Windows named pipe or a Unix socket that only the current user
//! can open. It is never reachable from the network.

use crate::{MeshEngine, PeerState};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Longest accepted request line.
const MAX_LINE: u64 = 64 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    Status,
    Peers,
    Revoke { node_id: String },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl ControlResponse {
    fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: serde_json::Value::Null,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerSummary {
    pub node_id: String,
    pub state: String,
    pub endpoint: String,
    /// "direct", "tcp" or "relay"
    pub path: String,
    pub epoch: u8,
}

/// Where a running node listens for control requests.
pub fn control_endpoint() -> String {
    if cfg!(windows) {
        r"\\.\pipe\ghostmesh-control".to_string()
    } else if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{dir}/ghostmesh.sock")
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        format!("/tmp/ghostmesh-{user}.sock")
    }
}

pub async fn handle_request(
    engine: &Arc<MeshEngine>,
    req: ControlRequest,
    shutdown: &tokio::sync::Notify,
) -> ControlResponse {
    match req {
        ControlRequest::Status => match serde_json::to_value(engine.diagnostics().await) {
            Ok(v) => ControlResponse::ok(v),
            Err(e) => ControlResponse::err(e.to_string()),
        },
        ControlRequest::Peers => {
            let table = engine.peers.read().await;
            let peers: Vec<PeerSummary> = table
                .iter()
                .map(|p| PeerSummary {
                    node_id: p.node_id.to_string(),
                    state: match p.state {
                        PeerState::Connected => "connected".into(),
                        other => other.to_string(),
                    },
                    endpoint: p.endpoint.to_string(),
                    path: if p.tcp.is_some() {
                        "tcp"
                    } else if p.is_direct() {
                        "direct"
                    } else if p.relay_seen.is_some() {
                        "relay"
                    } else {
                        "none"
                    }
                    .into(),
                    epoch: p.current_epoch(),
                })
                .collect();
            ControlResponse::ok(serde_json::to_value(peers).unwrap_or_default())
        }
        ControlRequest::Revoke { node_id } => match node_id.parse() {
            Ok(node) => {
                engine.revoke_peer(node).await;
                ControlResponse::ok(serde_json::Value::Null)
            }
            Err(e) => ControlResponse::err(e),
        },
        ControlRequest::Shutdown => {
            shutdown.notify_one();
            ControlResponse::ok(serde_json::Value::Null)
        }
    }
}

/// Serves requests on one connected stream until it closes.
pub async fn serve_stream<S>(engine: Arc<MeshEngine>, stream: S, shutdown: Arc<tokio::sync::Notify>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd.take(MAX_LINE));
    loop {
        let mut line = String::new();
        // The limit applies per line: reset it before each read.
        rd.get_mut().set_limit(MAX_LINE);
        match rd.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) if !line.ends_with('\n') => return, // longer than the limit, or cut off
            Ok(_) => {}
        }
        let response = match serde_json::from_str::<ControlRequest>(line.trim()) {
            Ok(req) => handle_request(&engine, req, &shutdown).await,
            Err(e) => ControlResponse::err(format!("bad request: {e}")),
        };
        let Ok(mut out) = serde_json::to_vec(&response) else {
            return;
        };
        out.push(b'\n');
        if wr.write_all(&out).await.is_err() {
            return;
        }
    }
}

#[cfg(unix)]
pub async fn serve_control(
    engine: Arc<MeshEngine>,
    shutdown: Arc<tokio::sync::Notify>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = control_endpoint();
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve_stream(
            Arc::clone(&engine),
            stream,
            Arc::clone(&shutdown),
        ));
    }
}

#[cfg(windows)]
pub async fn serve_control(
    engine: Arc<MeshEngine>,
    shutdown: Arc<tokio::sync::Notify>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let name = control_endpoint();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&name)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new()
            .reject_remote_clients(true)
            .create(&name)?;
        tokio::spawn(serve_stream(
            Arc::clone(&engine),
            connected,
            Arc::clone(&shutdown),
        ));
    }
}

/// Sends one request to a running node. Fails when no node is running.
pub async fn send_request(req: &ControlRequest) -> std::io::Result<ControlResponse> {
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(control_endpoint()).await?;
    #[cfg(windows)]
    let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(control_endpoint())?;

    let (rd, mut wr) = tokio::io::split(stream);
    let mut line = serde_json::to_vec(req).map_err(std::io::Error::other)?;
    line.push(b'\n');
    wr.write_all(&line).await?;
    let mut rd = BufReader::new(rd);
    let mut answer = String::new();
    rd.read_line(&mut answer).await?;
    serde_json::from_str(answer.trim()).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_roundtrip_as_json_lines() {
        let r = ControlRequest::Revoke {
            node_id: "ab".into(),
        };
        let text = serde_json::to_string(&r).unwrap();
        assert_eq!(text, r#"{"cmd":"revoke","node_id":"ab"}"#);
        assert_eq!(serde_json::from_str::<ControlRequest>(&text).unwrap(), r);
        assert_eq!(
            serde_json::from_str::<ControlRequest>(r#"{"cmd":"status"}"#).unwrap(),
            ControlRequest::Status
        );
        assert!(serde_json::from_str::<ControlRequest>(r#"{"cmd":"format_disk"}"#).is_err());
    }

    #[tokio::test]
    async fn serves_status_and_rejects_garbage() {
        let engine = Arc::new(MeshEngine::bind_ephemeral(15501).await.unwrap());
        let (client, server) = tokio::io::duplex(1 << 16);
        let shutdown = Arc::new(tokio::sync::Notify::new());
        tokio::spawn(serve_stream(
            Arc::clone(&engine),
            server,
            Arc::clone(&shutdown),
        ));

        let (rd, mut wr) = tokio::io::split(client);
        let mut rd = BufReader::new(rd);
        wr.write_all(
            b"{\"cmd\":\"status\"}\nnot json\n{\"cmd\":\"peers\"}\n{\"cmd\":\"shutdown\"}\n",
        )
        .await
        .unwrap();

        async fn read<R: AsyncBufReadExt + Unpin>(rd: &mut R) -> ControlResponse {
            let mut l = String::new();
            rd.read_line(&mut l).await.unwrap();
            serde_json::from_str::<ControlResponse>(l.trim()).unwrap()
        }
        let status = read(&mut rd).await;
        assert!(status.ok);
        assert_eq!(status.data["node_id"], engine.node_id().to_string());
        let bad = read(&mut rd).await;
        assert!(!bad.ok && bad.error.unwrap().contains("bad request"));
        let peers = read(&mut rd).await;
        assert!(peers.ok && peers.data.as_array().unwrap().is_empty());
        assert!(read(&mut rd).await.ok);
        tokio::time::timeout(std::time::Duration::from_secs(1), shutdown.notified())
            .await
            .expect("shutdown requested");
    }

    #[tokio::test]
    async fn oversized_lines_close_the_connection() {
        let engine = Arc::new(MeshEngine::bind_ephemeral(15502).await.unwrap());
        let (client, server) = tokio::io::duplex(1 << 20);
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(serve_stream(engine, server, shutdown));
        let (_rd, mut wr) = tokio::io::split(client);
        let junk = vec![b'a'; (MAX_LINE as usize) + 1000];
        let _ = wr.write_all(&junk).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("server must hang up")
            .unwrap();
    }
}
