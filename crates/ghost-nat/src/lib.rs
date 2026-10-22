use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
pub const DEFAULT_STUN_SERVER: &str = "stun.l.google.com:19302";

#[derive(Error, Debug)]
pub enum NatError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("STUN request timeout")]
    Timeout,
    #[error("Invalid STUN response: {0}")]
    InvalidResponse(String),
}

/// Discovers the reflexive public IP and port assigned by the NAT/router to the provided local socket.
pub async fn discover_public_endpoint(
    socket: &UdpSocket,
    stun_server: &str,
    timeout_duration: Duration,
) -> Result<SocketAddr, NatError> {
    let mut request = [0u8; 20];
    // Binding Request (0x0001)
    request[0] = 0x00;
    request[1] = 0x01;
    // Message Length: 0
    request[2] = 0x00;
    request[3] = 0x00;
    // Magic Cookie (0x2112A442)
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    // 12-byte Transaction ID
    let mut transaction_id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut transaction_id);
    request[8..20].copy_from_slice(&transaction_id);

    // Resolve STUN server address
    let dest_addr: SocketAddr = tokio::net::lookup_host(stun_server)
        .await?
        .next()
        .ok_or_else(|| NatError::InvalidResponse(format!("Cannot resolve STUN host: {stun_server}")))?;

    socket.send_to(&request, dest_addr).await?;

    let mut buf = [0u8; 512];
    let (len, _) = timeout(timeout_duration, socket.recv_from(&mut buf))
        .await
        .map_err(|_| NatError::Timeout)??;

    parse_stun_response(&buf[..len], &transaction_id)
}

fn parse_stun_response(data: &[u8], expected_tx_id: &[u8; 12]) -> Result<SocketAddr, NatError> {
    if data.len() < 20 {
        return Err(NatError::InvalidResponse("Response too short".into()));
    }

    // Check message type (0x0101 = Binding Success Response)
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return Err(NatError::InvalidResponse(format!("Unexpected message type: 0x{msg_type:04X}")));
    }

    // Check transaction ID
    if &data[8..20] != expected_tx_id {
        return Err(NatError::InvalidResponse("Transaction ID mismatch".into()));
    }

    let mut offset = 20;
    while offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        let attr_val = &data[offset..offset + attr_len];
        // 0x0020: XOR-MAPPED-ADDRESS, 0x0001: MAPPED-ADDRESS
        if attr_type == 0x0020 && attr_len >= 8 {
            let family = attr_val[1];
            if family == 0x01 {
                // IPv4
                let xor_port = u16::from_be_bytes([attr_val[2], attr_val[3]]);
                let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

                let xor_ip = u32::from_be_bytes([attr_val[4], attr_val[5], attr_val[6], attr_val[7]]);
                let ip_u32 = xor_ip ^ STUN_MAGIC_COOKIE;
                let ip = IpAddr::V4(Ipv4Addr::from(ip_u32));

                return Ok(SocketAddr::new(ip, port));
            }
        }

        // Align to 4 bytes boundary
        offset += (attr_len + 3) & !3;
    }

    Err(NatError::InvalidResponse("No XOR-MAPPED-ADDRESS found in STUN response".into()))
}
