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

/// Attempts to automatically forward a local port on the domestic router using UPnP / IGD.
pub async fn forward_port_upnp(local_port: u16, external_port: u16) -> Result<(), String> {
    use igd::aio::search_gateway;
    use igd::PortMappingProtocol;
    use std::net::SocketAddrV4;

    // Detect local network IPv4 address by probing routing table
    let probe_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    let _ = probe_socket.connect("1.1.1.1:80").await;
    let local_ip = match probe_socket.local_addr() {
        Ok(SocketAddr::V4(addr)) => *addr.ip(),
        _ => return Err("Could not detect local IPv4 address".into()),
    };

    let local_socket = SocketAddrV4::new(local_ip, local_port);
    // Bind the SSDP search to the interface that actually routes to the Internet,
    // otherwise multicast may leave through a VPN / virtual adapter and time out.
    let options = igd::SearchOptions {
        bind_addr: SocketAddr::V4(SocketAddrV4::new(local_ip, 0)),
        ..Default::default()
    };
    let gateway = search_gateway(options)
        .await
        .map_err(|e| format!("UPnP search failed: {e}"))?;

    gateway
        .add_port(
            PortMappingProtocol::UDP,
            external_port,
            local_socket,
            3600, // 1 hour lease
            "GhostMesh P2P Overlay",
        )
        .await
        .map_err(|e| format!("UPnP port mapping failed: {e}"))?;

    tracing::info!("UPnP successfully mapped external UDP port {external_port} to {local_socket}");
    Ok(())
}

/// Outcome of the automatic port-mapping attempts (UPnP-IGD, then NAT-PMP, then PCP).
#[derive(Debug, Clone, Default)]
pub struct MappingReport {
    /// Protocol that opened the UDP port ("UPnP", "NAT-PMP", "PCP"), `None` if all failed.
    pub method: Option<String>,
    pub upnp: String,
    pub natpmp: String,
    pub pcp: String,
    /// Router WAN address when the router told us (used to detect double NAT / CGNAT).
    pub external_ip: Option<Ipv4Addr>,
    pub udp_mapped: bool,
    /// External TCP ports that now lead to the local TCP listener.
    pub tcp_ports: Vec<u16>,
}

/// TCP port tried as an extra external port: it is almost never filtered by corporate networks.
pub const TCP_FALLBACK_EXTERNAL_PORT: u16 = 443;

fn local_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

fn gateway_candidates(local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut gws = Vec::new();
    if let Ok(gw) = default_net::get_default_gateway() {
        if let IpAddr::V4(v4) = gw.ip_addr {
            gws.push(v4);
        }
    }
    let o = local.octets();
    for last in [1u8, 254] {
        let guess = Ipv4Addr::new(o[0], o[1], o[2], last);
        if !gws.contains(&guess) {
            gws.push(guess);
        }
    }
    gws
}

async fn upnp_map(local_ip: Ipv4Addr, udp_port: u16, tcp_port: Option<u16>, report: &mut MappingReport) -> bool {
    use igd::aio::search_gateway;
    use igd::PortMappingProtocol;
    use std::net::SocketAddrV4;

    // Bind the SSDP search to the interface that actually routes to the Internet,
    // otherwise multicast may leave through a VPN / virtual adapter and time out.
    let options = igd::SearchOptions {
        bind_addr: SocketAddr::V4(SocketAddrV4::new(local_ip, 0)),
        ..Default::default()
    };
    let gateway = match search_gateway(options).await {
        Ok(g) => g,
        Err(e) => {
            report.upnp = format!("gateway not found ({e})");
            return false;
        }
    };

    if let Ok(ip) = gateway.get_external_ip().await {
        report.external_ip = Some(ip);
    }

    if let Err(e) = gateway
        .add_port(
            PortMappingProtocol::UDP,
            udp_port,
            SocketAddrV4::new(local_ip, udp_port),
            3600,
            "GhostMesh P2P Overlay",
        )
        .await
    {
        report.upnp = format!("UDP mapping refused ({e})");
        return false;
    }

    if let Some(tcp_local) = tcp_port {
        for external in [TCP_FALLBACK_EXTERNAL_PORT, udp_port] {
            if gateway
                .add_port(
                    PortMappingProtocol::TCP,
                    external,
                    SocketAddrV4::new(local_ip, tcp_local),
                    3600,
                    "GhostMesh TCP fallback",
                )
                .await
                .is_ok()
                && !report.tcp_ports.contains(&external)
            {
                report.tcp_ports.push(external);
            }
        }
    }

    report.upnp = "ok".into();
    true
}

/// RFC 6886 NAT-PMP request/response exchange. `opcode` 1 = UDP, 2 = TCP.
async fn natpmp_request(gw: Ipv4Addr, opcode: u8, internal: u16, external: u16) -> Result<u16, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    let mut req = [0u8; 12];
    req[1] = opcode;
    req[4..6].copy_from_slice(&internal.to_be_bytes());
    req[6..8].copy_from_slice(&external.to_be_bytes());
    req[8..12].copy_from_slice(&3600u32.to_be_bytes());

    let mut buf = [0u8; 32];
    for _ in 0..3 {
        socket
            .send_to(&req, SocketAddr::new(IpAddr::V4(gw), 5351))
            .await
            .map_err(|e| e.to_string())?;
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(600), socket.recv_from(&mut buf)).await {
            if n >= 16 && buf[1] == opcode + 128 {
                let result = u16::from_be_bytes([buf[2], buf[3]]);
                if result != 0 {
                    return Err(format!("NAT-PMP result code {result}"));
                }
                return Ok(u16::from_be_bytes([buf[10], buf[11]]));
            }
        }
    }
    Err("no answer".into())
}

async fn natpmp_external_ip(gw: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let req = [0u8, 0u8];
    let mut buf = [0u8; 16];
    for _ in 0..2 {
        socket.send_to(&req, SocketAddr::new(IpAddr::V4(gw), 5351)).await.ok()?;
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            if n >= 12 && buf[1] == 128 && buf[2] == 0 && buf[3] == 0 {
                return Some(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]));
            }
        }
    }
    None
}

async fn natpmp_map(local_ip: Ipv4Addr, udp_port: u16, tcp_port: Option<u16>, report: &mut MappingReport) -> bool {
    for gw in gateway_candidates(local_ip) {
        if natpmp_request(gw, 1, udp_port, udp_port).await.is_err() {
            continue;
        }
        if let Some(ip) = natpmp_external_ip(gw).await {
            report.external_ip = Some(ip);
        }
        if let Some(tcp_local) = tcp_port {
            for external in [TCP_FALLBACK_EXTERNAL_PORT, udp_port] {
                if let Ok(p) = natpmp_request(gw, 2, tcp_local, external).await {
                    if !report.tcp_ports.contains(&p) {
                        report.tcp_ports.push(p);
                    }
                }
            }
        }
        report.natpmp = format!("ok (gateway {gw})");
        return true;
    }
    report.natpmp = "no NAT-PMP gateway answered".into();
    false
}

/// RFC 6887 PCP MAP request. `protocol` is the IANA number (17 = UDP, 6 = TCP).
fn pcp_map_request(local_ip: Ipv4Addr, nonce: [u8; 12], protocol: u8, internal: u16, external: u16) -> [u8; 60] {
    let mut req = [0u8; 60];
    req[0] = 2; // version
    req[1] = 1; // MAP opcode, request
    req[4..8].copy_from_slice(&3600u32.to_be_bytes());
    req[18] = 0xff; // client address as IPv4-mapped IPv6: ::ffff:a.b.c.d
    req[19] = 0xff;
    req[20..24].copy_from_slice(&local_ip.octets());
    req[24..36].copy_from_slice(&nonce);
    req[36] = protocol;
    req[40..42].copy_from_slice(&internal.to_be_bytes());
    req[42..44].copy_from_slice(&external.to_be_bytes());
    req
}

async fn pcp_request(gw: Ipv4Addr, local_ip: Ipv4Addr, protocol: u8, internal: u16, external: u16) -> Result<u16, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let req = pcp_map_request(local_ip, nonce, protocol, internal, external);

    let mut buf = [0u8; 128];
    for _ in 0..3 {
        socket
            .send_to(&req, SocketAddr::new(IpAddr::V4(gw), 5351))
            .await
            .map_err(|e| e.to_string())?;
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(600), socket.recv_from(&mut buf)).await {
            if n >= 60 && buf[0] == 2 && buf[1] == 0x81 && buf[24..36] == nonce {
                if buf[3] != 0 {
                    return Err(format!("PCP result code {}", buf[3]));
                }
                return Ok(u16::from_be_bytes([buf[42], buf[43]]));
            }
        }
    }
    Err("no answer".into())
}

async fn pcp_map(local_ip: Ipv4Addr, udp_port: u16, tcp_port: Option<u16>, report: &mut MappingReport) -> bool {
    for gw in gateway_candidates(local_ip) {
        if pcp_request(gw, local_ip, 17, udp_port, udp_port).await.is_err() {
            continue;
        }
        if let Some(tcp_local) = tcp_port {
            for external in [TCP_FALLBACK_EXTERNAL_PORT, udp_port] {
                if let Ok(p) = pcp_request(gw, local_ip, 6, tcp_local, external).await {
                    if !report.tcp_ports.contains(&p) {
                        report.tcp_ports.push(p);
                    }
                }
            }
        }
        report.pcp = format!("ok (gateway {gw})");
        return true;
    }
    report.pcp = "no PCP gateway answered".into();
    false
}

/// Opens the UDP port (and TCP fallback ports) on the home router automatically.
/// Tries UPnP-IGD first, then NAT-PMP, then PCP, and reports what happened for diagnostics.
pub async fn map_ports(udp_port: u16, tcp_port: Option<u16>) -> MappingReport {
    let mut report = MappingReport::default();
    let Some(local_ip) = local_ipv4() else {
        report.upnp = "no local IPv4 interface".into();
        return report;
    };

    if upnp_map(local_ip, udp_port, tcp_port, &mut report).await {
        report.method = Some("UPnP".into());
        report.udp_mapped = true;
    } else if natpmp_map(local_ip, udp_port, tcp_port, &mut report).await {
        report.method = Some("NAT-PMP".into());
        report.udp_mapped = true;
    } else if pcp_map(local_ip, udp_port, tcp_port, &mut report).await {
        report.method = Some("PCP".into());
        report.udp_mapped = true;
    }

    if report.upnp.is_empty() {
        report.upnp = "skipped".into();
    }
    if report.natpmp.is_empty() {
        report.natpmp = "skipped".into();
    }
    if report.pcp.is_empty() {
        report.pcp = "skipped".into();
    }
    report
}

#[cfg(test)]
mod mapping_tests {
    use super::*;

    #[test]
    fn pcp_map_request_layout() {
        let req = pcp_map_request(Ipv4Addr::new(192, 168, 0, 117), [7u8; 12], 17, 4242, 4242);
        assert_eq!(req.len(), 60);
        assert_eq!(req[0], 2);
        assert_eq!(req[1], 1);
        assert_eq!(&req[18..20], &[0xff, 0xff]);
        assert_eq!(&req[20..24], &[192, 168, 0, 117]);
        assert_eq!(&req[24..36], &[7u8; 12]);
        assert_eq!(req[36], 17);
        assert_eq!(u16::from_be_bytes([req[40], req[41]]), 4242);
        assert_eq!(u16::from_be_bytes([req[42], req[43]]), 4242);
    }
}
