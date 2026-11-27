//! NAT behaviour detection and connection strategy.
//!
//! The type of NAT is inferred by asking several STUN servers from the *same* UDP socket: a NAT that
//! hands out the same public address and port to every destination ("cone", endpoint-independent
//! mapping) can be punched through; one that picks a new port per destination ("symmetric") cannot,
//! except in limited cases handled by port prediction.

use super::{parse_stun_response, NatError, DEFAULT_STUN_SERVERS};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// How many predicted ports are tried at most against a symmetric NAT.
pub const MAX_PREDICTED_PORTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// The public port equals the local one: no port translation (open host or static mapping).
    Open,
    /// Same public address and port towards every destination: hole punching works.
    Cone,
    /// A different public port per destination: hole punching fails unless the other side is a cone.
    Symmetric,
    /// Only one STUN server answered, so the behaviour cannot be told.
    Unknown,
    /// No STUN server answered: UDP is probably blocked.
    Blocked,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => "Open (no port translation)",
            Self::Cone => "Cone (hole punching works)",
            Self::Symmetric => "Symmetric (hole punching mostly fails)",
            Self::Unknown => "Unknown (only one STUN server answered)",
            Self::Blocked => "Blocked (no STUN answer, UDP likely filtered)",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatReport {
    pub nat_type: NatType,
    /// `(server, public address it saw)` for each STUN server that answered.
    pub observations: Vec<(String, SocketAddr)>,
}

impl NatReport {
    /// First observed public address, the one advertised to peers.
    pub fn primary(&self) -> Option<SocketAddr> {
        self.observations.first().map(|(_, a)| *a)
    }

    pub fn distinct_addresses(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for (_, a) in &self.observations {
            if !out.contains(a) {
                out.push(*a);
            }
        }
        out
    }
}

/// Decides the NAT type from what several STUN servers reported for one local port.
pub fn classify(local_port: u16, observations: &[(String, SocketAddr)]) -> NatType {
    match observations {
        [] => NatType::Blocked,
        [(_, only)] => {
            if only.port() == local_port {
                NatType::Open
            } else {
                NatType::Unknown
            }
        }
        [first, rest @ ..] => {
            if rest.iter().all(|(_, a)| *a == first.1) {
                if first.1.port() == local_port {
                    NatType::Open
                } else {
                    NatType::Cone
                }
            } else {
                NatType::Symmetric
            }
        }
    }
}

/// Sends a binding request to every server at once from `socket` and collects the answers.
/// Must run while nothing else reads the socket (before the receive loop starts).
pub async fn stun_query_all(
    socket: &UdpSocket,
    servers: &[String],
    wait: Duration,
) -> Vec<(String, SocketAddr)> {
    let mut pending: Vec<([u8; 12], String)> = Vec::new();
    for server in servers {
        let Some(dest) = tokio::net::lookup_host(server.as_str())
            .await
            .ok()
            .and_then(|mut i| i.find(|a| a.is_ipv4()))
        else {
            continue;
        };
        let mut request = [0u8; 20];
        request[1] = 0x01;
        request[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
        let mut tx = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut tx);
        request[8..20].copy_from_slice(&tx);
        if socket.send_to(&request, dest).await.is_ok() {
            pending.push((tx, server.clone()));
        }
    }

    let deadline = Instant::now() + wait;
    let mut found: Vec<(String, SocketAddr)> = Vec::new();
    let mut buf = [0u8; 512];
    while !pending.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Ok(Ok((len, _))) = tokio::time::timeout(left, socket.recv_from(&mut buf)).await else {
            break;
        };
        if let Some(i) = pending
            .iter()
            .position(|(tx, _)| parse_stun_response(&buf[..len], tx).is_ok())
        {
            let (tx, name) = pending.remove(i);
            if let Ok(addr) = parse_stun_response(&buf[..len], &tx) {
                found.push((name, addr));
            }
        }
    }
    // Keep the configured order so the "primary" address is stable.
    found.sort_by_key(|(name, _)| servers.iter().position(|s| s == name).unwrap_or(usize::MAX));
    found
}

pub async fn detect_nat(
    socket: &UdpSocket,
    servers: &[String],
    wait: Duration,
) -> Result<NatReport, NatError> {
    let list: Vec<String> = if servers.is_empty() {
        DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect()
    } else {
        servers.to_vec()
    };
    let local_port = socket.local_addr()?.port();
    let observations = stun_query_all(socket, &list, wait).await;
    Ok(NatReport {
        nat_type: classify(local_port, &observations),
        observations,
    })
}

/// Ports a symmetric NAT is likely to use next, assuming it allocates with a constant step.
/// `observed` are the public ports seen by successive servers. Returns at most
/// [`MAX_PREDICTED_PORTS`] guesses, or nothing when the allocation looks random.
pub fn predict_ports(observed: &[u16]) -> Vec<u16> {
    if observed.len() < 2 {
        return Vec::new();
    }
    let deltas: Vec<i32> = observed
        .windows(2)
        .map(|w| i32::from(w[1]) - i32::from(w[0]))
        .collect();
    let step = deltas[0];
    if step == 0 || step.abs() > 16 || deltas.iter().any(|d| *d != step) {
        return Vec::new();
    }
    let last = i32::from(*observed.last().unwrap_or(&0));
    (1..=MAX_PREDICTED_PORTS as i32)
        .filter_map(|k| u16::try_from(last + step * k).ok())
        .filter(|p| *p >= 1024)
        .collect()
}

/// What to do to connect two nodes, given the NAT behind each of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Both sides send to each other at once: ordinary UDP hole punching.
    Punch,
    /// One side is symmetric: it initiates towards the cone side, helped by port prediction.
    PunchWithPrediction,
    /// Direct connection is not expected to work: traffic goes through the relay (and keeps probing).
    Relay,
}

pub fn strategy(local: NatType, remote: NatType) -> Strategy {
    use NatType::*;
    match (local, remote) {
        (Blocked, _) | (_, Blocked) => Strategy::Relay,
        (Symmetric, Symmetric) => Strategy::Relay,
        (Symmetric, _) | (_, Symmetric) => Strategy::PunchWithPrediction,
        _ => Strategy::Punch,
    }
}

/// True for addresses that cannot be a real public mapping (private ranges, CGNAT 100.64/10, loopback).
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xFE00) == 0xFC00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(list: &[(&str, &str)]) -> Vec<(String, SocketAddr)> {
        list.iter()
            .map(|(n, a)| (n.to_string(), a.parse().unwrap()))
            .collect()
    }

    #[test]
    fn classification_table() {
        let same = obs(&[("a", "203.0.113.1:40000"), ("b", "203.0.113.1:40000")]);
        let diff = obs(&[("a", "203.0.113.1:40000"), ("b", "203.0.113.1:40002")]);
        let open = obs(&[("a", "203.0.113.1:4242"), ("b", "203.0.113.1:4242")]);
        assert_eq!(classify(4242, &[]), NatType::Blocked);
        assert_eq!(classify(4242, &same), NatType::Cone);
        assert_eq!(classify(4242, &diff), NatType::Symmetric);
        assert_eq!(classify(4242, &open), NatType::Open);
        assert_eq!(classify(4242, &same[..1]), NatType::Unknown);
        assert_eq!(classify(4242, &open[..1]), NatType::Open);
    }

    #[test]
    fn port_prediction_is_limited_and_conservative() {
        assert_eq!(
            predict_ports(&[40000, 40002]),
            vec![40004, 40006, 40008, 40010]
        );
        assert_eq!(
            predict_ports(&[40000, 40001, 40002]),
            vec![40003, 40004, 40005, 40006]
        );
        assert!(predict_ports(&[40000]).is_empty());
        assert!(predict_ports(&[40000, 40000]).is_empty());
        assert!(
            predict_ports(&[40000, 41000]).is_empty(),
            "big jumps look random"
        );
        assert!(
            predict_ports(&[40000, 40002, 40009]).is_empty(),
            "irregular steps are not predicted"
        );
        assert!(
            predict_ports(&[65534, 65535]).len() < MAX_PREDICTED_PORTS,
            "ports cannot overflow"
        );
    }

    /// The documented result table: what happens for every pair of NAT behaviours.
    #[test]
    fn connectivity_matrix() {
        use NatType::*;
        use Strategy::*;
        let cases = [
            (Open, Open, Punch),
            (Open, Cone, Punch),
            (Cone, Cone, Punch),
            (Cone, Unknown, Punch),
            (Cone, Symmetric, PunchWithPrediction),
            (Symmetric, Cone, PunchWithPrediction),
            (Open, Symmetric, PunchWithPrediction),
            (Symmetric, Symmetric, Relay),
            (Blocked, Cone, Relay),
            (Symmetric, Blocked, Relay),
        ];
        for (a, b, expected) in cases {
            assert_eq!(strategy(a, b), expected, "{a:?} vs {b:?}");
            assert_eq!(
                strategy(b, a),
                expected,
                "strategy must be symmetric: {b:?} vs {a:?}"
            );
        }
    }

    #[test]
    fn cgnat_and_private_ranges() {
        assert!(is_non_public("100.64.1.1".parse().unwrap()));
        assert!(is_non_public("192.168.1.1".parse().unwrap()));
        assert!(is_non_public("10.0.0.1".parse().unwrap()));
        assert!(!is_non_public("203.0.113.9".parse().unwrap()));
        assert!(!is_non_public("100.128.0.1".parse().unwrap()));
    }

    /// Two local fake STUN servers answering from the same socket: simulated cone and symmetric NATs.
    async fn fake_stun(answer: SocketAddr) -> String {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((len, from)) = sock.recv_from(&mut buf).await {
                if len < 20 {
                    continue;
                }
                let mut resp = vec![0x01, 0x01, 0x00, 0x0C];
                resp.extend_from_slice(&buf[4..20]);
                resp.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
                let port = answer.port() ^ 0x2112;
                resp.extend_from_slice(&port.to_be_bytes());
                if let IpAddr::V4(ip) = answer.ip() {
                    let x = u32::from(ip) ^ 0x2112_A442;
                    resp.extend_from_slice(&x.to_be_bytes());
                }
                let _ = sock.send_to(&resp, from).await;
            }
        });
        addr.to_string()
    }

    #[tokio::test]
    async fn detects_cone_symmetric_and_blocked_with_simulated_servers() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wait = Duration::from_secs(2);

        let a = fake_stun("203.0.113.1:40000".parse().unwrap()).await;
        let b = fake_stun("203.0.113.1:40000".parse().unwrap()).await;
        let cone = detect_nat(&client, &[a, b], wait).await.unwrap();
        assert_eq!(cone.nat_type, NatType::Cone);
        assert_eq!(cone.primary(), Some("203.0.113.1:40000".parse().unwrap()));

        let a = fake_stun("203.0.113.1:40000".parse().unwrap()).await;
        let b = fake_stun("203.0.113.1:40002".parse().unwrap()).await;
        let sym = detect_nat(&client, &[a, b], wait).await.unwrap();
        assert_eq!(sym.nat_type, NatType::Symmetric);
        assert_eq!(sym.distinct_addresses().len(), 2);

        // A dead server must not hang detection.
        let dead = "127.0.0.1:9".to_string();
        let blocked = detect_nat(&client, &[dead], Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(blocked.nat_type, NatType::Blocked);
    }
}
