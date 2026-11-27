//! Local name resolver: `<name>.ghost` -> virtual IP of that device.
//!
//! A tiny authoritative DNS server for the `.ghost` zone only. It answers A queries from the list of
//! paired devices (and this machine), says "no such name" for other `.ghost` names and refuses
//! everything else, so it can never be used as an open resolver. Hooking it into the operating
//! system (so that browsers use it for `.ghost`) is done by `os_install_commands`.

use crate::config::AppConfig;
use ghost_protocol::NodeId;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::warn;

pub const ZONE: &str = "ghost";
const TYPE_A: u16 = 1;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const TTL: u32 = 30;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;
const RCODE_NOTIMP: u8 = 4;

pub type NameTable = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

/// Turns a device alias into a valid DNS label (`My Laptop` -> `my-laptop`).
pub fn sanitize_label(alias: &str) -> Option<String> {
    let mut out = String::new();
    for c in alias.trim().chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if (c == '-' || c == '_' || c == ' ' || c == '.')
            && !out.ends_with('-')
            && !out.is_empty()
        {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    (!out.is_empty()).then(|| out.chars().take(63).collect())
}

/// Names of this machine and of every saved device (revoked ones excluded). On a clash the first
/// device keeps the name.
pub fn build_names(cfg: &AppConfig, self_id: NodeId, self_name: &str) -> HashMap<String, Ipv4Addr> {
    let mut names = HashMap::new();
    if let Some(label) = sanitize_label(self_name) {
        names.insert(label, self_id.to_virtual_ip());
    }
    for k in cfg.known_peers.iter().filter(|k| !k.revoked) {
        let (Some(label), Ok(id)) = (sanitize_label(&k.alias), k.node_id.parse::<NodeId>()) else {
            continue;
        };
        names.entry(label).or_insert_with(|| id.to_virtual_ip());
    }
    names
}

/// Reads a question name; refuses compression pointers and oversized names. Returns the lower-cased
/// labels and the offset just after the name.
fn parse_name(msg: &[u8], mut pos: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut total = 0usize;
    loop {
        let len = usize::from(*msg.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // also rejects the 0xC0 compression pointers, which a question never needs
        }
        total += len + 1;
        if total > 253 {
            return None;
        }
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    Some((labels, pos))
}

fn reply(query: &[u8], question_end: usize, rcode: u8, answer: Option<Ipv4Addr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(question_end + 16);
    out.extend_from_slice(&query[..2]);
    // QR=1, AA=1, keep the opcode and RD of the query
    out.push(0x84 | (query[2] & 0x01) | (query[2] & 0x78));
    out.push(rcode & 0x0F);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&[0, u8::from(answer.is_some())]);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..question_end]);
    if let Some(ip) = answer {
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&[0, 4]);
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// Builds the answer to one DNS query, or `None` when the bytes are not a query we should answer.
pub fn answer(query: &[u8], names: &HashMap<String, Ipv4Addr>) -> Option<Vec<u8>> {
    if query.len() < 12 || query.len() > 512 {
        return None;
    }
    let is_response = query[2] & 0x80 != 0;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if is_response || qdcount != 1 {
        return None;
    }
    let (labels, pos) = parse_name(query, 12)?;
    let tail = query.get(pos..pos + 4)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    let end = pos + 4;

    if query[2] & 0x78 != 0 {
        return Some(reply(query, end, RCODE_NOTIMP, None));
    }
    if labels.len() < 2 || labels.last().map(String::as_str) != Some(ZONE) {
        return Some(reply(query, end, RCODE_REFUSED, None));
    }
    let host = labels[..labels.len() - 1].join(".");
    match names.get(&host) {
        Some(ip) if qclass == CLASS_IN && (qtype == TYPE_A || qtype == TYPE_ANY) => {
            Some(reply(query, end, 0, Some(*ip)))
        }
        // The name exists but has no record of this type (AAAA, ...): "no data", not "no such name".
        Some(_) => Some(reply(query, end, 0, None)),
        None => Some(reply(query, end, RCODE_NXDOMAIN, None)),
    }
}

/// Serves the `.ghost` zone on `socket` until the task is dropped.
pub async fn serve(socket: UdpSocket, names: NameTable) {
    let mut buf = [0u8; 600];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                let response = {
                    let table = names.read().await;
                    answer(&buf[..len], &table)
                };
                if let Some(r) = response {
                    let _ = socket.send_to(&r, from).await;
                }
            }
            Err(e) => {
                warn!("DNS socket error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

/// Commands that make the operating system send `.ghost` lookups to the resolver at `dns_ip`.
/// Returned as data so they can be shown, tested and run with the right privileges.
pub fn os_install_commands(dns_ip: Ipv4Addr, interface: &str) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if cfg!(windows) {
        // Name Resolution Policy Table rule: only the `.ghost` namespace goes to our resolver.
        vec![s(&[
            "powershell",
            "-NoProfile",
            "-Command",
            &format!("Add-DnsClientNrptRule -Namespace '.{ZONE}' -NameServers '{dns_ip}' -Comment 'GhostMesh'"),
        ])]
    } else if cfg!(target_os = "macos") {
        vec![
            s(&["mkdir", "-p", "/etc/resolver"]),
            s(&[
                "sh",
                "-c",
                &format!("echo 'nameserver {dns_ip}' > /etc/resolver/{ZONE}"),
            ]),
        ]
    } else {
        vec![
            s(&["resolvectl", "dns", interface, &dns_ip.to_string()]),
            s(&["resolvectl", "domain", interface, &format!("~{ZONE}")]),
        ]
    }
}

pub fn os_uninstall_commands(interface: &str) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if cfg!(windows) {
        vec![s(&[
            "powershell",
            "-NoProfile",
            "-Command",
            &format!("Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -contains '.{ZONE}' }} | Remove-DnsClientNrptRule -Force"),
        ])]
    } else if cfg!(target_os = "macos") {
        vec![s(&["rm", "-f", &format!("/etc/resolver/{ZONE}")])]
    } else {
        vec![s(&["resolvectl", "revert", interface])]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn table() -> HashMap<String, Ipv4Addr> {
        HashMap::from([("pc".to_string(), Ipv4Addr::new(10, 42, 7, 9))])
    }

    #[test]
    fn answers_a_record_for_a_known_name() {
        let r = answer(&query("PC.ghost", TYPE_A), &table()).unwrap();
        assert_eq!(&r[..2], &[0x12, 0x34], "same transaction id");
        assert_eq!(r[2] & 0x80, 0x80, "is a response");
        assert_eq!(r[3] & 0x0F, 0, "no error");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one answer");
        assert_eq!(&r[r.len() - 4..], &[10, 42, 7, 9]);
    }

    #[test]
    fn unknown_names_and_other_zones() {
        let nx = answer(&query("nobody.ghost", TYPE_A), &table()).unwrap();
        assert_eq!(nx[3] & 0x0F, RCODE_NXDOMAIN);
        let refused = answer(&query("example.com", TYPE_A), &table()).unwrap();
        assert_eq!(refused[3] & 0x0F, RCODE_REFUSED, "never an open resolver");
        let bare = answer(&query("ghost", TYPE_A), &table()).unwrap();
        assert_eq!(bare[3] & 0x0F, RCODE_REFUSED);
        // AAAA for an existing name: no data, but the name exists.
        let aaaa = answer(&query("pc.ghost", 28), &table()).unwrap();
        assert_eq!(aaaa[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([aaaa[6], aaaa[7]]), 0);
    }

    #[test]
    fn malformed_input_is_dropped_without_panicking() {
        let good = query("pc.ghost", TYPE_A);
        for cut in 0..good.len() {
            let _ = answer(&good[..cut], &table());
        }
        assert!(answer(&[], &table()).is_none());
        let mut response = good.clone();
        response[2] |= 0x80;
        assert!(
            answer(&response, &table()).is_none(),
            "responses are not answered"
        );
        let mut pointer = good.clone();
        pointer[12] = 0xC0;
        assert!(
            answer(&pointer, &table()).is_none(),
            "compression pointer in a question"
        );
        let mut two = good.clone();
        two[5] = 2;
        assert!(answer(&two, &table()).is_none());
        assert!(
            answer(&vec![0xFF; 600], &table()).is_none(),
            "oversized datagram"
        );
        let mut long = vec![0u8; 12];
        long[5] = 1;
        for _ in 0..10 {
            long.push(60);
            long.extend_from_slice(&[b'a'; 60]);
        }
        long.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(
            answer(&long, &table()).is_none(),
            "name longer than 253 bytes"
        );
        // Pseudo-random garbage of every length must never panic.
        let mut x = 0x2545F491u32;
        for len in 0..200 {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = answer(&junk, &table());
        }
    }

    #[test]
    fn labels_and_name_table() {
        assert_eq!(sanitize_label("My Laptop").as_deref(), Some("my-laptop"));
        assert_eq!(
            sanitize_label("  Peer_1.local ").as_deref(),
            Some("peer-1-local")
        );
        assert_eq!(sanitize_label("???"), None);
        assert_eq!(sanitize_label(&"a".repeat(100)).unwrap().len(), 63);

        let mut cfg = AppConfig::default();
        let mk = |alias: &str, id: u8, revoked: bool| crate::KnownPeer {
            alias: alias.into(),
            node_id: NodeId::new([id; 16]).to_string(),
            endpoint: "0.0.0.0:0".into(),
            last_seen: String::new(),
            allow_rdp: true,
            allow_ghostdrop: true,
            temporary_session: false,
            revoked,
            expires_at: None,
            access: Default::default(),
        };
        cfg.known_peers = vec![
            mk("Phone", 1, false),
            mk("phone", 2, false),
            mk("Old", 3, true),
        ];
        let names = build_names(&cfg, NodeId::new([9; 16]), "Desktop PC");
        assert_eq!(
            names.get("desktop-pc"),
            Some(&NodeId::new([9; 16]).to_virtual_ip())
        );
        assert_eq!(
            names.get("phone"),
            Some(&NodeId::new([1; 16]).to_virtual_ip()),
            "first one keeps the name"
        );
        assert!(!names.contains_key("old"), "revoked devices have no name");
    }

    #[tokio::test]
    async fn serves_over_udp() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let names: NameTable = Arc::new(RwLock::new(table()));
        tokio::spawn(serve(sock, names));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&query("pc.ghost", TYPE_A), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buf[n - 4..n], &[10, 42, 7, 9]);
    }

    #[test]
    fn os_commands_target_the_ghost_zone() {
        let ip = Ipv4Addr::new(10, 42, 1, 1);
        let all: String = os_install_commands(ip, "ghost0")
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(all.contains("ghost") && all.contains("10.42.1.1"));
        assert!(!os_uninstall_commands("ghost0").is_empty());
    }
}
