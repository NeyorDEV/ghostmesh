//! Per-peer packet filter applied to the IP packets read from and written to the TUN device.
//!
//! Restricted profiles deny everything by default. What a rule allows is described from the point
//! of view of this machine: `In` packets come from the peer towards us (the peer reaching one of our
//! services), `Out` packets go from us to the peer. Replies to an allowed connection are let
//! through by a small flow table, so a restricted peer can use an allowed service but nothing else.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ICMPV6: u8 = 58;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const MAX_FLOWS: usize = 4096;
const TCP_FLOW_TTL: Duration = Duration::from_secs(300);
const UDP_FLOW_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
}

impl Flow {
    fn reversed(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            proto: self.proto,
            sport: self.dport,
            dport: self.sport,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub flow: Flow,
    /// Not the first fragment: there is no transport header to read ports from.
    pub later_fragment: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Neither IPv4 nor IPv6.
    NotIp,
    Malformed,
    /// IPv6 packet with extension headers: the ports cannot be read safely, so it is refused.
    ExtensionHeader,
    Fragment,
    NoRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(DenyReason),
}

/// Reads the addresses, protocol and ports of an IPv4 or IPv6 packet, rejecting anything inconsistent.
pub fn parse_packet(pkt: &[u8]) -> Result<Parsed, DenyReason> {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => parse_v4(pkt),
        Some(6) => parse_v6(pkt),
        Some(_) => Err(DenyReason::NotIp),
        None => Err(DenyReason::Malformed),
    }
}

fn read_ports(proto: u8, l4: &[u8]) -> Result<(u16, u16), DenyReason> {
    if l4.len() < 8 || (proto == PROTO_TCP && l4.len() < 20) {
        return Err(DenyReason::Malformed);
    }
    Ok((
        u16::from_be_bytes([l4[0], l4[1]]),
        u16::from_be_bytes([l4[2], l4[3]]),
    ))
}

fn parse_v6(pkt: &[u8]) -> Result<Parsed, DenyReason> {
    if pkt.len() < 40 {
        return Err(DenyReason::Malformed);
    }
    let total = 40 + usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if total > pkt.len() {
        return Err(DenyReason::Malformed);
    }
    let proto = pkt[6];
    let addr = |at: usize| {
        let mut o = [0u8; 16];
        o.copy_from_slice(&pkt[at..at + 16]);
        IpAddr::V6(Ipv6Addr::from(o))
    };
    let (mut sport, mut dport) = (0, 0);
    match proto {
        PROTO_TCP | PROTO_UDP => (sport, dport) = read_ports(proto, &pkt[40..total])?,
        PROTO_ICMPV6 => {}
        _ => return Err(DenyReason::ExtensionHeader),
    }
    Ok(Parsed {
        flow: Flow {
            src: addr(8),
            dst: addr(24),
            proto,
            sport,
            dport,
        },
        later_fragment: false,
    })
}

fn parse_v4(pkt: &[u8]) -> Result<Parsed, DenyReason> {
    if pkt.len() < 20 {
        return Err(DenyReason::Malformed);
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if ihl < 20 || total < ihl || total > pkt.len() {
        return Err(DenyReason::Malformed);
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let offset = frag & 0x1FFF;
    let proto = pkt[9];
    let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let (mut sport, mut dport) = (0, 0);
    if offset == 0 && (proto == PROTO_TCP || proto == PROTO_UDP) {
        (sport, dport) = read_ports(proto, &pkt[ihl..total])?;
    }
    Ok(Parsed {
        flow: Flow {
            src,
            dst,
            proto,
            sport,
            dport,
        },
        later_fragment: offset > 0,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, p: u16) -> bool {
        (self.start..=self.end).contains(&p)
    }
}

impl FromStr for PortRange {
    type Err = String;

    /// `8765` or `8000-8100`.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (a, b) = match s.split_once('-') {
            Some((a, b)) => (a, b),
            None => (s, s),
        };
        let start: u16 = a
            .trim()
            .parse()
            .map_err(|_| format!("invalid port '{s}'"))?;
        let end: u16 = b
            .trim()
            .parse()
            .map_err(|_| format!("invalid port '{s}'"))?;
        if start == 0 || start > end {
            return Err(format!("invalid port range '{s}'"));
        }
        Ok(Self { start, end })
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl FromStr for Proto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            "any" => Ok(Self::Any),
            other => Err(format!("unknown protocol '{other}' (tcp, udp, icmp, any)")),
        }
    }
}

impl FromStr for Direction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "in" => Ok(Self::In),
            "out" => Ok(Self::Out),
            "both" => Ok(Self::Both),
            other => Err(format!("unknown direction '{other}' (in, out, both)")),
        }
    }
}

/// Allows packets of one protocol towards some destination ports, in one direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub direction: Direction,
    pub proto: Proto,
    /// Destination ports; empty means every port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
}

impl Rule {
    fn matches(&self, dir: Dir, p: &Parsed) -> bool {
        let dir_ok = matches!(
            (self.direction, dir),
            (Direction::Both, _) | (Direction::In, Dir::In) | (Direction::Out, Dir::Out)
        );
        if !dir_ok {
            return false;
        }
        let proto = p.flow.proto;
        let proto_ok = match self.proto {
            Proto::Tcp => proto == PROTO_TCP,
            Proto::Udp => proto == PROTO_UDP,
            Proto::Icmp => proto == PROTO_ICMP || proto == PROTO_ICMPV6,
            Proto::Any => true,
        };
        if !proto_ok {
            return false;
        }
        if p.later_fragment {
            return false;
        }
        let has_ports = proto == PROTO_TCP || proto == PROTO_UDP;
        if self.ports.is_empty() || self.proto == Proto::Icmp || !has_ports {
            return self.ports.is_empty() || self.proto == Proto::Icmp;
        }
        self.ports.iter().any(|r| r.contains(p.flow.dport))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// No restriction (the behaviour before access control existed).
    #[default]
    Full,
    /// A phone or other untrusted client: it may reach only the TCP ports listed in `ports`.
    Phone,
    /// Web browsing of our pages: TCP 80 and 443.
    Web,
    /// Remote desktop: TCP and UDP 3389.
    Rdp,
    /// Only the rules written in the policy.
    Custom,
    /// Nothing at all.
    Blocked,
}

impl FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "phone" => Ok(Self::Phone),
            "web" => Ok(Self::Web),
            "rdp" => Ok(Self::Rdp),
            "custom" => Ok(Self::Custom),
            "blocked" => Ok(Self::Blocked),
            other => Err(format!(
                "unknown profile '{other}' (full, phone, web, rdp, custom, blocked)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccessPolicy {
    #[serde(default)]
    pub profile: Profile,
    /// Ports opened by the `phone` profile.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    /// Rules of the `custom` profile.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl AccessPolicy {
    pub fn full() -> Self {
        Self::default()
    }

    pub fn phone(ports: Vec<PortRange>) -> Self {
        Self {
            profile: Profile::Phone,
            ports,
            rules: Vec::new(),
        }
    }

    fn compiled_rules(&self) -> Vec<Rule> {
        let port = |p: u16| PortRange { start: p, end: p };
        match self.profile {
            Profile::Full | Profile::Blocked => Vec::new(),
            Profile::Phone => vec![Rule {
                direction: Direction::In,
                proto: Proto::Tcp,
                ports: self.ports.clone(),
            }],
            Profile::Web => vec![Rule {
                direction: Direction::In,
                proto: Proto::Tcp,
                ports: vec![port(80), port(443)],
            }],
            Profile::Rdp => vec![
                Rule {
                    direction: Direction::In,
                    proto: Proto::Tcp,
                    ports: vec![port(3389)],
                },
                Rule {
                    direction: Direction::In,
                    proto: Proto::Udp,
                    ports: vec![port(3389)],
                },
            ],
            Profile::Custom => self.rules.clone(),
        }
    }
}

/// Filter state for one peer: its rules plus the flows opened by allowed packets.
#[derive(Debug)]
pub struct PeerFilter {
    policy: AccessPolicy,
    rules: Vec<Rule>,
    flows: HashMap<Flow, (Dir, Instant)>,
}

impl PeerFilter {
    pub fn new(policy: AccessPolicy) -> Self {
        let rules = policy.compiled_rules();
        Self {
            policy,
            rules,
            flows: HashMap::new(),
        }
    }

    pub fn policy(&self) -> &AccessPolicy {
        &self.policy
    }

    pub fn is_unrestricted(&self) -> bool {
        self.policy.profile == Profile::Full
    }

    fn live(&self, key: &Flow, want: Dir, now: Instant) -> bool {
        match self.flows.get(key) {
            Some((dir, seen)) if *dir == want => {
                let ttl = if key.proto == PROTO_TCP {
                    TCP_FLOW_TTL
                } else {
                    UDP_FLOW_TTL
                };
                now.duration_since(*seen) < ttl
            }
            _ => false,
        }
    }

    pub fn check(&mut self, dir: Dir, pkt: &[u8], now: Instant) -> Verdict {
        if self.is_unrestricted() {
            return Verdict::Allow;
        }
        let parsed = match parse_packet(pkt) {
            Ok(p) => p,
            Err(r) => return Verdict::Deny(r),
        };
        if parsed.later_fragment {
            return Verdict::Deny(DenyReason::Fragment);
        }
        let flow = parsed.flow;
        let trackable = flow.proto == PROTO_TCP || flow.proto == PROTO_UDP;

        // A reply to a flow that an earlier allowed packet opened in the other direction.
        let opened_by = if dir == Dir::In { Dir::Out } else { Dir::In };
        if trackable && self.live(&flow.reversed(), opened_by, now) {
            self.flows.insert(flow.reversed(), (opened_by, now));
            return Verdict::Allow;
        }

        if self.rules.iter().any(|r| r.matches(dir, &parsed)) {
            if trackable {
                if self.flows.len() >= MAX_FLOWS {
                    self.flows.retain(|k, (_, seen)| {
                        let ttl = if k.proto == PROTO_TCP {
                            TCP_FLOW_TTL
                        } else {
                            UDP_FLOW_TTL
                        };
                        now.duration_since(*seen) < ttl
                    });
                }
                if self.flows.len() < MAX_FLOWS || self.flows.contains_key(&flow) {
                    self.flows.insert(flow, (dir, now));
                }
            }
            return Verdict::Allow;
        }
        Verdict::Deny(DenyReason::NoRule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PC: Ipv4Addr = Ipv4Addr::new(10, 42, 1, 1);
    const PHONE: Ipv4Addr = Ipv4Addr::new(10, 42, 2, 2);

    /// Builds a real IPv4 packet with a TCP/UDP header (or ICMP) and `payload` bytes.
    fn ip_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        sport: u16,
        dport: u16,
        payload: usize,
    ) -> Vec<u8> {
        let l4_len = match proto {
            PROTO_TCP => 20,
            PROTO_UDP => 8,
            _ => 8,
        };
        let total = 20 + l4_len + payload;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        if proto == PROTO_TCP || proto == PROTO_UDP {
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p[22..24].copy_from_slice(&dport.to_be_bytes());
        }
        if proto == PROTO_TCP {
            p[32] = 0x50;
        }
        p
    }

    fn phone_filter() -> PeerFilter {
        PeerFilter::new(AccessPolicy::phone(vec![
            "8765".parse().unwrap(),
            "5173".parse().unwrap(),
        ]))
    }

    #[test]
    fn phone_profile_reaches_only_the_chosen_ports() {
        let mut f = phone_filter();
        let now = Instant::now();
        let tcp = |dport| ip_packet(PHONE, PC, PROTO_TCP, 50000, dport, 10);

        assert_eq!(f.check(Dir::In, &tcp(8765), now), Verdict::Allow);
        assert_eq!(f.check(Dir::In, &tcp(5173), now), Verdict::Allow);
        assert_eq!(
            f.check(Dir::In, &tcp(3389), now),
            Verdict::Deny(DenyReason::NoRule),
            "RDP is not opened"
        );
        assert_eq!(
            f.check(Dir::In, &tcp(22), now),
            Verdict::Deny(DenyReason::NoRule)
        );
        assert_eq!(
            f.check(Dir::In, &tcp(8766), now),
            Verdict::Deny(DenyReason::NoRule)
        );
        // UDP on an allowed port number, ping and unknown protocols are refused.
        assert_eq!(
            f.check(
                Dir::In,
                &ip_packet(PHONE, PC, PROTO_UDP, 5000, 8765, 4),
                now
            ),
            Verdict::Deny(DenyReason::NoRule)
        );
        assert_eq!(
            f.check(Dir::In, &ip_packet(PHONE, PC, PROTO_ICMP, 0, 0, 4), now),
            Verdict::Deny(DenyReason::NoRule)
        );
        assert_eq!(
            f.check(Dir::In, &ip_packet(PHONE, PC, 47, 0, 0, 4), now),
            Verdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn we_cannot_open_connections_towards_a_phone_but_replies_flow() {
        let mut f = phone_filter();
        let now = Instant::now();
        // The PC trying to reach a service on the phone is refused...
        assert_eq!(
            f.check(
                Dir::Out,
                &ip_packet(PC, PHONE, PROTO_TCP, 40000, 8080, 10),
                now
            ),
            Verdict::Deny(DenyReason::NoRule)
        );
        // ...a reply to an unknown flow too...
        assert_eq!(
            f.check(
                Dir::Out,
                &ip_packet(PC, PHONE, PROTO_TCP, 8765, 50000, 10),
                now
            ),
            Verdict::Deny(DenyReason::NoRule)
        );
        // ...but once the phone opened 8765, the PC's answers go back.
        assert_eq!(
            f.check(
                Dir::In,
                &ip_packet(PHONE, PC, PROTO_TCP, 50000, 8765, 0),
                now
            ),
            Verdict::Allow
        );
        assert_eq!(
            f.check(
                Dir::Out,
                &ip_packet(PC, PHONE, PROTO_TCP, 8765, 50000, 100),
                now
            ),
            Verdict::Allow
        );
        // A different source port on the PC side is not that flow.
        assert_eq!(
            f.check(
                Dir::Out,
                &ip_packet(PC, PHONE, PROTO_TCP, 8765, 50001, 10),
                now
            ),
            Verdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn flows_expire() {
        let mut f = phone_filter();
        let t0 = Instant::now();
        assert_eq!(
            f.check(
                Dir::In,
                &ip_packet(PHONE, PC, PROTO_TCP, 50000, 8765, 0),
                t0
            ),
            Verdict::Allow
        );
        let later = t0 + TCP_FLOW_TTL + Duration::from_secs(1);
        assert_eq!(
            f.check(
                Dir::Out,
                &ip_packet(PC, PHONE, PROTO_TCP, 8765, 50000, 10),
                later
            ),
            Verdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn malformed_and_non_ipv4_packets_are_denied() {
        let mut f = phone_filter();
        let now = Instant::now();
        assert_eq!(
            f.check(Dir::In, &[], now),
            Verdict::Deny(DenyReason::Malformed)
        );
        assert_eq!(
            f.check(Dir::In, &[0x45, 0, 0], now),
            Verdict::Deny(DenyReason::Malformed)
        );
        let mut v6 = vec![0u8; 60];
        v6[0] = 0x60;
        assert_eq!(
            f.check(Dir::In, &v6, now),
            Verdict::Deny(DenyReason::ExtensionHeader)
        );
        v6[0] = 0x90;
        assert_eq!(f.check(Dir::In, &v6, now), Verdict::Deny(DenyReason::NotIp));
        // Length field larger than the buffer, and a header length below the minimum.
        let mut p = ip_packet(PHONE, PC, PROTO_TCP, 1, 8765, 0);
        p[2..4].copy_from_slice(&9000u16.to_be_bytes());
        assert_eq!(
            f.check(Dir::In, &p, now),
            Verdict::Deny(DenyReason::Malformed)
        );
        let mut p = ip_packet(PHONE, PC, PROTO_TCP, 1, 8765, 0);
        p[0] = 0x44;
        assert_eq!(
            f.check(Dir::In, &p, now),
            Verdict::Deny(DenyReason::Malformed)
        );
        // TCP packet cut right after the IP header.
        let mut p = ip_packet(PHONE, PC, PROTO_TCP, 1, 8765, 0);
        p.truncate(24);
        p[2..4].copy_from_slice(&24u16.to_be_bytes());
        assert_eq!(
            f.check(Dir::In, &p, now),
            Verdict::Deny(DenyReason::Malformed)
        );
    }

    /// Real IPv6 packet: 40-byte header followed by a TCP header.
    fn v6_tcp(src: [u8; 16], dst: [u8; 16], dport: u16, payload: usize) -> Vec<u8> {
        let l4 = 20 + payload;
        let mut p = vec![0u8; 40 + l4];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(l4 as u16).to_be_bytes());
        p[6] = PROTO_TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40..42].copy_from_slice(&50000u16.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p[52] = 0x50;
        p
    }

    #[test]
    fn ipv6_is_filtered_like_ipv4() {
        let mut f = phone_filter();
        let now = Instant::now();
        let pc = [0xfd, 0x42, 0x47, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let phone = [0xfd, 0x42, 0x47, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        assert_eq!(
            f.check(Dir::In, &v6_tcp(phone, pc, 8765, 10), now),
            Verdict::Allow
        );
        assert_eq!(
            f.check(Dir::In, &v6_tcp(phone, pc, 22, 10), now),
            Verdict::Deny(DenyReason::NoRule)
        );
        // The reply goes back to the phone.
        let mut reply = v6_tcp(pc, phone, 50000, 10);
        reply[40..42].copy_from_slice(&8765u16.to_be_bytes());
        assert_eq!(f.check(Dir::Out, &reply, now), Verdict::Allow);
        // Extension headers hide the transport header: refused.
        let mut ext = v6_tcp(phone, pc, 8765, 10);
        ext[6] = 44;
        assert_eq!(
            f.check(Dir::In, &ext, now),
            Verdict::Deny(DenyReason::ExtensionHeader)
        );
        // Declared length longer than the buffer, and a truncated header.
        let mut long = v6_tcp(phone, pc, 8765, 10);
        long[4..6].copy_from_slice(&9000u16.to_be_bytes());
        assert_eq!(
            f.check(Dir::In, &long, now),
            Verdict::Deny(DenyReason::Malformed)
        );
        assert_eq!(
            f.check(Dir::In, &long[..30], now),
            Verdict::Deny(DenyReason::Malformed)
        );
    }

    #[test]
    fn fragments_cannot_smuggle_traffic() {
        let mut f = phone_filter();
        let now = Instant::now();
        // A later fragment has no ports to check: refused. Its bytes could be anything.
        let mut frag = ip_packet(PHONE, PC, PROTO_TCP, 0, 0, 100);
        frag[6..8].copy_from_slice(&0x00B9u16.to_be_bytes());
        assert_eq!(
            f.check(Dir::In, &frag, now),
            Verdict::Deny(DenyReason::Fragment)
        );
        // A first fragment to a closed port is refused like any other packet.
        let mut first = ip_packet(PHONE, PC, PROTO_TCP, 50000, 22, 100);
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert_eq!(
            f.check(Dir::In, &first, now),
            Verdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn full_and_blocked_profiles() {
        let now = Instant::now();
        let mut full = PeerFilter::new(AccessPolicy::full());
        assert_eq!(
            full.check(Dir::In, b"not even an ip packet", now),
            Verdict::Allow
        );
        let mut blocked = PeerFilter::new(AccessPolicy {
            profile: Profile::Blocked,
            ..Default::default()
        });
        assert_eq!(
            blocked.check(Dir::In, &ip_packet(PHONE, PC, PROTO_TCP, 1, 80, 0), now),
            Verdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn presets_and_custom_rules() {
        let now = Instant::now();
        let tcp = |dport| ip_packet(PHONE, PC, PROTO_TCP, 50000, dport, 0);
        let mut web = PeerFilter::new(AccessPolicy {
            profile: Profile::Web,
            ..Default::default()
        });
        assert_eq!(web.check(Dir::In, &tcp(443), now), Verdict::Allow);
        assert_eq!(
            web.check(Dir::In, &tcp(8443), now),
            Verdict::Deny(DenyReason::NoRule)
        );

        let mut rdp = PeerFilter::new(AccessPolicy {
            profile: Profile::Rdp,
            ..Default::default()
        });
        assert_eq!(rdp.check(Dir::In, &tcp(3389), now), Verdict::Allow);
        assert_eq!(
            rdp.check(Dir::In, &ip_packet(PHONE, PC, PROTO_UDP, 5, 3389, 0), now),
            Verdict::Allow
        );

        // Custom: ping both ways plus a UDP range we may open towards the peer.
        let rules = vec![
            Rule {
                direction: Direction::Both,
                proto: Proto::Icmp,
                ports: vec![],
            },
            Rule {
                direction: Direction::Out,
                proto: Proto::Udp,
                ports: vec!["9000-9010".parse().unwrap()],
            },
        ];
        let mut c = PeerFilter::new(AccessPolicy {
            profile: Profile::Custom,
            ports: vec![],
            rules,
        });
        assert_eq!(
            c.check(Dir::In, &ip_packet(PHONE, PC, PROTO_ICMP, 0, 0, 8), now),
            Verdict::Allow
        );
        assert_eq!(
            c.check(Dir::Out, &ip_packet(PC, PHONE, PROTO_UDP, 1, 9005, 8), now),
            Verdict::Allow
        );
        assert_eq!(
            c.check(Dir::Out, &ip_packet(PC, PHONE, PROTO_UDP, 1, 9011, 8), now),
            Verdict::Deny(DenyReason::NoRule)
        );
        assert_eq!(
            c.check(Dir::In, &ip_packet(PHONE, PC, PROTO_UDP, 1, 9005, 8), now),
            Verdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn port_range_parsing_and_serde() {
        assert_eq!(
            "80".parse::<PortRange>().unwrap(),
            PortRange { start: 80, end: 80 }
        );
        assert_eq!(
            "8000-8100".parse::<PortRange>().unwrap().to_string(),
            "8000-8100"
        );
        assert!("0".parse::<PortRange>().is_err());
        assert!("9-3".parse::<PortRange>().is_err());
        assert!("abc".parse::<PortRange>().is_err());
        assert!("70000".parse::<PortRange>().is_err());
        let policy = AccessPolicy::phone(vec!["8765".parse().unwrap(), "5173".parse().unwrap()]);
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(serde_json::from_str::<AccessPolicy>(&json).unwrap(), policy);
        assert_eq!(
            serde_json::from_str::<AccessPolicy>("{}").unwrap().profile,
            Profile::Full
        );
    }
}
