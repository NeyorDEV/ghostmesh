//! Rendezvous records and the tiny request/response protocol used to publish and look them up.
//!
//! A record says "this node can currently be reached at these addresses". It is signed by the node
//! (the signature is checked by whoever looks it up, so the server cannot forge or alter it).
//! The server never lists nodes: a record can only be fetched by a NodeId the caller already knows.

use crate::{NodeId, ProtocolError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC: &[u8; 4] = b"GMR1";
pub const MAX_ADDRS: usize = 8;
pub const MAX_TTL_SECS: u32 = 3600;
/// Largest signed record: magic + key + times + count + 8 IPv6 addresses + signature.
pub const MAX_SIGNED_RECORD: usize = 4 + 32 + 8 + 4 + 1 + MAX_ADDRS * 19 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousRecord {
    pub node_public: [u8; 32],
    /// Unix time (seconds) of issue; strictly increasing per node, doubles as the anti-replay counter.
    pub issued_at: u64,
    pub ttl_secs: u32,
    pub addrs: Vec<SocketAddr>,
}

fn bad(msg: &str) -> ProtocolError {
    ProtocolError::BufferError(msg.to_string())
}

fn take<const N: usize>(raw: &[u8], pos: usize) -> Result<[u8; N], ProtocolError> {
    raw.get(pos..pos + N)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or_else(|| bad("truncated record"))
}

impl RendezvousRecord {
    pub fn node_id(&self) -> NodeId {
        let mut id = [0u8; 16];
        id.copy_from_slice(&self.node_public[..16]);
        NodeId::new(id)
    }

    /// Canonical bytes that get signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&self.node_public);
        v.extend_from_slice(&self.issued_at.to_be_bytes());
        v.extend_from_slice(&self.ttl_secs.to_be_bytes());
        let addrs: Vec<_> = self.addrs.iter().take(MAX_ADDRS).collect();
        v.push(addrs.len() as u8);
        for a in addrs {
            match a.ip() {
                IpAddr::V4(ip) => {
                    v.push(4);
                    v.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    v.push(6);
                    v.extend_from_slice(&ip.octets());
                }
            }
            v.extend_from_slice(&a.port().to_be_bytes());
        }
        v
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 49 || &raw[..4] != MAGIC {
            return Err(bad("not a rendezvous record"));
        }
        let node_public: [u8; 32] = take(raw, 4)?;
        let issued_at = u64::from_be_bytes(take(raw, 36)?);
        let ttl_secs = u32::from_be_bytes(take(raw, 44)?);
        if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
            return Err(bad("record ttl out of range"));
        }
        let count = raw[48] as usize;
        if count > MAX_ADDRS {
            return Err(bad("too many addresses"));
        }
        let mut pos = 49;
        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let [family] = take::<1>(raw, pos)?;
            pos += 1;
            let ip = match family {
                4 => {
                    let b: [u8; 4] = take(raw, pos)?;
                    pos += 4;
                    IpAddr::V4(Ipv4Addr::from(b))
                }
                6 => {
                    let b: [u8; 16] = take(raw, pos)?;
                    pos += 16;
                    IpAddr::V6(Ipv6Addr::from(b))
                }
                _ => return Err(bad("unknown address family")),
            };
            let port = u16::from_be_bytes(take(raw, pos)?);
            pos += 2;
            addrs.push(SocketAddr::new(ip, port));
        }
        if pos != raw.len() {
            return Err(bad("trailing bytes after record"));
        }
        Ok(Self {
            node_public,
            issued_at,
            ttl_secs,
            addrs,
        })
    }
}

/// A record together with the node's signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    pub body: Vec<u8>,
    pub signature: [u8; 64],
}

impl SignedRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.body.clone();
        v.extend_from_slice(&self.signature);
        v
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 64 + 49 || raw.len() > MAX_SIGNED_RECORD {
            return Err(bad("signed record has an invalid size"));
        }
        let (body, sig) = raw.split_at(raw.len() - 64);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(sig);
        Ok(Self {
            body: body.to_vec(),
            signature,
        })
    }

    pub fn record(&self) -> Result<RendezvousRecord, ProtocolError> {
        RendezvousRecord::decode(&self.body)
    }
}

const F_PUBLISH: u8 = 0x20;
const F_LOOKUP: u8 = 0x21;
const F_RECORD: u8 = 0x22;
const F_NOT_FOUND: u8 = 0x23;
const F_OK: u8 = 0x24;
const F_ERROR: u8 = 0x25;

pub const ERR_INVALID: u8 = 1;
pub const ERR_STALE: u8 = 2;
pub const ERR_RATE: u8 = 3;
pub const ERR_FULL: u8 = 4;

/// One request or answer; each connection carries exactly one of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdvFrame {
    Publish(SignedRecord),
    Lookup(NodeId),
    Record(SignedRecord),
    NotFound,
    Ok,
    Error(u8),
}

impl RdvFrame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Publish(r) => [&[F_PUBLISH][..], &r.to_bytes()].concat(),
            Self::Lookup(id) => [&[F_LOOKUP][..], id.as_bytes()].concat(),
            Self::Record(r) => [&[F_RECORD][..], &r.to_bytes()].concat(),
            Self::NotFound => vec![F_NOT_FOUND],
            Self::Ok => vec![F_OK],
            Self::Error(c) => vec![F_ERROR, *c],
        }
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        let (&kind, rest) = raw.split_first().ok_or_else(|| bad("empty frame"))?;
        match kind {
            F_PUBLISH => Ok(Self::Publish(SignedRecord::from_bytes(rest)?)),
            F_RECORD => Ok(Self::Record(SignedRecord::from_bytes(rest)?)),
            F_LOOKUP if rest.len() == 16 => {
                let mut id = [0u8; 16];
                id.copy_from_slice(rest);
                Ok(Self::Lookup(NodeId::new(id)))
            }
            F_NOT_FOUND if rest.is_empty() => Ok(Self::NotFound),
            F_OK if rest.is_empty() => Ok(Self::Ok),
            F_ERROR if rest.len() == 1 => Ok(Self::Error(rest[0])),
            _ => Err(bad("unknown or malformed rendezvous frame")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RendezvousRecord {
        RendezvousRecord {
            node_public: [7; 32],
            issued_at: 1_700_000_000,
            ttl_secs: 600,
            addrs: vec![
                "203.0.113.5:4242".parse().unwrap(),
                "[2001:db8::1]:4242".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn record_roundtrip() {
        let r = sample();
        assert_eq!(RendezvousRecord::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn malformed_records_are_rejected() {
        let good = sample().encode();
        for cut in 0..good.len() {
            assert!(
                RendezvousRecord::decode(&good[..cut]).is_err(),
                "truncated at {cut}"
            );
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(RendezvousRecord::decode(&extra).is_err());
        let mut zero_ttl = good.clone();
        zero_ttl[44..48].copy_from_slice(&0u32.to_be_bytes());
        assert!(RendezvousRecord::decode(&zero_ttl).is_err());
        let mut many = good.clone();
        many[48] = 200;
        assert!(RendezvousRecord::decode(&many).is_err());
        let mut fam = good;
        fam[49] = 9;
        assert!(RendezvousRecord::decode(&fam).is_err());
    }

    #[test]
    fn frames_roundtrip() {
        let sr = SignedRecord {
            body: sample().encode(),
            signature: [1; 64],
        };
        for f in [
            RdvFrame::Publish(sr.clone()),
            RdvFrame::Lookup(NodeId::new([3; 16])),
            RdvFrame::Record(sr),
            RdvFrame::NotFound,
            RdvFrame::Ok,
            RdvFrame::Error(2),
        ] {
            assert_eq!(RdvFrame::decode(&f.encode()).unwrap(), f);
        }
        assert!(RdvFrame::decode(&[]).is_err());
        assert!(RdvFrame::decode(&[F_LOOKUP, 1, 2]).is_err());
        assert!(RdvFrame::decode(&[0x99]).is_err());
    }
}
