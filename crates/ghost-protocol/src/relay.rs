//! Wire format spoken between a node and a relay server.
//!
//! Frames travel over a byte stream, each prefixed with a big-endian `u16` length. The relay only
//! ever sees already sealed [`crate::Packet`]s, public keys and addresses.

use crate::packet::{HEADER_SIZE, MAGIC_BYTES};
use crate::{NodeId, ProtocolError};

pub const RELAY_VERSION: u8 = 1;
/// Largest accepted frame body. Encoded packets stay well below this (TUN MTU + header + tag).
pub const MAX_RELAY_FRAME: usize = 4096;
pub const CHALLENGE_LEN: usize = 32;

const T_HELLO: u8 = 0x01;
const T_REGISTER: u8 = 0x02;
const T_REGISTERED: u8 = 0x03;
const T_ERROR: u8 = 0x04;
const T_PING: u8 = 0x05;
const T_PACKET: u8 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    /// Relay -> node: protocol version, random challenge and the relay's static public key.
    Hello {
        version: u8,
        challenge: [u8; CHALLENGE_LEN],
        relay_public: [u8; 32],
    },
    /// Node -> relay: the node's public key and its proof of possession of the private key.
    Register {
        node_public: [u8; 32],
        proof: [u8; 32],
    },
    Registered,
    Error(u8),
    Ping,
    /// An encoded [`crate::Packet`], forwarded untouched.
    Packet(Vec<u8>),
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

fn bad(msg: &str) -> ProtocolError {
    ProtocolError::BufferError(msg.to_string())
}

impl RelayFrame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Hello {
                version,
                challenge,
                relay_public,
            } => {
                let mut v = vec![T_HELLO, *version];
                v.extend_from_slice(challenge);
                v.extend_from_slice(relay_public);
                v
            }
            Self::Register { node_public, proof } => {
                let mut v = vec![T_REGISTER];
                v.extend_from_slice(node_public);
                v.extend_from_slice(proof);
                v
            }
            Self::Registered => vec![T_REGISTERED],
            Self::Error(code) => vec![T_ERROR, *code],
            Self::Ping => vec![T_PING],
            Self::Packet(p) => {
                let mut v = Vec::with_capacity(1 + p.len());
                v.push(T_PACKET);
                v.extend_from_slice(p);
                v
            }
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        if body.is_empty() || body.len() > MAX_RELAY_FRAME {
            return Err(bad("relay frame has an invalid size"));
        }
        let rest = &body[1..];
        match body[0] {
            T_HELLO if rest.len() == 1 + CHALLENGE_LEN + 32 => Ok(Self::Hello {
                version: rest[0],
                challenge: arr32(&rest[1..33]),
                relay_public: arr32(&rest[33..65]),
            }),
            T_REGISTER if rest.len() == 64 => Ok(Self::Register {
                node_public: arr32(&rest[..32]),
                proof: arr32(&rest[32..]),
            }),
            T_REGISTERED if rest.is_empty() => Ok(Self::Registered),
            T_ERROR if rest.len() == 1 => Ok(Self::Error(rest[0])),
            T_PING if rest.is_empty() => Ok(Self::Ping),
            T_PACKET if rest.len() >= HEADER_SIZE => Ok(Self::Packet(rest.to_vec())),
            _ => Err(bad("unknown or malformed relay frame")),
        }
    }
}

/// Header fields a relay may look at in a packet it forwards: `(src, dest)`.
/// Returns `None` when the bytes cannot be a GhostMesh packet.
pub fn packet_route(raw: &[u8]) -> Option<(NodeId, NodeId)> {
    if raw.len() < HEADER_SIZE || raw[..2] != MAGIC_BYTES {
        return None;
    }
    let mut dest = [0u8; 16];
    let mut src = [0u8; 16];
    dest.copy_from_slice(&raw[3..19]);
    src.copy_from_slice(&raw[19..35]);
    Some((NodeId::new(src), NodeId::new(dest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let frames = [
            RelayFrame::Hello {
                version: 1,
                challenge: [3; 32],
                relay_public: [4; 32],
            },
            RelayFrame::Register {
                node_public: [5; 32],
                proof: [6; 32],
            },
            RelayFrame::Registered,
            RelayFrame::Error(9),
            RelayFrame::Ping,
            RelayFrame::Packet(vec![0x47; HEADER_SIZE + 5]),
        ];
        for f in frames {
            assert_eq!(RelayFrame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn malformed_is_rejected() {
        assert!(RelayFrame::decode(&[]).is_err());
        assert!(RelayFrame::decode(&[0xFF, 1, 2]).is_err());
        assert!(RelayFrame::decode(&[T_REGISTER, 1, 2]).is_err());
        assert!(RelayFrame::decode(&[T_PACKET, 1, 2]).is_err());
        assert!(RelayFrame::decode(&vec![T_PACKET; MAX_RELAY_FRAME + 1]).is_err());
    }

    #[test]
    fn route_reads_header_only() {
        let mut raw = vec![0u8; HEADER_SIZE];
        raw[..2].copy_from_slice(&MAGIC_BYTES);
        raw[3..19].copy_from_slice(&[1; 16]);
        raw[19..35].copy_from_slice(&[2; 16]);
        assert_eq!(
            packet_route(&raw),
            Some((NodeId::new([2; 16]), NodeId::new([1; 16])))
        );
        assert!(packet_route(&raw[..10]).is_none());
        raw[0] = 0;
        assert!(packet_route(&raw).is_none());
    }
}
