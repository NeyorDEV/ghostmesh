use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use thiserror::Error;

pub const MAGIC_BYTES: [u8; 2] = [0x47, 0x4D]; // "GM"
pub const HEADER_SIZE: usize = 43;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Packet too short: expected at least {HEADER_SIZE} bytes, got {0}")]
    PacketTooShort(usize),
    #[error("Invalid magic bytes: expected 0x474D, got {0:02X?}")]
    InvalidMagic([u8; 2]),
    #[error("Unknown packet type: 0x{0:02X}")]
    UnknownPacketType(u8),
    #[error("Buffer error: {0}")]
    BufferError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Derives a deterministic virtual IPv4 address in the 10.42.0.0/16 subnet.
    pub fn to_virtual_ip(&self) -> std::net::Ipv4Addr {
        let x = (self.0[14] % 254) + 1;
        let y = (self.0[15] % 253) + 1;
        std::net::Ipv4Addr::new(10, 42, x, y)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for NodeId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex for NodeId: {e}"))?;
        if bytes.len() != 16 {
            return Err(format!("NodeId must be 16 bytes (32 hex characters), got {}", bytes.len()));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    StunProbe = 0x01,
    HandshakeInit = 0x02,
    HandshakeResp = 0x03,
    Data = 0x04,
    KeepAlive = 0x05,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::StunProbe),
            0x02 => Ok(Self::HandshakeInit),
            0x03 => Ok(Self::HandshakeResp),
            0x04 => Ok(Self::Data),
            0x05 => Ok(Self::KeepAlive),
            other => Err(ProtocolError::UnknownPacketType(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: PacketType,
    pub dest_node: NodeId,
    pub src_node: NodeId,
    pub sequence: u64,
    pub payload: Bytes,
}

impl Packet {
    pub fn new(
        packet_type: PacketType,
        src_node: NodeId,
        dest_node: NodeId,
        sequence: u64,
        payload: impl Into<Bytes>,
    ) -> Self {
        Self {
            packet_type,
            src_node,
            dest_node,
            sequence,
            payload: payload.into(),
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.put_slice(&MAGIC_BYTES);
        buf.put_u8(self.packet_type as u8);
        buf.put_slice(self.dest_node.as_bytes());
        buf.put_slice(self.src_node.as_bytes());
        buf.put_u64(self.sequence);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(mut raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort(raw.len()));
        }

        let magic = [raw[0], raw[1]];
        if magic != MAGIC_BYTES {
            return Err(ProtocolError::InvalidMagic(magic));
        }

        let packet_type = PacketType::try_from(raw[2])?;
        raw.advance(3);

        let mut dest_bytes = [0u8; 16];
        raw.copy_to_slice(&mut dest_bytes);
        let dest_node = NodeId::new(dest_bytes);

        let mut src_bytes = [0u8; 16];
        raw.copy_to_slice(&mut src_bytes);
        let src_node = NodeId::new(src_bytes);

        let sequence = raw.get_u64();
        let payload = Bytes::copy_from_slice(raw);

        Ok(Self {
            packet_type,
            dest_node,
            src_node,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let src = NodeId::new([1u8; 16]);
        let dest = NodeId::new([2u8; 16]);
        let original = Packet::new(
            PacketType::Data,
            src,
            dest,
            42,
            Bytes::from_static(b"Hello GhostMesh!"),
        );

        let encoded = original.encode();
        assert_eq!(encoded.len(), HEADER_SIZE + 16);

        let decoded = Packet::decode(&encoded).expect("Failed to decode valid packet");
        assert_eq!(decoded.packet_type, PacketType::Data);
        assert_eq!(decoded.src_node, src);
        assert_eq!(decoded.dest_node, dest);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(&decoded.payload[..], b"Hello GhostMesh!");
    }

    #[test]
    fn test_invalid_magic() {
        let mut bad_packet = vec![0x00, 0x00];
        bad_packet.extend_from_slice(&[0u8; HEADER_SIZE - 2]);
        let err = Packet::decode(&bad_packet).unwrap_err();
        assert_eq!(err, ProtocolError::InvalidMagic([0x00, 0x00]));
    }

    #[test]
    fn test_packet_too_short() {
        let short = vec![0x47, 0x4D, 0x01];
        let err = Packet::decode(&short).unwrap_err();
        assert_eq!(err, ProtocolError::PacketTooShort(3));
    }

    #[test]
    fn test_node_id_virtual_ip() {
        let mut bytes = [0u8; 16];
        bytes[14] = 10;
        bytes[15] = 20;
        let id = NodeId::new(bytes);
        let ip = id.to_virtual_ip();
        assert_eq!(ip, std::net::Ipv4Addr::new(10, 42, 11, 21));
    }
}
