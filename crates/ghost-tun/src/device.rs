use ghost_protocol::NodeId;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub const DEFAULT_MTU: u16 = 1420;
pub const DEFAULT_VIRTUAL_NETWORK: &str = "10.42.0.0/16";

#[derive(Error, Debug)]
pub enum TunError {
    #[error("TUN device configuration error: {0}")]
    Config(String),
    #[error("IO error on TUN device: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid IPv4 packet: {0}")]
    InvalidPacket(String),
    #[error("Administrator privileges required to create virtual network adapter on Windows")]
    ElevationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dest: Ipv4Addr,
    pub protocol: u8,
    pub total_len: u16,
}

impl Ipv4Header {
    pub fn parse(packet: &[u8]) -> Result<Self, TunError> {
        if packet.len() < 20 {
            return Err(TunError::InvalidPacket("Packet too short for IPv4 header".into()));
        }

        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return Err(TunError::InvalidPacket(format!("Expected IPv4, got version {version}")));
        }

        let total_len = u16::from_be_bytes([packet[2], packet[3]]);
        let protocol = packet[9];

        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        Ok(Self {
            src,
            dest,
            protocol,
            total_len,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    ip_to_node: HashMap<Ipv4Addr, NodeId>,
    node_to_ip: HashMap<NodeId, Ipv4Addr>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, ip: Ipv4Addr, node_id: NodeId) {
        self.ip_to_node.insert(ip, node_id);
        self.node_to_ip.insert(node_id, ip);
    }

    pub fn get_node_by_ip(&self, ip: &Ipv4Addr) -> Option<NodeId> {
        self.ip_to_node.get(ip).copied()
    }

    pub fn get_ip_by_node(&self, node_id: &NodeId) -> Option<Ipv4Addr> {
        self.node_to_ip.get(node_id).copied()
    }
}

pub struct VirtualAdapter {
    pub device: AsyncDevice,
    pub assigned_ip: Ipv4Addr,
    pub routes: Arc<RwLock<RouteTable>>,
}

impl VirtualAdapter {
    pub fn create(name: &str, assigned_ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self, TunError> {
        let builder = DeviceBuilder::new()
            .name(name)
            .ipv4(assigned_ip, netmask, None)
            .mtu(DEFAULT_MTU);

        let device = match builder.build_async() {
            Ok(dev) => dev,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Access is denied") || err_str.contains("administrator") {
                    return Err(TunError::ElevationRequired);
                }
                return Err(TunError::Config(err_str));
            }
        };

        info!("Created virtual network interface '{name}' with IP {assigned_ip}/{netmask}");

        Ok(Self {
            device,
            assigned_ip,
            routes: Arc::new(RwLock::new(RouteTable::new())),
        })
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.device.recv(buf).await.map_err(TunError::Io)
    }

    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        self.device.send(buf).await.map_err(TunError::Io)
    }
}
