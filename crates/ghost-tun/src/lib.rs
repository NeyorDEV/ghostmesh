pub mod device;
pub mod filter;

pub use device::{
    mtu_for_link, Ipv4Header, RouteTable, TunError, VirtualAdapter, DEFAULT_MTU,
    DEFAULT_VIRTUAL_NETWORK, TUNNEL_OVERHEAD,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_valid_ipv4_packet() {
        // Minimal 20-byte IPv4 packet header
        let mut raw = vec![0u8; 20];
        raw[0] = 0x45; // Version 4, IHL 5
        raw[2] = 0x00;
        raw[3] = 0x14; // Total Length: 20 bytes
        raw[9] = 0x01; // Protocol: ICMP (1)
                       // Src IP: 10.42.0.1
        raw[12] = 10;
        raw[13] = 42;
        raw[14] = 0;
        raw[15] = 1;
        // Dest IP: 10.42.0.2
        raw[16] = 10;
        raw[17] = 42;
        raw[18] = 0;
        raw[19] = 2;

        let parsed = Ipv4Header::parse(&raw).expect("Failed to parse valid IPv4 header");
        assert_eq!(parsed.src, Ipv4Addr::new(10, 42, 0, 1));
        assert_eq!(parsed.dest, Ipv4Addr::new(10, 42, 0, 2));
        assert_eq!(parsed.protocol, 1);
        assert_eq!(parsed.total_len, 20);
    }

    #[test]
    fn mtu_leaves_room_for_the_tunnel_headers() {
        assert_eq!(mtu_for_link(1500), 1393);
        assert_eq!(mtu_for_link(1492), 1385, "PPPoE");
        assert_eq!(mtu_for_link(1280), 1280, "never below the IPv6 minimum");
        assert_eq!(mtu_for_link(9000), 1420, "capped");
        assert!(u32::from(DEFAULT_MTU) + TUNNEL_OVERHEAD <= 1492);
    }

    #[test]
    fn test_route_table_mapping() {
        let mut table = RouteTable::new();
        let ip = Ipv4Addr::new(10, 42, 0, 2);
        let node_id = ghost_protocol::NodeId::new([0xAA; 16]);

        table.insert(ip, node_id);
        assert_eq!(table.get_node_by_ip(&ip), Some(node_id));
        assert_eq!(table.get_ip_by_node(&node_id), Some(ip));
    }
}
