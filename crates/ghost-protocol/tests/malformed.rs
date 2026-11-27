//! Decoders must never panic on bytes from the network. These deterministic tests run in every CI
//! build; the `fuzz/` targets explore the same decoders much further with cargo-fuzz.

use ghost_protocol::relay::{packet_route, RelayFrame};
use ghost_protocol::rendezvous::{RdvFrame, RendezvousRecord, SignedRecord};
use ghost_protocol::{InviteTicket, Packet, PacketType};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn random_bytes_never_panic_any_decoder() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for len in 0..300 {
        for _ in 0..40 {
            let data = rng.bytes(len);
            let _ = Packet::decode(&data);
            let _ = RelayFrame::decode(&data);
            let _ = packet_route(&data);
            let _ = RdvFrame::decode(&data);
            let _ = RendezvousRecord::decode(&data);
            let _ = SignedRecord::from_bytes(&data);
            let _ = String::from_utf8_lossy(&data).parse::<InviteTicket>();
        }
    }
}

#[test]
fn mutated_valid_inputs_never_panic() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let packet = Packet::new(
        PacketType::Data,
        ghost_protocol::NodeId::new([1; 16]),
        ghost_protocol::NodeId::new([2; 16]),
        7,
        vec![9u8; 50],
    )
    .encode()
    .to_vec();
    let ticket = InviteTicket::new(
        ghost_protocol::NodeId::new([3; 16]),
        "203.0.113.4:4242".parse().unwrap(),
        [5; 32],
    )
    .to_ticket_string();
    for _ in 0..5000 {
        let mut p = packet.clone();
        for _ in 0..(rng.next() % 4 + 1) {
            let i = (rng.next() as usize) % p.len();
            p[i] ^= 1 << (rng.next() % 8);
        }
        let cut = (rng.next() as usize) % (p.len() + 1);
        let _ = Packet::decode(&p[..cut]);

        let mut t = ticket.clone().into_bytes();
        let i = (rng.next() as usize) % t.len();
        t[i] = rng.next() as u8;
        let _ = String::from_utf8_lossy(&t).parse::<InviteTicket>();
    }
}

#[test]
fn ticket_edge_cases_are_errors() {
    for bad in [
        "",
        "gm1_",
        "gm1_!!!",
        "gm2_abcd",
        "gm1_e30",
        "gm1_bnVsbA",
        "   ",
        "gm1_\u{0}",
    ] {
        assert!(bad.parse::<InviteTicket>().is_err(), "{bad:?}");
    }
    // Huge input is rejected without allocating absurd amounts.
    let huge = format!("gm1_{}", "A".repeat(1_000_000));
    assert!(huge.parse::<InviteTicket>().is_err());
}
