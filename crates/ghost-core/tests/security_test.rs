use ghost_core::{MeshEngine, PeerState};
use ghost_protocol::{Packet, PacketType};

use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

async fn engine(port: u16) -> Arc<MeshEngine> {
    let e = Arc::new(MeshEngine::bind_ephemeral(port).await.expect("bind failed"));
    tokio::spawn(Arc::clone(&e).run_receive_loop());
    e
}

async fn wait_connected(from: &Arc<MeshEngine>, to: &Arc<MeshEngine>, secs: u64) -> bool {
    for _ in 0..(secs * 5) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let table = from.peers.read().await;
        if let Some(p) = table.get(&to.node_id()) {
            if p.state == PeerState::Connected {
                return true;
            }
        }
    }
    false
}

async fn pair(alice: &Arc<MeshEngine>, bob: &Arc<MeshEngine>) {
    let mut ticket = alice.create_invite();
    ticket.endpoint = format!("127.0.0.1:{}", alice.local_udp_port).parse().unwrap();
    bob.join_ticket(ticket).await.unwrap();
    assert!(wait_connected(bob, alice, 6).await, "bob must connect to alice");
    assert!(wait_connected(alice, bob, 6).await, "alice must see bob connected");
}

#[tokio::test]
async fn test_chat_is_delivered_after_authenticated_handshake() {
    let alice = engine(15201).await;
    let bob = engine(15202).await;
    pair(&alice, &bob).await;

    bob.send_chat_message(alice.node_id(), "bonjour alice").await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let msgs = alice.chat_messages.read().await;
    assert!(msgs.iter().any(|m| m.text == "bonjour alice"), "alice should receive the sealed chat message");
}

#[tokio::test]
async fn test_forged_and_plaintext_packets_are_rejected() {
    let alice = engine(15211).await;
    let bob = engine(15212).await;
    pair(&alice, &bob).await;

    // An attacker spoofs bob's NodeId and sends a plaintext chat message straight to alice's UDP port
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let forged = Packet::new(
        PacketType::ChatMessage,
        bob.node_id(),
        alice.node_id(),
        u64::MAX / 2,
        b"evil".to_vec(),
    );
    attacker
        .send_to(&forged.encode(), format!("127.0.0.1:{}", alice.local_udp_port))
        .await
        .unwrap();

    // A packet claiming a valid-looking sealed payload with garbage bytes is rejected as well
    let garbage = Packet::new(
        PacketType::Data,
        bob.node_id(),
        alice.node_id(),
        u64::MAX / 2 + 1,
        vec![0xAB; 64],
    );
    attacker
        .send_to(&garbage.encode(), format!("127.0.0.1:{}", alice.local_udp_port))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(alice.chat_messages.read().await.is_empty(), "forged chat must not be delivered");
    assert!(
        alice.diagnostics().await.rejected_packets >= 2,
        "both forged packets must be counted as rejected"
    );
}

#[tokio::test]
async fn test_handshake_with_wrong_identity_is_rejected() {
    let alice = engine(15221).await;
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Init whose NodeId does not match the public key it carries
    let fake_id = ghost_protocol::NodeId::new([0x11; 16]);
    let pk = vec![0x22u8; 32];
    let init = Packet::new(PacketType::HandshakeInit, fake_id, alice.node_id(), 1, pk);
    attacker
        .send_to(&init.encode(), format!("127.0.0.1:{}", alice.local_udp_port))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(alice.peers.read().await.get(&fake_id).is_none(), "spoofed identity must not enter the peer table");
}

#[tokio::test]
async fn test_tcp_fallback_when_udp_is_blocked() {
    let alice = engine(15231).await;
    let bob = engine(15232).await;
    bob.set_udp_enabled(false); // simulate a network that drops all outbound UDP

    pair(&alice, &bob).await;

    {
        let table = bob.peers.read().await;
        assert!(table.get(&alice.node_id()).unwrap().tcp.is_some(), "bob must reach alice through TCP");
    }

    bob.send_chat_message(alice.node_id(), "via tcp").await.unwrap();
    alice.send_chat_message(bob.node_id(), "retour").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(alice.chat_messages.read().await.iter().any(|m| m.text == "via tcp"));
    assert!(bob.chat_messages.read().await.iter().any(|m| m.text == "retour"));
    assert!(alice.diagnostics().await.tcp_packets_rx > 0);
}

#[tokio::test]
async fn test_unreachable_peer_is_reported_without_hanging() {
    // Nothing listens on this ticket's endpoints: the peer must stay out of the connected count
    let bob = engine(15242).await;
    let mut ticket = engine(15241).await.create_invite();
    ticket.endpoint = "127.0.0.1:9".parse().unwrap();
    ticket.lan_endpoints = vec![];
    let node = ticket.node_id;
    bob.join_ticket(ticket).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let table = bob.peers.read().await;
    assert_eq!(table.get(&node).unwrap().state, PeerState::Punching);
}
