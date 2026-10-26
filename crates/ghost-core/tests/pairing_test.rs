use ghost_core::{MeshEngine, PeerState};
use ghost_protocol::InviteTicket;

use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_two_nodes_direct_pairing() {
    // 1. Bind Alice on local port 15001
    let alice = Arc::new(MeshEngine::bind(15001).await.expect("Failed to bind Alice"));
    let mut alice_ticket = alice.create_invite();
    // For local test, override public endpoint to localhost to avoid loopback NAT hairpinning
    alice_ticket.endpoint = "127.0.0.1:15001".parse().unwrap();
    let ticket_str = alice_ticket.to_ticket_string();

    let alice_clone = Arc::clone(&alice);
    tokio::spawn(async move {
        alice_clone.run_receive_loop().await;
    });

    // 2. Bob parses Alice's ticket and joins from port 15002
    let parsed_ticket: InviteTicket = ticket_str.parse().expect("Failed to parse ticket");
    let bob = Arc::new(MeshEngine::bind(15002).await.expect("Failed to bind Bob"));

    let bob_clone = Arc::clone(&bob);
    tokio::spawn(async move {
        bob_clone.run_receive_loop().await;
    });

    // Bob triggers join routine towards Alice
    bob.join_ticket(parsed_ticket).await.expect("Bob failed to join");

    // Wait up to 3 seconds for handshake completion
    let mut connected = false;
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let table = bob.peers.read().await;
        if let Some(peer) = table.get(&alice.node_id()) {
            if peer.state == PeerState::Connected {
                connected = true;
                break;
            }
        }
    }

    assert!(connected, "Bob should have established a Direct P2P connection with Alice");
}
