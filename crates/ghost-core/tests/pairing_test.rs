use ghost_core::{MeshEngine, PeerState};
use ghost_protocol::InviteTicket;

use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_two_nodes_direct_pairing() {
    // 1. Bind Alice on local port 15001 with ephemeral identity
    let alice = Arc::new(MeshEngine::bind_ephemeral(15001).await.expect("Failed to bind Alice"));
    let mut alice_ticket = alice.create_invite();
    // For local test, override public endpoint to localhost to avoid loopback NAT hairpinning
    alice_ticket.endpoint = "127.0.0.1:15001".parse().unwrap();
    let ticket_str = alice_ticket.to_ticket_string();

    let alice_clone = Arc::clone(&alice);
    tokio::spawn(async move {
        alice_clone.run_receive_loop().await;
    });

    // 2. Bob parses Alice's ticket and joins from port 15002 with independent ephemeral identity
    let parsed_ticket: InviteTicket = ticket_str.parse().expect("Failed to parse ticket");
    let bob = Arc::new(MeshEngine::bind_ephemeral(15002).await.expect("Failed to bind Bob"));

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

#[tokio::test]
async fn test_pairing_with_unreachable_wan_and_lan_candidates() {
    // 1. Bind Alice on local port 15003 with ephemeral identity
    let alice = Arc::new(MeshEngine::bind_ephemeral(15003).await.expect("Failed to bind Alice"));
    let mut alice_ticket = alice.create_invite();
    // Simulate a public WAN IP that drops traffic (no NAT hairpinning)
    alice_ticket.endpoint = "198.51.100.1:4242".parse().unwrap();
    // Ensure localhost is in lan_endpoints
    alice_ticket.lan_endpoints = vec!["127.0.0.1:15003".parse().unwrap()];
    let ticket_str = alice_ticket.to_ticket_string();

    let alice_clone = Arc::clone(&alice);
    tokio::spawn(async move {
        alice_clone.run_receive_loop().await;
    });

    // 2. Bob parses Alice's ticket and joins from port 15004 with independent ephemeral identity
    let parsed_ticket: InviteTicket = ticket_str.parse().expect("Failed to parse ticket");
    let bob = Arc::new(MeshEngine::bind_ephemeral(15004).await.expect("Failed to bind Bob"));

    let bob_clone = Arc::clone(&bob);
    tokio::spawn(async move {
        bob_clone.run_receive_loop().await;
    });

    // Bob triggers join routine towards Alice
    bob.join_ticket(parsed_ticket).await.expect("Bob failed to join");

    // Wait up to 3 seconds for handshake completion on both sides
    let mut bob_connected = false;
    let mut alice_connected = false;
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let table = bob.peers.read().await;
            if let Some(peer) = table.get(&alice.node_id()) {
                if peer.state == PeerState::Connected {
                    bob_connected = true;
                }
            }
        }
        {
            let table = alice.peers.read().await;
            if let Some(peer) = table.get(&bob.node_id()) {
                if peer.state == PeerState::Connected {
                    alice_connected = true;
                }
            }
        }
        if bob_connected && alice_connected {
            break;
        }
    }

    assert!(bob_connected, "Bob should connect to Alice via candidate endpoints");
    assert!(alice_connected, "Alice should also see Bob as Connected in her peer table");
}

#[tokio::test]
async fn test_two_gui_engines_bind_and_pair() {
    // Exactly simulates GUI instance 1 (port 4242)
    let engine_a = Arc::new(MeshEngine::bind(4242).await.expect("Engine A bind failed"));
    let a_clone = Arc::clone(&engine_a);
    tokio::spawn(async move {
        a_clone.run_receive_loop().await;
    });

    // Exactly simulates GUI instance 2 (port 4242 -> falls back to 4244)
    let engine_b = Arc::new(MeshEngine::bind(4242).await.expect("Engine B bind failed"));
    let b_clone = Arc::clone(&engine_b);
    tokio::spawn(async move {
        b_clone.run_receive_loop().await;
    });

    println!("Engine A port: {}, node_id: {}", engine_a.socket.local_addr().unwrap().port(), engine_a.node_id());
    println!("Engine B port: {}, node_id: {}", engine_b.socket.local_addr().unwrap().port(), engine_b.node_id());

    // A invites B
    let ticket = engine_a.create_invite();
    let ticket_str = ticket.to_ticket_string();
    println!("Ticket string: {}", ticket_str);
    println!("Ticket all_endpoints: {:?}", ticket.all_endpoints());

    let parsed_ticket: InviteTicket = ticket_str.parse().expect("Parse ticket failed");

    // B joins A
    engine_b.join_ticket(parsed_ticket).await.expect("B join_ticket failed");

    // Wait up to 4 seconds
    let mut a_has_b = false;
    let mut b_has_a = false;
    for i in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let table_b = engine_b.peers.read().await;
            if let Some(p) = table_b.get(&engine_a.node_id()) {
                if p.state == PeerState::Connected {
                    b_has_a = true;
                }
            }
        }
        {
            let table_a = engine_a.peers.read().await;
            if let Some(p) = table_a.get(&engine_b.node_id()) {
                if p.state == PeerState::Connected {
                    a_has_b = true;
                }
            }
        }
        println!("Tick {}: B has A: {}, A has B: {}", i, b_has_a, a_has_b);
        if a_has_b && b_has_a {
            break;
        }
    }

    assert!(b_has_a, "Engine B must have Engine A connected");
    assert!(a_has_b, "Engine A must have Engine B connected");
}
use tokio::net::UdpSocket;

/// On Windows, an ICMP "port unreachable" after sending to a dead endpoint surfaces as an error on
/// the *next* recv; candidate probing must never make a socket unusable.
#[tokio::test]
async fn test_udp_socket_survives_unreachable_probe() {
    let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let s2_addr = s2.local_addr().unwrap();

    // Probe a closed local port, then talk to a live one
    let _ = s1.send_to(b"TEST_UNREACHABLE", "127.0.0.1:9").await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    s1.send_to(b"TEST_LOCAL", s2_addr).await.unwrap();

    let mut buf = [0u8; 128];
    let recv_res = tokio::time::timeout(std::time::Duration::from_millis(500), s2.recv_from(&mut buf)).await;
    assert!(recv_res.is_ok(), "S2 should have received packet from S1");
}
