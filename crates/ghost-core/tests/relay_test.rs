use ghost_core::{MeshEngine, PeerState, RelayEndpoint};
use ghost_crypto::IdentityKeypair;
use ghost_relay::{RelayConfig, RelayServer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

async fn start_node(port: u16, relay: &RelayEndpoint) -> Arc<MeshEngine> {
    let node = Arc::new(MeshEngine::bind_ephemeral(port).await.expect("bind"));
    tokio::spawn(Arc::clone(&node).run_receive_loop());
    node.start_background_tasks().await;
    node.start_relays(vec![relay.clone()]).await;
    node
}

async fn wait_for<F: Fn() -> Fut, Fut: std::future::Future<Output = bool>>(
    secs: u64,
    f: F,
) -> bool {
    for _ in 0..secs * 10 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn chat_seen(node: &Arc<MeshEngine>, text: &str) -> bool {
    node.chat_messages
        .read()
        .await
        .iter()
        .any(|m| m.text == text)
}

/// Two nodes with no usable direct route talk through the relay, then switch to the direct path.
#[tokio::test]
async fn relayed_then_direct() {
    let server = RelayServer::new(IdentityKeypair::generate().unwrap(), RelayConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = RelayEndpoint {
        addr: listener.local_addr().unwrap().to_string(),
        public_key: hex::encode(server.public_key()),
    };
    tokio::spawn(Arc::clone(&server).serve(listener));

    let alice = start_node(15101, &relay).await;
    let bob = start_node(15102, &relay).await;

    // No direct route: UDP is blocked on both sides and the ticket address is a black hole.
    alice.set_udp_enabled(false);
    bob.set_udp_enabled(false);
    assert!(
        wait_for(5, || async { server.connected_nodes() == 2 }).await,
        "both nodes must register with the relay"
    );

    let mut ticket = alice.create_invite();
    ticket.endpoint = "198.51.100.1:9".parse().unwrap();
    ticket.lan_endpoints = vec![];
    bob.join_ticket(ticket).await.unwrap();

    let connected = wait_for(10, || async {
        let t = bob.peers.read().await;
        t.get(&alice.node_id())
            .map(|p| p.state == PeerState::Connected)
            .unwrap_or(false)
    })
    .await;
    assert!(connected, "bob must reach alice through the relay");

    bob.send_chat_message(alice.node_id(), "via-relay")
        .await
        .unwrap();
    assert!(
        wait_for(5, || async { chat_seen(&alice, "via-relay").await }).await,
        "data must cross the relay"
    );
    {
        let t = bob.peers.read().await;
        let p = t.get(&alice.node_id()).unwrap();
        assert!(
            p.relay_seen.is_some() && !p.is_direct(),
            "bob is on the relayed path"
        );
    }
    assert!(
        server
            .stats
            .forwarded
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );

    // A direct route becomes possible: both sides learn each other's address and UDP opens up.
    let a_addr: SocketAddr = "127.0.0.1:15101".parse().unwrap();
    let b_addr: SocketAddr = "127.0.0.1:15102".parse().unwrap();
    bob.set_peer_endpoint(alice.node_id(), a_addr).await;
    alice.set_peer_endpoint(bob.node_id(), b_addr).await;
    alice.set_udp_enabled(true);
    bob.set_udp_enabled(true);

    let direct = wait_for(15, || async {
        let b = bob.peers.read().await;
        let a = alice.peers.read().await;
        b.get(&alice.node_id())
            .map(|p| p.is_direct())
            .unwrap_or(false)
            && a.get(&bob.node_id())
                .map(|p| p.is_direct())
                .unwrap_or(false)
    })
    .await;
    assert!(
        direct,
        "traffic must switch to the direct path once it works"
    );

    let before = server
        .stats
        .forwarded
        .load(std::sync::atomic::Ordering::Relaxed);
    bob.send_chat_message(alice.node_id(), "via-direct")
        .await
        .unwrap();
    assert!(wait_for(5, || async { chat_seen(&alice, "via-direct").await }).await);
    assert_eq!(
        server
            .stats
            .forwarded
            .load(std::sync::atomic::Ordering::Relaxed),
        before,
        "direct traffic must no longer go through the relay"
    );
}

/// A client with the wrong pinned key refuses to register (no impersonation of the relay).
#[tokio::test]
async fn pinned_key_mismatch_is_refused() {
    let server = RelayServer::new(IdentityKeypair::generate().unwrap(), RelayConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = RelayEndpoint {
        addr: listener.local_addr().unwrap().to_string(),
        public_key: hex::encode(IdentityKeypair::generate().unwrap().public),
    };
    tokio::spawn(Arc::clone(&server).serve(listener));
    let _node = start_node(15103, &relay).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(server.connected_nodes(), 0);
}
