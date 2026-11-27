use ghost_core::{MeshEngine, PeerState};
use ghost_crypto::IdentityKeypair;
use ghost_relay::rendezvous::{RendezvousConfig, RendezvousServer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

async fn node(port: u16, id: IdentityKeypair, servers: &[String]) -> Arc<MeshEngine> {
    let n = Arc::new(
        MeshEngine::bind_with_identity(port, id)
            .await
            .expect("bind"),
    );
    tokio::spawn(Arc::clone(&n).run_receive_loop());
    n.start_background_tasks().await;
    n.set_rendezvous_servers(servers.to_vec()).await;
    n
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

async fn connected(a: &Arc<MeshEngine>, b: &Arc<MeshEngine>) -> bool {
    let t = a.peers.read().await;
    t.get(&b.node_id())
        .map(|p| p.state == PeerState::Connected)
        .unwrap_or(false)
}

/// Both devices change address at the same time and find each other again without a new ticket.
#[tokio::test]
async fn devices_find_each_other_after_both_addresses_change() {
    let server = RendezvousServer::new(RendezvousConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let servers = vec![listener.local_addr().unwrap().to_string()];
    tokio::spawn(Arc::clone(&server).serve(listener));

    let id_a = IdentityKeypair::generate().unwrap();
    let id_b = IdentityKeypair::generate().unwrap();

    // Both devices come up on new addresses; neither knows where the other is.
    let alice = node(15201, id_a, &servers).await;
    let bob = node(15202, id_b, &servers).await;
    let a_addr: SocketAddr = "127.0.0.1:15201".parse().unwrap();
    let b_addr: SocketAddr = "127.0.0.1:15202".parse().unwrap();
    assert_eq!(alice.publish_rendezvous(&servers, vec![a_addr]).await, 1);
    assert_eq!(bob.publish_rendezvous(&servers, vec![b_addr]).await, 1);
    assert_eq!(server.record_count(), 2);

    // Bob only knows Alice's NodeId (as a paired device): no ticket, no address.
    assert!(
        bob.connect_known(alice.node_id()).await,
        "rendezvous lookup must succeed"
    );
    assert!(
        wait_for(10, || async {
            connected(&bob, &alice).await && connected(&alice, &bob).await
        })
        .await
    );

    // They move again (new ports), republish, and reconnect the same way.
    // Records are ordered by whole seconds: a restart within the same second would look like a replay.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let a_id = alice.identity.clone();
    let b_id = bob.identity.clone();
    let alice2 = node(15203, a_id, &servers).await;
    let bob2 = node(15204, b_id, &servers).await;
    assert_eq!(
        alice2
            .publish_rendezvous(&servers, vec!["127.0.0.1:15203".parse().unwrap()])
            .await,
        1
    );
    assert_eq!(
        bob2.publish_rendezvous(&servers, vec!["127.0.0.1:15204".parse().unwrap()])
            .await,
        1
    );
    assert_eq!(
        server.record_count(),
        2,
        "records are replaced, not accumulated"
    );

    assert!(alice2.connect_known(bob2.node_id()).await);
    assert!(
        wait_for(10, || async {
            connected(&alice2, &bob2).await && connected(&bob2, &alice2).await
        })
        .await
    );

    alice2
        .send_chat_message(bob2.node_id(), "found-again")
        .await
        .unwrap();
    assert!(
        wait_for(5, || async {
            bob2.chat_messages
                .read()
                .await
                .iter()
                .any(|m| m.text == "found-again")
        })
        .await
    );
}

#[tokio::test]
async fn unknown_node_is_not_found() {
    let server = RendezvousServer::new(RendezvousConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let servers = vec![listener.local_addr().unwrap().to_string()];
    tokio::spawn(Arc::clone(&server).serve(listener));
    let n = node(15205, IdentityKeypair::generate().unwrap(), &servers).await;
    let stranger = IdentityKeypair::generate().unwrap();
    assert!(n
        .lookup_rendezvous(&servers, &stranger.node_id())
        .await
        .is_none());
    assert!(!n.connect_known(stranger.node_id()).await);
}
