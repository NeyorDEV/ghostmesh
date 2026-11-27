use ghost_core::{MeshEngine, PeerState};
use std::sync::Arc;
use std::time::Duration;

async fn node(port: u16) -> Arc<MeshEngine> {
    let n = Arc::new(MeshEngine::bind_ephemeral(port).await.expect("bind"));
    tokio::spawn(Arc::clone(&n).run_receive_loop());
    n.start_background_tasks().await;
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

async fn pair(a: &Arc<MeshEngine>, b: &Arc<MeshEngine>, port_a: u16) {
    let mut t = a.create_invite();
    t.endpoint = format!("127.0.0.1:{port_a}").parse().unwrap();
    t.lan_endpoints = vec![];
    b.join_ticket(t).await.unwrap();
    assert!(
        wait_for(10, || async {
            let t = b.peers.read().await;
            t.get(&a.node_id())
                .map(|p| p.state == PeerState::Connected)
                .unwrap_or(false)
        })
        .await,
        "pairing failed"
    );
}

async fn epoch_of(n: &Arc<MeshEngine>, other: &Arc<MeshEngine>) -> u8 {
    n.peers
        .read()
        .await
        .get(&other.node_id())
        .map(|p| p.current_epoch())
        .unwrap_or(0)
}

async fn got(n: &Arc<MeshEngine>, text: &str) -> bool {
    n.chat_messages.read().await.iter().any(|m| m.text == text)
}

/// Keys are renewed by age, then by volume, and traffic keeps flowing across each switch.
#[tokio::test]
async fn rekey_by_time_and_by_volume() {
    let a = node(15301).await;
    let b = node(15302).await;
    pair(&a, &b, 15301).await;

    a.set_rekey_policy(2, u64::MAX);
    b.set_rekey_policy(2, u64::MAX);
    assert!(
        wait_for(10, || async {
            epoch_of(&a, &b).await >= 1 && epoch_of(&b, &a).await >= 1
        })
        .await
    );
    let e1 = epoch_of(&a, &b).await;
    assert_eq!(
        e1,
        epoch_of(&b, &a).await,
        "both sides must agree on the epoch"
    );

    b.send_chat_message(a.node_id(), "after-time-rekey")
        .await
        .unwrap();
    a.send_chat_message(b.node_id(), "reply-after-time-rekey")
        .await
        .unwrap();
    assert!(
        wait_for(5, || async {
            got(&a, "after-time-rekey").await && got(&b, "reply-after-time-rekey").await
        })
        .await
    );

    // Now renew by volume only: a few KiB are enough with a tiny threshold.
    a.set_rekey_policy(100_000, 3_000);
    b.set_rekey_policy(100_000, 3_000);
    let filler = "x".repeat(900);
    for _ in 0..6 {
        a.send_chat_message(b.node_id(), &filler).await.unwrap();
        b.send_chat_message(a.node_id(), &filler).await.unwrap();
    }
    assert!(
        wait_for(10, || async {
            epoch_of(&a, &b).await != e1 && epoch_of(&b, &a).await != e1
        })
        .await
    );
    assert_eq!(epoch_of(&a, &b).await, epoch_of(&b, &a).await);

    a.send_chat_message(b.node_id(), "after-volume-rekey")
        .await
        .unwrap();
    assert!(wait_for(5, || async { got(&b, "after-volume-rekey").await }).await);
}

/// A replayed packet from before a rekey is not accepted again.
#[tokio::test]
async fn old_epoch_packets_are_not_replayable() {
    let a = node(15303).await;
    let b = node(15304).await;
    pair(&a, &b, 15303).await;
    a.set_rekey_policy(1, u64::MAX);
    b.set_rekey_policy(1, u64::MAX);
    assert!(
        wait_for(10, || async {
            epoch_of(&a, &b).await >= 1 && epoch_of(&b, &a).await >= 1
        })
        .await
    );
    let before = b.diagnostics().await.rejected_packets;
    // Raw garbage claiming a rekeyed epoch (top byte set) cannot be opened with any key.
    let mut forged = ghost_protocol::Packet::new(
        ghost_protocol::PacketType::ChatMessage,
        a.node_id(),
        b.node_id(),
        (9u64 << 56) | 5,
        vec![1u8; 40],
    )
    .encode()
    .to_vec();
    forged.truncate(forged.len());
    a.socket.send_to(&forged, "127.0.0.1:15304").await.unwrap();
    assert!(
        wait_for(3, || async {
            b.diagnostics().await.rejected_packets > before
        })
        .await
    );
    assert!(!got(&b, "\u{1}").await);
}

/// Revoking a device blocks it locally and on every other paired device.
#[tokio::test]
async fn revocation_is_propagated() {
    let a = node(15305).await;
    let b = node(15306).await;
    let c = node(15307).await;
    pair(&a, &b, 15305).await; // b joined a
    pair(&a, &c, 15305).await; // c joined a
    pair(&c, &b, 15307).await; // b joined c

    b.send_chat_message(c.node_id(), "before-revoke")
        .await
        .unwrap();
    assert!(wait_for(5, || async { got(&c, "before-revoke").await }).await);

    a.revoke_peer(b.node_id()).await;
    assert!(a.is_blocked(&b.node_id()).await);
    assert!(
        wait_for(5, || async { c.is_blocked(&b.node_id()).await }).await,
        "the other paired device must learn about the revocation"
    );

    b.send_chat_message(c.node_id(), "after-revoke")
        .await
        .unwrap();
    b.send_chat_message(a.node_id(), "after-revoke-a")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !got(&c, "after-revoke").await,
        "revoked device must be ignored by c"
    );
    assert!(
        !got(&a, "after-revoke-a").await,
        "revoked device must be ignored by a"
    );
    assert!(a.peers.read().await.get(&b.node_id()).is_none());
}
