use ghost_core::{MeshEngine, PeerState};
use ghost_tun::filter::AccessPolicy;
use std::sync::atomic::Ordering;
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

/// Real IPv4/TCP packet bytes, as a phone's TUN would produce them.
fn tcp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[32] = 0x50;
    p
}

/// The PC (a) lets the phone (b) reach only 8765 and 5173; everything else is dropped on arrival.
#[tokio::test]
async fn phone_profile_over_a_real_link() {
    let pc = node(15401).await;
    let phone = node(15402).await;
    let mut t = pc.create_invite();
    t.endpoint = "127.0.0.1:15401".parse().unwrap();
    t.lan_endpoints = vec![];
    phone.join_ticket(t).await.unwrap();
    assert!(
        wait_for(10, || async {
            let t = phone.peers.read().await;
            t.get(&pc.node_id())
                .map(|p| p.state == PeerState::Connected)
                .unwrap_or(false)
        })
        .await
    );

    pc.access.set_policy(
        phone.node_id(),
        AccessPolicy::phone(vec!["8765".parse().unwrap(), "5173".parse().unwrap()]),
    );

    let src = [10, 42, 2, 2];
    let dst = [10, 42, 1, 1];
    for dport in [8765u16, 5173, 22, 3389, 80, 8766] {
        phone
            .send_packet(
                pc.node_id(),
                ghost_protocol::PacketType::Data,
                &tcp_packet(src, dst, 50000, dport),
            )
            .await
            .unwrap();
    }
    assert!(
        wait_for(5, || async {
            pc.access.allowed_in.load(Ordering::Relaxed)
                + pc.access.denied_in.load(Ordering::Relaxed)
                == 6
        })
        .await,
        "all six packets must reach the filter"
    );
    assert_eq!(
        pc.access.allowed_in.load(Ordering::Relaxed),
        2,
        "only 8765 and 5173 pass"
    );
    assert_eq!(pc.access.denied_in.load(Ordering::Relaxed), 4);

    // Garbage that is not IP at all is dropped too, not written anywhere.
    phone
        .send_packet(pc.node_id(), ghost_protocol::PacketType::Data, b"hello")
        .await
        .unwrap();
    assert!(
        wait_for(5, || async {
            pc.access.denied_in.load(Ordering::Relaxed) == 5
        })
        .await
    );
}
