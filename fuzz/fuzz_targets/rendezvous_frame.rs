#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = ghost_protocol::rendezvous::RdvFrame::decode(data) {
        let _ = ghost_protocol::rendezvous::RdvFrame::decode(&f.encode());
    }
    let _ = ghost_protocol::rendezvous::RendezvousRecord::decode(data);
});
