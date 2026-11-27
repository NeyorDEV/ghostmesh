#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = ghost_protocol::relay::RelayFrame::decode(data) {
        assert_eq!(ghost_protocol::relay::RelayFrame::decode(&f.encode()), Ok(f));
    }
    let _ = ghost_protocol::relay::packet_route(data);
});
