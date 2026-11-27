#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = ghost_protocol::Packet::decode(data) {
        // Whatever decodes must re-encode to the same bytes.
        assert_eq!(p.encode().as_ref(), data);
    }
});
