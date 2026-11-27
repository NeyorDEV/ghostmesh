#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let names = HashMap::from([("pc".to_string(), std::net::Ipv4Addr::new(10, 42, 1, 1))]);
    let _ = ghost_core::dns::answer(data, &names);
});
