#![no_main]
use ghost_tun::filter::{AccessPolicy, Dir, PeerFilter};
use libfuzzer_sys::fuzz_target;
use std::time::Instant;

fuzz_target!(|data: &[u8]| {
    let mut f = PeerFilter::new(AccessPolicy::phone(vec!["8765".parse().unwrap()]));
    let _ = f.check(Dir::In, data, Instant::now());
    let _ = f.check(Dir::Out, data, Instant::now());
});
