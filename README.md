# GhostMesh

> **Decentralized, zero-config, peer-to-peer encrypted mesh overlay network.**

GhostMesh connects your devices directly over UDP without relying on centralized relay servers. It uses modern end-to-end cryptography (Noise Protocol) and automated NAT traversal (UDP Hole Punching via public STUN) to establish resilient, low-latency tunnels across firewalls and dynamic IP addresses.

---

## Key Features

- **Direct P2P Connectivity:** Traverses domestic NATs and firewalls via automated UDP hole punching.
- **End-to-End Cryptography:** Noise Protocol handshake (`Noise_XX` / `Curve25519` + `ChaCha20-Poly1305` + `BLAKE2s`).
- **Zero Central Relay:** Data packets travel directly peer-to-peer.
- **Cross-Platform CLI:** Clean commands for identity generation, node pairing, and live link monitoring.
- **Modular Architecture:** Extensible crates separating protocol serialization, cryptographic wrappers, NAT discovery, and peer orchestration.

---

## Architecture (Cargo Workspace)

```text
ghostmesh/
├── crates/
│   ├── ghost-protocol/   # Wire format, binary packet serialization & headers
│   ├── ghost-crypto/     # Noise protocol state machine, key generation & frame encryption
│   ├── ghost-nat/        # Lightweight STUN client & UDP hole-punching probes
│   ├── ghost-core/       # Routing table, peer state machine, event loop
│   └── ghost-cli/        # CLI binary (ghostmesh keygen, invite, join, discover, up)
```

---

## Quick Start

### 1. Build the project
```bash
cargo build --release
```

### 2. Generate node identity
```bash
cargo run -p ghost-cli -- keygen
```

### 3. Connect two machines via direct P2P

**On Machine A (Host):**
```bash
cargo run -p ghost-cli -- invite
```

**On Machine B (Guest):**
```bash
cargo run -p ghost-cli -- join <ticket>
```

---

## License
Licensed under [MIT OR Apache-2.0](LICENSE).
