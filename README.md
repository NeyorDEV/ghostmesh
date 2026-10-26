# GhostMesh

[![GitHub release](https://img.shields.io/github/v/release/NeyorDEV/ghostmesh?color=06b6d4)](https://github.com/NeyorDEV/ghostmesh/releases/latest)
[![CI & Build](https://github.com/NeyorDEV/ghostmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/NeyorDEV/ghostmesh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

> **Decentralized, zero-config, peer-to-peer encrypted mesh overlay network.**

GhostMesh connects your devices directly over UDP without relying on centralized relay servers. It uses modern end-to-end cryptography (Noise Protocol) and automated NAT traversal (UDP Hole Punching via public STUN) to establish resilient, low-latency tunnels across firewalls and dynamic IP addresses.

---

## Downloads

Download the pre-compiled binaries from the **[Latest Release](https://github.com/NeyorDEV/ghostmesh/releases/latest)**:

- **Desktop GUI (Windows x64):** [`ghostmesh-desktop-v0.2.2-windows-x64.zip`](https://github.com/NeyorDEV/ghostmesh/releases/download/v0.2.2/ghostmesh-desktop-v0.2.2-windows-x64.zip) (Standalone executable `GhostMesh.exe`, zero dependencies).
- **CLI Binary (Windows x64):** [`ghostmesh-cli-v0.2.2-windows-x64.zip`](https://github.com/NeyorDEV/ghostmesh/releases/download/v0.2.2/ghostmesh-cli-v0.2.2-windows-x64.zip).

---

## Key Features

- **Direct P2P Connectivity & Automated UPnP:** Traverses domestic NATs and firewalls via synchronized UDP hole punching and automated router port mapping.
- **Consent-Based Reconnection & Known Devices:** Remembers previously paired computers. One-click reconnect dispatches an authorization request with real-time **Accept** / **Decline** prompts and device revocation (**Forget**).
- **Per-Device Mesh Firewall:** Granular permissions per peer to enable or block Remote Desktop (RDP), GhostDrop file transfers, and temporary auto-revoking sessions.
- **GhostChat (P2P Encrypted Messaging):** Real-time instant messaging encrypted end-to-end with the Noise Protocol, ephemeral with zero server logs.
- **GhostDrop with Resume & Folder Support:** High-throughput P2P transfers with automatic resumption on network cuts and automatic folder zipping on the fly.
- **One-Click Windows Remote Desktop (RDP):** Built-in integration with native Windows `mstsc.exe` over encrypted virtual mesh IPs (`10.42.X.Y`). Control remote PCs at 60 FPS without installing third-party software (AnyDesk, TeamViewer).
- **Silent Windows Autostart:** Optional startup on Windows login running minimized directly in the system tray.
- **GhostSync (Continuous Folder Sync):** Automatically watches a local folder and synchronizes changes across connected peers in real time.
- **QR Code Instant Pairing:** Vector SVG QR Code generation for one-tap companion device pairing.
- **Multi-Hop Mesh Forwarding:** Transparent packet routing across intermediary nodes when direct links are asymmetric.
- **Corporate Firewall Fallback (HTTPS/WSS):** Automatic fallback relay tunnel when corporate networks filter outbound UDP.
- **End-to-End Cryptography:** Noise Protocol handshake (`Noise_XX` / `Curve25519` + `ChaCha20-Poly1305` + `BLAKE2s`).
- **Virtual Network Layer (Wintun):** Automatic collision-free virtual IPs (`10.42.X.Y/16`) for Windows SMB, SSH, LAN gaming, and remote desktop across the internet.
- **Cross-Platform CLI:** Clean commands for identity generation, node pairing, and live link monitoring.
- **Modular Architecture:** Extensible crates separating protocol serialization, cryptographic wrappers, NAT discovery, and peer orchestration.

---

## Desktop Dashboard Highlights (GUI)

- **Known Devices with Mutual Consent:** Save paired computers in local configuration (`config.json`). Clicking **Connect** sends an explicit authorization request that the remote user can **Accept** or **Decline**.
- **Per-Device Mesh Firewall:** Granular permission switches per saved device: toggle **RDP** access, **GhostDrop** file reception, or enforce **Temporary Sessions** that auto-revoke upon disconnection.
- **GhostChat (P2P Encrypted Messaging):** Send instant messages directly over the peer-to-peer authenticated Noise channel. Zero centralized servers, ephemeral memory storage.
- **GhostDrop (Resume & Auto-Folder Zip):** High-speed direct streaming over port 4243. Automatically resumes broken transfers from the last byte offset and packages folders into zip archives on the fly.
- **Windows Remote Desktop (RDP in 1-Click):** Launch native Windows `mstsc.exe` connected directly to the remote peer's virtual mesh IP (`10.42.X.Y`) without third-party remote desktop software.
- **Silent Windows Autostart:** One-click setting in the dashboard to register GhostMesh in Windows startup, launching silently into the system tray.
- **Integrated Update Checker:** Automatic GitHub releases notification banner in the header with 1-click update link.

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

### Option A: Instant Run via npx (No Rust required)

```bash
# On Machine A (Host)
npx ghostmesh-cli invite

# On Machine B (Guest)
npx ghostmesh-cli join <ticket>
```

### Option B: Build from source (Rust & Cargo)

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
