# GhostMesh

[![GitHub release](https://img.shields.io/github/v/release/NeyorDEV/ghostmesh?color=06b6d4)](https://github.com/NeyorDEV/ghostmesh/releases/latest)
[![CI & Build](https://github.com/NeyorDEV/ghostmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/NeyorDEV/ghostmesh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

> **Decentralized, zero-config, peer-to-peer encrypted mesh overlay network.**

GhostMesh connects your devices directly over UDP without relying on centralized relay servers. It uses modern end-to-end cryptography (Noise Protocol) and automated NAT traversal (UDP Hole Punching via public STUN) to establish resilient, low-latency tunnels across firewalls and dynamic IP addresses.

---

## Downloads

Téléchargez les exécutables autonomes directement depuis la **[Dernière Release (v0.3.0)](https://github.com/NeyorDEV/ghostmesh/releases/latest)** :

- **`ghostmesh-gui.exe` (Application Bureau avec Interface Graphique) :**
  - Application complète avec interface visuelle (tableau de bord, QR code, gestion des pairs, RDP en 1 clic, chat et transferts de fichiers).
  - À double-cliquer pour lancer l'application immédiatement sans installation.
- **`ghostmesh-cli.exe` (Ligne de commande - CLI / Console) :**
  - Binaire console destiné aux terminaux (PowerShell, CMD, bash), serveurs sans écran ou scripts automatisés (`ghost up`, `ghost status`, `ghost invite`).

---

## Key Features

- **Direct P2P Connectivity & Automated UPnP:** Traverses domestic NATs and firewalls via synchronized UDP hole punching and automated router port mapping.
- **Consent-Based Reconnection & Known Devices:** Remembers previously paired computers. One-click reconnect dispatches an authorization request with real-time **Accept** / **Decline** prompts and device revocation (**Forget**).
- **Per-Device Mesh Firewall:** Granular permissions per peer to enable or block Remote Desktop (RDP), GhostDrop file transfers, and temporary auto-revoking sessions.
- **Presse-Papier Partagé (Clipboard Sync):** Seamlessly share clipboard text between connected computers. 1-click send or automatic synchronization upon copy.
- **Exit Node Gateway (Internet Sharing):** Route your complete Internet connection through a trusted remote mesh peer (e.g. your home PC while on public Wi-Fi).
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
│   ├── ghost-protocol/   # Wire formats: packets, tickets, relay frames, rendezvous records
│   ├── ghost-crypto/     # Identity keys, packet sealing, rekey, signatures, zeroization
│   ├── ghost-nat/        # STUN, NAT type detection, UPnP / NAT-PMP / PCP
│   ├── ghost-tun/        # Virtual interface (IPv4 + IPv6), routes, per-peer packet filter
│   ├── ghost-core/       # Engine: peers, relay & rendezvous clients, rekey, trust, access, DNS
│   ├── ghost-relay/      # Server: relay + rendezvous (self-hosted, see docs/SELF-HOSTING.md)
│   ├── ghost-pki/        # Local CA limited to .ghost, HTTPS exposure (ghostmesh serve)
│   └── ghost-cli/        # CLI binary (ghostmesh ...)
├── apps/ghostmesh-gui/   # Tauri desktop app
└── fuzz/                 # cargo-fuzz targets for every network decoder
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the direct / relayed paths, [SECURITY.md](SECURITY.md) for
the threat model (what a relay sees, what a stolen device can do, how to revoke it) and
[CHANGELOG.md](CHANGELOG.md).

---

## Beyond direct connections

- **Relay** (`ghostmesh relay add host:port#key`): when two devices cannot connect directly (CGNAT,
  symmetric NAT, strict firewalls), sealed packets go through a relay **you host**. Traffic returns to
  the direct path by itself when it becomes possible. No relay is configured by default.
- **Rendezvous** (`ghostmesh rendezvous add host:port`): paired devices find each other again after
  an address change, without a new ticket.
- **Diagnostics** (`ghostmesh status`): NAT type, candidate addresses, relay, direct vs relayed peers.
- **Keys**: the private key lives in the OS vault; sessions are rekeyed every 10 minutes or 1 GiB.
- **Access control** (`ghostmesh access <node> phone --ports 8765,5173`): per-device profiles on the
  virtual network, deny by default for restricted profiles.
- **Revocation** (`ghostmesh revoke <node>`) and expiry (`ghostmesh expire <node> <hours>`).
- **Names and HTTPS** (`ghostmesh dns ...`, `ghostmesh serve 5173`): `https://<name>.ghost` with a
  valid certificate; see [docs/HTTPS-NAMES.md](docs/HTTPS-NAMES.md).
- **Background mode** (`ghostmesh service install`): systemd unit, launchd job or Windows logon task.

> **Note on cryptography.** Packets are protected with ChaCha20-Poly1305 using keys derived from the
> static X25519 identities, plus ephemeral rekeying. The `Noise_XX` handshake code in `ghost-crypto`
> is not used by the engine. Details in [SECURITY.md](SECURITY.md).

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
