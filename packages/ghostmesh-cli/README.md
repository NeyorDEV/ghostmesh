# ghostmesh-cli

> Decentralized, zero-config, peer-to-peer encrypted mesh overlay CLI built with Rust.

Connect your devices directly over UDP without relying on centralized relay servers. It uses modern end-to-end cryptography (Noise Protocol) and automated NAT traversal (UDP Hole Punching via public STUN) to establish resilient, low-latency tunnels across firewalls and dynamic IP addresses.

---

## Quick Start via npx

No Rust installation required:

```bash
# Generate node cryptographic identity
npx ghostmesh-cli keygen

# Discover public NAT reflexive IP:Port
npx ghostmesh-cli discover

# Host an invitation ticket for a peer
npx ghostmesh-cli invite

# Join a peer via an invitation ticket
npx ghostmesh-cli join <ticket>
```

---

## Global Installation

```bash
npm install -g ghostmesh-cli
```

Then run `ghostmesh` anywhere:

```bash
ghostmesh invite
```

---

## Repository & Documentation
Source code, architecture, and protocol specifications:
[https://github.com/NeyorDEV/ghostmesh](https://github.com/NeyorDEV/ghostmesh)
