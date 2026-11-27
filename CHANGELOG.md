# Changelog

## 0.3.0

### Relay (new crate `ghost-relay`)
- Relay server: a node registers by proving it owns its private key (challenge answered with an
  X25519-derived proof), then hands over sealed packets that are forwarded to the registered
  destination. Source spoofing is refused, connections and rates are limited per IP and per
  connection, nothing is stored.
- Relay client in `ghost-core`: reads incoming packets and injects them into the engine, reconnects
  with growing back-off, rotates over a configurable list of relays, pins each relay's public key.
- Path selection: direct UDP when it works, relay otherwise, with a background probe that moves
  traffic back to the direct path as soon as it becomes possible.
- CLI: `ghostmesh relay add|remove|list`.

### Rendezvous
- Signed address records (XEdDSA, made with the existing X25519 identity: no new key), anti-replay by
  strictly increasing issue time, expiry, lookup only by known NodeId, in-memory storage.
- Client publishes at start-up, periodically and when candidate addresses change; known devices are
  looked up again when they are lost. A device can reconnect to a paired device without a new ticket.
- Configurable server list; none by default. CLI: `ghostmesh rendezvous add|remove|list`.
- `Dockerfile` and `docs/SELF-HOSTING.md`.

### NAT traversal
- Several STUN servers (configurable, built-in public defaults), NAT type detection (open, cone,
  symmetric, unknown, blocked), candidate set (STUN, router mapping, predicted ports, LAN),
  carrier-grade NAT detection, richer diagnostics and hints.
- CLI: `ghostmesh status` (uses a running node when there is one), `ghostmesh stun add|remove|list`.

### Keys and sessions
- Private key moved to the OS vault (Windows Credential Manager, macOS Keychain, Linux Secret
  Service), with an Argon2id + ChaCha20-Poly1305 encrypted file as fallback. Automatic migration from
  `config.json` with erasure of the old value after read-back. Zeroization of identity and session
  keys.
- Session rekey by time (10 min) and volume (1 GiB) with ephemeral keys (forward secrecy); the epoch
  is carried in the top byte of the packet sequence number. Peers without support stay on base keys.
- Device revocation (propagated to connected peers) and expiry. New packet types `Rekey`, `RekeyAck`,
  `Revoke`. CLI: `ghostmesh revoke`, `expire`, `devices`.

### Access control
- Per-device profiles (`full`, `phone`, `web`, `rdp`, `custom`, `blocked`) applied to IP packets on
  the virtual interface: protocol, destination ports, direction, deny by default for restricted
  profiles, replies allowed through a flow table, anti-spoofing of source addresses.
- CLI `ghostmesh access`, and a profile selector plus **Revoke** button in the desktop app.

### Names and HTTPS
- `.ghost` resolver, system integration commands (NRPT, resolvectl, /etc/resolver), certificate
  authority limited to `.ghost`, `ghostmesh serve` (HTTPS reverse proxy), `ghostmesh ca`,
  `docs/HTTPS-NAMES.md` with iOS and Android installation steps.

### Service and platforms
- `ghostmesh up` runs headless and exposes a local control channel (named pipe / Unix socket);
  `ghostmesh service install|uninstall` (systemd unit, launchd job, Windows logon task).
- IPv6 inside the tunnel (`fd42:474d::/32`), MTU 1380 by default (was 1420, which fragmented on
  1500-byte links), configurable.
- Signed update manifest verification (no release key published yet, nothing is accepted).
- CI: formatting and clippy checks on all three systems.

### Hardening and tests
- Tickets longer than 4 KiB are refused before decoding.
- Malformed-input tests for every decoder; `cargo-fuzz` targets in `fuzz/` for packets, tickets,
  relay frames, rendezvous frames, DNS queries and the IP filter.
- Integration tests: relay then direct switch, rendezvous after both addresses change, rekey by time
  and volume, revocation propagation, phone profile over a real link, HTTPS through the proxy.

### Not done
- Mobile clients (Android, iOS): left out on request.
- TLS / WebSocket in front of the relay; ACME certificates; Windows service integration with the
  service control manager; active path-MTU discovery; automatic update download and install.
