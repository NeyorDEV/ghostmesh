# Architecture

## Crates

| Crate | Role |
|---|---|
| `ghost-protocol` | Wire formats: `Packet` (43-byte header), `InviteTicket`, relay frames, rendezvous records. No I/O. |
| `ghost-crypto` | Identity keys, packet sealing, rekey epoch keys, relay proof, XEdDSA signatures, zeroization. |
| `ghost-nat` | STUN (several servers), NAT type detection, port prediction, UPnP / NAT-PMP / PCP port mapping. |
| `ghost-tun` | Virtual interface (IPv4 + IPv6), route table, per-peer packet filter. |
| `ghost-core` | The engine: peers, transports, relay and rendezvous clients, rekey, trust, access control, DNS, control channel, key store. |
| `ghost-relay` | Server binary: relay and rendezvous services. |
| `ghost-pki` | Local certificate authority and the HTTPS exposure used by `ghostmesh serve`. |
| `ghost-cli` | `ghostmesh` command line. |
| `apps/ghostmesh-gui` | Tauri desktop application. |

## Paths between two devices

```
 Device A                                                             Device B
 ┌──────────┐                                                       ┌──────────┐
 │ TUN      │  IP packet                                            │ TUN      │
 │ filter   │──► seal (epoch keys) ──► Packet ──┐        ┌──► open ─►│ filter   │
 └──────────┘                                   │        │           └──────────┘
                                                ▼        │
   1. direct UDP  ──────────────────────────────────────────────────►   (preferred, NAT hole punched)
   2. TCP link    ──────────────────────────────────────────────────►   (UDP blocked, TCP 443 / port)
   3. relay       ───► ┌────────────┐ ───────────────────────────────►   (no direct route)
                       │ ghost-relay│  sees: public keys, addresses,
                       └────────────┘  sizes. Not the content.
```

Choice per packet (`MeshEngine::send_packet`):

1. A TCP link to the peer, if one is up.
2. Direct UDP when a direct packet from the peer arrived in the last 25 s.
3. Otherwise the relay, if connected. Handshake and pairing packets also try UDP, so a direct path can
   be discovered. While a peer is only reachable through the relay, a keep-alive "probe" is sent
   straight over UDP every 3 s to its known addresses; as soon as one comes back, traffic switches to
   the direct path by itself.

The relay delivers packets to the engine like any transport; they are authenticated and replay-checked
exactly like direct ones, so the relay cannot inject traffic.

## Finding each other

```
 Device A                 Rendezvous server                Device B
    │  publish signed record  │                                │
    │  {key, addresses, ttl}  │                                │
    ├────────────────────────►│                                │
    │                         │◄───── lookup(NodeId of A) ─────┤
    │                         ├──── signed record of A ───────►│
    │                         │          (B verifies signature)│
    │◄══════ handshake to A's addresses (and via relay) ═══════╡
```

A device publishes at start-up, every 200 s, and whenever its candidate addresses change. Candidates
are, best first: addresses reported by STUN, the port opened on the router, a few predicted ports when
the NAT is symmetric, then LAN addresses. A device that has lost a known peer looks it up every 10 s.
The invite ticket no longer needs a fresh address: it only has to identify the device.

## NAT behaviour

STUN queries go out from the same UDP socket to several servers. Same mapped address and port from all
of them: cone NAT (punching works). Different ports: symmetric NAT. What to expect for each pair
(`ghost_nat::strategy`, covered by a unit test):

| This side \ other side | Open / Cone | Symmetric | Blocked (no UDP) |
|---|---|---|---|
| **Open / Cone** | punch | punch with port prediction | relay |
| **Symmetric** | punch with port prediction | relay | relay |
| **Blocked** | relay | relay | relay |

The engine does not branch on this table: it always sends handshakes to every candidate address at
once (including a few predicted ports for a symmetric NAT), tries the TCP fallback, and uses the relay
as soon as it is connected. The table says which outcome to expect and is what `ghostmesh status`
explains in its hints. The direct path is retried in the background after a fallback.

## Packet protection

```
 header (43 B, authenticated)  | payload = ChaCha20-Poly1305(key[epoch], nonce = sequence)
 magic type dest src sequence  |
                  └ top byte of the sequence = rekey epoch (0 = base keys)
```

Epoch 0 keys come from the static X25519 identities. A rekey installs epoch N keys derived from the
static secret and fresh ephemeral keys; the previous epoch keeps decrypting for 30 s.

## Trust and access

- Block list: revoked or expired NodeIds are dropped before any processing.
- Access profiles: applied to IP packets read from and written to the TUN, per peer.
- Source address check: a device may only send packets whose source IP is its own.

## Local services

- Control channel: JSON lines over a named pipe (Windows) or a Unix socket (mode 0600). Used by the
  CLI (`status`, ...) when `ghostmesh up` is running.
- Resolver: `<name>.ghost` answered on the virtual IP, port 53. The OS is told to use it for `.ghost`
  only (NRPT rule, `resolvectl`, `/etc/resolver/ghost`).
- HTTPS: `ghostmesh serve <port>` terminates TLS for `<name>.ghost` and forwards to `127.0.0.1:<port>`.
