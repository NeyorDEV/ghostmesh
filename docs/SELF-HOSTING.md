# Self-hosting the relay and rendezvous server

GhostMesh works without any server when two devices can reach each other directly. A server helps in
two cases, and you choose and host it yourself. There is **no default server**: nothing is configured
until you add one.

| Service | What it does | What it sees |
|---|---|---|
| **Relay** (`--listen`, TCP 8443) | Forwards sealed packets between two devices that cannot connect directly (CGNAT, strict firewalls, symmetric NAT). | Public keys, source/destination NodeIds, packet sizes and timing, IP addresses of the clients. Never the content: packets are encrypted end to end before they reach it. |
| **Rendezvous** (`--rendezvous-listen`, TCP 8444) | Stores each device's latest signed address record so known devices can find each other after an IP change, without a new ticket. | Public keys, the addresses each device published, and the IP of whoever asks. It cannot list devices, cannot forge or alter a record (devices verify the signature), and keeps everything in memory only. |

## Requirements

- A machine with a public IPv4 address (a small VPS is enough: the relay is light on CPU and memory).
- TCP 8443 and 8444 open (or the ports you choose).

## Run it

### With Docker

```bash
docker build -t ghost-relay .
docker run -d --name ghost-relay --restart unless-stopped \
    -p 8443:8443 -p 8444:8444 -v ghost-relay-data:/data ghost-relay
docker logs ghost-relay        # prints the relay public key
```

### From source

```bash
cargo build --release -p ghost-relay
./target/release/ghost-relay --listen 0.0.0.0:8443 --rendezvous-listen 0.0.0.0:8444 --key-file ghost-relay.key
```

On first start the relay creates its private key (`ghost-relay.key`, keep it private, mode 0600) and
prints a line like:

```
clients pin it with: relay.example.org:8443#3f9c...c1
```

That `host:port#publickey` string is what clients configure. The key is **pinned**: a client refuses a
relay whose key differs, so a hostile network cannot impersonate your relay.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--listen` | `0.0.0.0:8443` | relay address |
| `--rendezvous-listen` | `0.0.0.0:8444` | rendezvous address |
| `--no-rendezvous` | off | run the relay only |
| `--key-file` | `ghost-relay.key` | relay private key |
| `--max-connections` | 4096 | simultaneous relay connections |
| `--max-per-ip` | 16 | simultaneous relay connections from one IP |
| `--rate-kib` | 8192 | sustained forwarding rate per connection (KiB/s) |

Rendezvous limits (built in): 100 000 records, 30 publications and 120 lookups per minute per IP,
records live at most one hour.

### systemd

```ini
[Unit]
Description=GhostMesh relay
After=network-online.target

[Service]
User=ghost
ExecStart=/usr/local/bin/ghost-relay --key-file /var/lib/ghostmesh/ghost-relay.key
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ghostmesh

[Install]
WantedBy=multi-user.target
```

## Point your devices at it

```powershell
ghostmesh relay add relay.example.org:8443#<public key>
ghostmesh rendezvous add relay.example.org:8444
ghostmesh status
```

Add several relays and the client tries them in turn. Do this on every device of your mesh.

## Not provided yet

- **TLS / WebSocket on port 443.** The relay speaks its own framing over plain TCP. Packet contents
  are already encrypted and the relay is authenticated by key pinning, so TLS would only add
  camouflage against networks that block non-HTTPS traffic. Until it exists, a network that only
  allows 443 needs the relay on port 443 (`--listen 0.0.0.0:443`, with the rights to bind it).
- **Persistent state.** By design there is none: a restart forgets all records and registrations, and
  devices re-publish within seconds.
- **Metrics endpoint.** The relay logs a one-line summary every minute.

## Hardening checklist

- Run as an unprivileged user; keep the key file unreadable by others.
- Put the server behind a firewall that only exposes the two ports.
- Rotate the key if the machine is compromised: clients must then be given the new public key.
- Remember the server operator can see who talks to whom (metadata); host it yourself if that matters.
