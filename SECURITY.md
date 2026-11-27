# Security model

This document says what GhostMesh protects, against whom, and what it does not. It describes the code
as it is, including its limits.

## What is protected, and how

**Packets between two devices.** Every data-bearing packet (IP traffic, chat, clipboard, keep-alives,
rekey and revocation messages) is encrypted and authenticated with ChaCha20-Poly1305. The 43-byte
packet header (type, source, destination) is authenticated as associated data, so it cannot be
altered. Keys are derived per direction from the static X25519 identities of both devices (BLAKE2s),
and the packet sequence number is the nonce. A 64-packet replay window rejects duplicates. A packet
that opens correctly proves the sender owns the private key of its NodeId.

> The `Noise_XX` handshake code in `ghost-crypto` is **not used** by the engine. Earlier documentation
> described the link as a Noise session; it is the construction above.

**Forward secrecy (rekey).** Every 10 minutes or 1 GiB (whichever comes first, per peer) the device
with the lower NodeId proposes a new epoch: both sides exchange ephemeral X25519 keys under the
current keys and derive new keys from the static secret *and* the ephemeral secret. Once the
ephemeral secrets are wiped, a later theft of an identity key does not decrypt traffic of past
epochs. The first epoch (before the first rekey, up to 10 minutes) has no forward secrecy. A peer
that does not understand rekey stays on the base keys.

**Pairing.** A device is trusted because its NodeId (the first 16 bytes of its public key) was
exchanged through an invite ticket or QR code and accepted by a user. There is no certificate
authority for devices. A ticket is a bearer token for *starting* a connection to you; treat it like
an address, not like a secret that grants access (the other side still has to be accepted).

**Private key at rest.** The key is held by the operating system vault (Windows Credential Manager,
macOS Keychain, Linux Secret Service). Without a vault it goes to a file encrypted with Argon2id and
ChaCha20-Poly1305 when `GHOSTMESH_KEY_PASSPHRASE` is set, otherwise to a file readable only by the
current user, and a warning is logged. A key found in an older `config.json` is moved to the store and
erased from the config only after reading it back succeeds. In memory, identity and session keys are
zeroized when dropped. The key is not protected against malware running as the same user: such
malware can ask the vault for it.

**Network exposure of a peer.** Each paired device has an access profile (`full`, `phone`, `web`,
`rdp`, `custom`, `blocked`). Restricted profiles deny everything by default and apply to the IP
packets read from and written to the virtual interface, IPv4 and IPv6. Replies to allowed
connections pass; new connections in the other direction do not. Packets with a source address that
does not belong to the sending device are dropped (except from your exit node). IP fragments after
the first, malformed packets and IPv6 packets with extension headers are refused for restricted
profiles. New devices default to `full` for compatibility with earlier versions: set a profile when
you pair a phone or any device you trust less.

**Names and HTTPS.** `ghostmesh serve` uses a certificate authority created on your machine. It is
restricted by an X.509 name constraint to `*.ghost`: installing it on a phone or browser does not let
it vouch for any other website. Its private key is stored like the identity key. Leaf certificates
last 90 days.

**Updates.** Update manifests are verified (XEdDSA signature under a pinned release key, version
strictly newer, HTTPS URL, SHA-256 of the file). No release key is published yet, so the verification
code accepts nothing, and automatic installation is not implemented.

## What the servers see

| | Relay | Rendezvous |
|---|---|---|
| Message contents | never (sealed before leaving the device) | n/a |
| Public keys / NodeIds | yes | yes (of those who publish or are looked up) |
| IP addresses of clients | yes | yes (publishers and askers) |
| Addresses published by a device | n/a | yes, until the record expires (at most 1 hour) |
| Who talks to whom, when, how much | yes (metadata) | which NodeIds are looked up, from which IP |
| Can it forge a message? | no | no |
| Can it forge a device's address record? | n/a | no: records are signed; a client rejects a bad signature |
| Can it make a device connect to a wrong address? | n/a | it can withhold or replay an old record (denial of service); a wrong address cannot complete the encrypted handshake |
| Persistent storage | none | none (memory only) |

Both servers validate sizes and formats, limit connections and rates per source, compare secrets in
constant time, never log contents, and treat every input from the network as hostile. The relay is
authenticated to clients by a pinned key; clients authenticate to the relay by proving possession of
their private key, so nobody can register under another device's NodeId. Whoever operates a server
learns the metadata above: host it yourself if that matters.

## Stolen or lost device

A stolen device that is unlocked, or whose key store is readable, can act as that device: it can
connect to your other devices with the permissions you gave it, until it is revoked.

**Revoke it:**

1. On any of your devices: `ghostmesh revoke <node_id>` (or **Revoke** in the app, Known Devices).
2. The device is blocked immediately, removed from the peer table, and the revocation is sent to every
   other device that is **connected at that moment**, which blocks it as well. A device that is
   offline is **not** told later: revoke while your other devices are on, or run the command on each
   one that was offline.
3. To limit the damage of a device you cannot revoke in time, give new devices a lifetime:
   `ghostmesh expire <node_id> <hours>`, and a restricted profile such as `phone`.
4. If the stolen device held a full-access profile for a long time, assume what it could reach was
   exposed, and change secrets for those services.

Revocation notices are accepted from any paired, authenticated device. In a personal mesh this is
deliberate (there is no administrator), but it means **a compromised paired device could revoke your
other devices** (a nuisance, not a data leak). You restore them by pairing again.

A revoked device keeps the old identity key: if it is re-paired, it is the same NodeId. To get a new
identity on a machine, delete its key from the vault and its config; it will generate a new one.

## Known limits

- Metadata is visible to relay and rendezvous operators, and to the network (UDP/TCP flows and sizes).
- No forward secrecy during the first rekey interval; no post-quantum protection.
- The relay protocol is not wrapped in TLS yet (see docs/SELF-HOSTING.md).
- Path MTU discovery is not implemented: the virtual interface uses a conservative fixed MTU (1380).
- Symmetric NATs on both sides cannot be punched; traffic falls back to the relay.
- The Linux Secret Service and macOS Keychain backends are compiled in but were **not exercised in
  tests** (only the Windows build of the vault path ran); the encrypted-file fallback is tested.
- DNS names are only as private as the local resolver: `.ghost` lookups stay on the machine.

## Reporting a vulnerability

Please report privately to the maintainer (see the repository owner's profile) before opening a public
issue. Include the version, what you did, and what you expected.
