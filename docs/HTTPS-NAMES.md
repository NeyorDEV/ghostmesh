# Names and HTTPS: `https://<name>.ghost`

Browsers only allow the microphone, camera and many web APIs on pages served over **HTTPS with a
certificate they trust**. GhostMesh gives each machine a small certificate authority that is limited
to the `.ghost` zone, so that `https://my-pc.ghost` is valid on devices that installed it.

> **Reaching the mesh from a phone needs a GhostMesh client on the phone, and that client does not
> exist yet** (a mobile app was left out of this work). Everything below works between desktop
> machines today; the phone steps are ready for the day a phone can join the mesh (or reaches the
> mesh through another tunnel that routes `10.42.0.0/16` and resolves `.ghost`).

## 1. Choose a name

The name of a machine is its device name (computer name by default). Change it in `config.json`:
`"device_name": "my-pc"`. Names are lower-case letters, digits and `-`. Paired devices are reachable
under their alias too (`phone.ghost`).

## 2. Run the resolver and register it with the system

```powershell
ghostmesh up                    # the mesh must be up (virtual interface present)
ghostmesh dns run               # answers *.ghost on this machine's virtual IP, port 53
ghostmesh dns install           # administrator: only the .ghost zone is sent to it
```

`dns install` runs, depending on the system: a Name Resolution Policy Table rule on Windows
(`Add-DnsClientNrptRule -Namespace .ghost`), `resolvectl dns/domain` on Linux with systemd-resolved,
or a file `/etc/resolver/ghost` on macOS. `ghostmesh dns uninstall` reverses it. The resolver only
answers `.ghost`; it refuses everything else, so it is never an open resolver.

## 3. Publish a local web service

Say your assistant listens on `127.0.0.1:5173` (web page) and `127.0.0.1:8765` (WebSocket):

```powershell
ghostmesh serve 5173 --port 443            # https://<name>.ghost
ghostmesh serve 8765 --port 8443           # wss://<name>.ghost:8443
```

The first run creates the authority and prints where its certificate is
(`ghostmesh ca path`). `serve` listens on this machine's virtual IP, so only devices on the mesh can
reach it, and only with the permissions of their access profile
(`ghostmesh access <node_id> phone --ports 443,8443`).

## 4. Install the authority on the devices that open the page

Copy the authority **certificate** (`ghostmesh-ca.pem`; never the key) to the device.

### Windows / macOS / Linux (desktop)

- Windows: double-click the file, *Install Certificate*, *Current User*, place it in *Trusted Root
  Certification Authorities*.
- macOS: open it with Keychain Access, add to *login*, set *Always Trust* for SSL.
- Firefox keeps its own store: Settings, Privacy & Security, Certificates, *View Certificates*,
  Authorities, *Import*.

### iOS and iPadOS

1. Send `ghostmesh-ca.pem` to the device (AirDrop, mail, a link) and open it. Tap *Allow*, then
   Settings shows *Profile Downloaded*.
2. Settings, General, VPN & Device Management, tap the profile, *Install*.
3. Settings, General, About, *Certificate Trust Settings*, switch on full trust for *GhostMesh local CA*.

### Android

1. Send the file to the device.
2. Settings, Security (or *Security & privacy*), *More security settings*, *Encryption & credentials*,
   *Install a certificate*, *CA certificate*, confirm the warning, pick the file.
3. Chrome and most apps use the system store. Firefox for Android needs *Settings, About, tap the
   logo five times, Secret Settings, Use third party CA certificates*.

Because the authority carries an X.509 *name constraint* limited to `.ghost`, even a leaked authority
key cannot be used to impersonate any other website on a device that installed it. Each machine has
its own authority: if you serve from two machines, install both certificates.

## 5. Check

Open `https://<name>.ghost` in the browser: there must be no warning, and the page can ask for the
microphone. If the name does not resolve, check `ghostmesh dns run` is running and the system rule is
installed; if the certificate is refused, check the authority is installed *and trusted* on that
device.

## Not provided

- ACME certificates (Let's Encrypt, DNS-01) for a domain you own: not implemented. The local
  authority is used for every name.
- Automatic installation of the authority on a device.
- Starting the resolver and `serve` at boot (use `ghostmesh service install` for the node, and your
  system's own tools for the others).
