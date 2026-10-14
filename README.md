# VPN Gate for Ubuntu

Unofficial native Ubuntu/Linux client for [VPN Gate](https://www.vpngate.net) and other SoftEther
VPN servers, written in **Python**. It is a full port of the macOS Swift client (same protocol
implementation, same feature set, same defaults) — built from the protocol as implemented by the
Windows SoftEther VPN Client / VPN Gate plugin (v4.44 build 9807). It is not affiliated with VPN
Gate or SoftEther and does not claim full parity with the Windows client.

## What is implemented

- **Relay directory**: RSA-verified `VPNGate.dat` synchronisation, bundled bootstrap file, local
  cache, CSV mirror fallback, server details, search/filter, TCP ping measurement. The list table
  follows the Windows client's columns: DDNS name (Fqdn), ping to Google and to Japan, SSL ports
  in the client's priority order (443, 992, 995, 465, 585, 993, 22, then the rest), a UDP flag,
  uptime as minutes (up to 1 h), hours (up to 24 h) or days. The status line says the list is OK
  within 24 h of its timestamp and "stale" after that (a download is still accepted up to 36 h,
  as in the original).
- **List sync (same order as the Windows client)**: the project's HTTP API first, then relays,
  then the cached or bundled list.
  - *HTTP API*: `http://x<a>.x<b>.client.api.vpngate2.jp/api/?session_id=<random u64>` (`<a>` and
    `<b>` are random hex digits). The reply is the same signed `.dat`: it is used only if the RSA
    signature verifies and it is fresh, otherwise it is ignored. The original's `X-Transaction`
    header is not sent; if the server insists on it this step simply fails and the relays are
    used. Skipped when an app proxy is configured. A hidden preference (`alternativeMode: true`
    in `~/.local/share/vpngate/preferences.json`) adds the original's https retry.
  - *Relays* (peer to peer, over TLS): the relay that delivered the last list is tried first
    (remembered across launches), then up to 13 hosts offering port 443, then up to 13 others on
    the first port of their priority order.
  - *Tunables*: a verified list may carry a signed `DynList` that overrides client timers. It is
    parsed as the original does (names are case-insensitive, a value of 0 means "unset", values
    are clamped to [default/5, default*50]). Honoured: `VGC_HTTP_POLL_INTERVAL_OK` / `_ERROR`,
    `VGC_UDP_POLL_INTERVAL_ERROR`, `VGC_NUM_TCP_TARGET_HOSTS`, `VGC_TCP_POLL_CONNECT_TIMEOUT`,
    `VGC_TCP_POLL_SSL_TIMEOUT`, `VGC_HTTP_CONNECT_TIMEOUT`, `VGC_HTTP_DATA_TIMEOUT`. The shipped
    list sets the OK interval to 2 h.
  - *Schedule*: the next poll is now + a uniformly random time in [0, interval) (the original's
    `Rand % interval`), so the average is half the interval.
- **Client Manager**: saved connection settings for your own SoftEther servers (host, ports,
  virtual hub, user, Anonymous / Standard (SHA-0) password / Plain password / User certificate
  authentication). Passwords, certificates, private keys and proxy passwords are stored in the
  system secret store (Secret Service via `secretstorage`, with a `0600` file fallback), never in
  `accounts.json`. A damaged or newer `accounts.json` is never overwritten (it is kept as
  `accounts.json.corrupt-<date>`).
- **Connections to VPN Gate servers** use the Windows client's account: hub `VPNGATE`, anonymous,
  **one TCP connection**, **QoS off**, no compression, UDP acceleration allowed, ports in the
  priority order above (the extra fallback ports 992, 5555 and 1194 are a deviation: Windows
  retries one port only). A custom account has its own settings instead: "Max TCP Connections"
  (default 1, up to 32) and a **"Use QoS"** option (on by default; for VPN Gate connections QoS
  is always off).
- **Reconnect**: for a connection you start from the server list, with "Reconnect automatically"
  on (Settings), the app retries forever, every 15 s (the stock account's `NumRetry` infinite,
  `RetryInterval` 15 s), until you disconnect or connect elsewhere. The helper is asked to make a
  single attempt and the app does the waiting. For your own accounts the helper retries up to 8
  times, 3 s apart, then gives up.
- **Certificate login**: import a PEM or DER certificate with its **RSA** private key (PKCS#1 or
  PKCS#8, not passphrase-protected), or a `.p12` file (passphrase asked). EC keys and encrypted
  PEM keys are rejected with an explanation. The key is kept in the secret store and sent to the
  root helper over the uid-restricted local socket for each connection; the helper signs the
  server challenge.
- **Server certificate checking**: a configured SHA-1 or SHA-256 fingerprint is enforced;
  "Verify Server Certificate" without a fingerprint uses the system trust store; the default
  accepts any certificate (VPN Gate relays commonly use self-signed certificates).
- **Tunnel**: a Linux TUN interface, DHCP over the SoftEther virtual hub, routes and DNS, IPv6
  handling (below), connection history (last 100 connections, stored locally in
  `connection_history.json`), optional proxy (HTTP CONNECT / SOCKS5), launch at login (XDG
  autostart entry).
- **Protocol features**: additional TCP connections when an account allows more than one
  (replenished when they drop), per-block zlib compression, cluster redirects, UDP acceleration
  v2 (opportunistic, TCP fallback if UDP is not stable for 10 s; honours the compress flag; no
  NAT traversal, so only servers given as an IPv4 address, host-name servers use TCP only).
- Privileged helper systemd service (`vpngate-helper`, IPC version 7), GTK 3 window app, system
  tray icon (AppIndicator when available).

### Platform mapping (macOS → Ubuntu)

| macOS | Ubuntu (this port) |
| --- | --- |
| utun interface (`com.apple.net.utun_control`) | `/dev/net/tun` + `TUNSETIFF` (`IFF_TUN|IFF_NO_PI`) |
| `/sbin/route`, `/sbin/ifconfig` | `ip route`, `ip addr`, `ip link` (iproute2) |
| configd DNS (SCDynamicStore) | `resolvectl` (systemd-resolved), `/etc/resolv.conf` fallback |
| Keychain | Secret Service (`secretstorage`), `0600` file fallback |
| LaunchDaemon + launchctl | systemd service (`vpngate-helper.service`) |
| `getpeereid()` IPC check | `SO_PEERCRED` |
| MenuBarExtra (tray) | AppIndicator / AyatanaAppIndicator3 |
| SwiftUI windows | GTK 3 (PyGObject) |
| SMAppService login item | `~/.config/autostart` `.desktop` file |
| ChaCha20-Poly1305 (CryptoKit) | `cryptography` (pure-Python RFC 8439 fallback included) |

### Routing rules

Settings → Routing (and, per connection setting, its own editor) lets you send specific domains,
IP addresses or CIDR ranges **through the tunnel** (`Proxy`), **around it** (`Direct`, the
original default route), or drop them (`Block`) — the same idea as V2rayN's routing rules.
Domain rules match by suffix, exact name, keyword or regular expression; IP/CIDR rules match IPv4
and IPv6 literals and ranges. Rules are checked top to bottom, first match wins; "Bypass private
networks" adds the RFC 1918/CGNAT/link-local ranges as low-priority `Direct` rules. A connection
setting can use its own rules instead of the app-wide list.

- **How it stays safe to use somewhere that censors by domain**: a rule's domain is resolved by a
  small DNS proxy the helper runs on `127.0.0.1` (published as the system resolver while one is
  needed). A domain matched `Direct` is looked up through the physical network's own resolver,
  captured before the tunnel overrides it — never the tunnel's resolver. Every other domain (the
  default, and anything matched `Proxy`) is looked up only through the tunnel, so nothing but an
  explicitly `Direct` domain's name is ever exposed to an ISP-controlled resolver. A lookup that
  cannot be answered safely (no usable resolver, a timeout, an unparsable query) gets SERVFAIL,
  never a guess that could leak. IP/CIDR rules need no DNS proxy; they are plain routes (or a
  blackhole route, for `Block`).
- **Known limits**: resolution is UDP only (no TCP DNS fallback yet); an app that does its own
  DNS (DNS-over-HTTPS, a hardcoded resolver) bypasses domain matching, though IP/CIDR rules still
  apply to its traffic once connected; there is no bundled country IP/domain list — build one
  with custom CIDR/domain rules if you need it; V2rayN rule-set import/export is not implemented.

### IPv6
- **Block IPv6 on (default)**: `::/1` and `8000::/1` are routed into the tunnel and all IPv6 is
  dropped, so nothing leaks around the VPN; dual-stack sites fall back to IPv4.
- **Block IPv6 off**: IPv6 works only if the VPN network advertises an IPv6 prefix by Router
  Advertisement (SLAAC EUI-64 address, router solicitation retries, NDP). Otherwise IPv6 is still
  captured and dropped (no leak).
- Not implemented: privacy/stable addresses, DHCPv6, DNS over IPv6/RDNSS, router reachability
  tracking. When an address lifetime expires it is only no longer used; it stays on the tun until
  disconnect.

### Not implemented
- **"Knock"**: the Windows client sends servers with a build above 9074 that publish a
  `HostUniqueKey` a pre-connect blob before the TLS connection. This port does not either (same
  reason as the macOS app: the blob's pack key names are not recoverable from the decompile).
- **NAT-T / R-UDP**: neither the VPN transport nor the list download over R-UDP.
- **Half-connection** (never requested). The account field is stored and ignored.
- UDP-acceleration public-IP discovery through a relay; the original's "alt mode" decoys.

### Telemetry (opt-in, app only)
Off by default; nothing is scheduled or sent until you turn it on (Settings → Advanced shows the
switch). When on, every 10 minutes it POSTs `HostKey` (a random ID generated on this machine,
resettable in Settings; not derived from the machine name), `Build` and `ClientBuild` (9807),
`ClientVer` (444), `ClientOsName` ("Linux") and `IsClient` (1) to the statistics host of the VPN
Gate project (`x<c>.x<d>.statistics.api.vpngate2.jp`, where `<c>` and `<d>` are the third and
fourth characters of the HostKey, as in the original). No traffic, addresses or personal data are
sent.

Each connection setting's own `reconnectInterval` (default 3 s) and `reconnectCount` (default 8)
control the helper's own retry loop. VPN Gate connections ignore both: the app retries those
itself, forever, every 15 s, like the real VPN Gate account does.

### First-run disclaimer
The academic-use disclaimer must be accepted before any connection starts, from any screen
(server list, Client Manager, tray). Declining quits the app.

## Install

```sh
# Runtime dependencies (Ubuntu 22.04/24.04):
sudo apt install python3 python3-cryptography python3-gi gir1.2-gtk-3.0 \
                 gir1.2-ayatanaappindicator3-0.1 python3-secretstorage iproute2

sudo scripts/install-helper.sh    # helper -> /usr/local/bin, systemd service, bundled VPNGate.dat
./bin/vpngate                     # the app (also: menu launcher if installed system-wide)
```

After that the app never asks for anything: the helper (a systemd service) accepts requests from
the user logged in at the console. If the helper is missing or outdated, **Connect** shows a
one-time setup alert and installs it via `pkexec`/`sudo`, then connects by itself.

Run without installing: `python3 bin/vpngate` from this directory (the helper still needs
`scripts/install-helper.sh` once for actual VPN connections).

## Command line

```sh
build check / no-root handshake test:
  bin/vpngate-helper --probe 219.100.37.7 --port 443
  bin/vpngate-helper --probe <ip> --watch-udp 30   # + observe UDP acceleration usability

Foreground tunnel for debugging (sudo; Ctrl-C restores routes/DNS):
  sudo bin/vpngate-helper --connect <ip> [--port N]

Helper service:
  bin/vpngate-helper --version        # IPC version (7)
  systemctl status vpngate-helper
```

`--probe` performs the protocol hello and a DHCP lease only — no tun device, no routes — so it
runs without root.

## Tests

```sh
scripts/test.sh        # 189 tests, no network or root, ~1 s
```

The suite uses an in-memory fake hub that answers DHCP/ARP, a fake SoftEther session transport, a
recording double for `ip`, a fake DNS upstream, and a real Unix-socket IPC round trip, so the
session, bridge, network configuration and IPC are tested without privileges. The real
`assets/VPNGate.dat` is parsed and RSA-verified in tests, as are the SHA-0/RC4/ChaCha20-Poly1305
reference vectors.

## Layout

```
vpngate/core/      protocol core: Pack, SHA-0, RC4, packets, DataPhase, VPNGate.dat, TLS stream,
                   certificate pinning, routing rules, SoftEther errors, UDP-accel packets
vpngate/helper/    privileged helper: TUN device, iproute2 net config, DNS proxy, Ethernet
                   bridge (DHCP/ARP/NDP), SoftEther client, connection pool, UDP acceleration,
                   IPC server, session lifecycle
vpngate/app/       app services: model, list fetcher, accounts, keyring, connection history,
                   certificate import, helper install (systemd), GTK 3 user interface
packaging/         vpngate-helper.service unit
scripts/           install / uninstall / test / build-check / e2e tunnel
tests/             unittest suite (no network, no root)
assets/            bundled VPNGate.dat, icon, third-party notices
decompiled/        reverse-engineering notes (Ghidra pseudocode + VPNGate.dat decoder),
                   used to understand the protocol — not part of the build
```

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for diagnosis of every common
problem (DNS leaks, speed drops, relay stalls, browser issues, disconnect cleanup).

Quick tools:
```sh
scripts/check-tunnel.sh    # full diagnostics while connected
scripts/check-latency.sh   # tunnel vs direct latency
scripts/restore-dns.sh     # restore internet after a bad disconnect
```

## Notes / Security
- If the helper crashes, stale routes/DNS are cleaned on its next start (only routes it added —
  state is persisted in `/var/run/vpngate-helper.state`).
- Not affiliated with VPN Gate or SoftEther. VPN Gate relays are volunteer-run public servers:
  don't send sensitive traffic through them unless you trust the operator.
- `assets/NOTICE.md` has the third-party notices (the icon and watermark are SoftEther VPN
  Project material, Apache-2.0).
