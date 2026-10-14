# VPN Gate for Ubuntu — Troubleshooting & Architecture

## Quick Diagnosis

```sh
scripts/check-tunnel.sh    # while connected: tunnel, DNS, ping, TCP, browser probe
scripts/check-latency.sh   # while connected: tunnel latency vs direct latency
scripts/restore-dns.sh     # if internet breaks after disconnecting
```

## Architecture (macOS → Ubuntu mapping)

| macOS | Ubuntu | File |
|-------|--------|------|
| utun (kernel L3) | `/dev/net/tun` + `TUNSETIFF` | `helper/tun.py` |
| `/sbin/route`, `ifconfig` | `ip route`, `ip addr`, `ip link` | `helper/netconfig.py` |
| configd (SCDynamicStore DNS) | `resolvectl` + DNS link isolation | `helper/netconfig.py` |
| Keychain | Secret Service (`secretstorage`), file fallback | `app/keyring.py` |
| LaunchDaemon | systemd service | `packaging/vpngate-helper.service` |
| `getpeereid()` IPC | `SO_PEERCRED` | `helper/ipcserver.py` |
| MenuBarExtra (tray) | AppIndicator / AyatanaAppIndicator3 | `app/ui/tray.py` |
| SwiftUI | GTK 3 (PyGObject) | `app/ui/` |
| SMAppService (login item) | `~/.config/autostart/*.desktop` | `app/helperinstaller.py` |
| CryptoKit | `cryptography` + pure-Python fallback | `core/` |
| NWConnection (async TLS) | blocking SSLSocket + executor threads | `core/stream.py` |

## Common Problems & Solutions

### 1. "No sites open / DNS resolves to 10.10.34.36"

**Symptom**: `resolvectl query www.youtube.com` returns `10.10.34.36` or `2001:4860:...`
**Cause**: The physical network's DNS is poisoned (Iranian censorship). The tunnel's DNS must be the only resolver.
**Fix** (in code, automatic): DNS link isolation disables DNS on the physical link when connected.
**If it still happens**: `sudo resolvectl flush-caches` then reconnect.

### 2. "Internet dies after disconnecting"

**Symptom**: After pressing Disconnect, no website opens.
**Cause**: The DNS link isolation disabled DNS on the physical link but didn't restore it.
**Fix**: `bash scripts/restore-dns.sh` or `sudo resolvectl revert ens33`.
**In code**: teardown now always reverts all links.

### 3. "YouTube doesn't open but curl works"

**Symptom**: `curl https://www.youtube.com/` → code=200, but browser shows "offline".
**Cause**: Browser cached poisoned DNS (AAAA or A) from before the VPN connected.
**Fix**: Incognito window, or `chrome://net-internals/#dns → Clear host cache`.
**In code**: AAAA returns NODATA when blockIPv6 is on (browser falls back to IPv4).

### 4. "Speed drops after downloading for a while"

**Symptom**: Starts at 1-4 Mbps, drops to 0.00 Mbps, then relay disconnects.
**Cause**: Relay-side traffic cap (official Tsukuba servers cap after ~90MB) or ISP throttling.
**Fix**: Set "TCP connections per VPN Gate connection" to 4 in Settings → Advanced.
**Also**: Switch relays (the app's failover does this automatically on stall).
**Cannot fix**: ISP DPI throttling of the VPN protocol — use WireGuard/Outline on a VPS for guaranteed speed.

### 5. "UDP acceleration breaks (echo lag)"

**Symptom**: Log shows `[udp] acceleration NOT usable (echo lag)`.
**Cause**: One-way NAT — our UDP datagrams don't reach the relay.
**Fix** (automatic): Falls back to TCP after the echo-lag guard fires (20s).

### 6. "Relay delivers zero data (in=0.00) but stays connected"

**Symptom**: Session stays "connected" but `in=0.00Mbps` for minutes.
**Cause**: Relay-side cap or congestion.
**Fix** (automatic): The 60s stall detector warns on the connection card and the failover rotates to the next relay.

### 7. "Most relays fail to connect"

**Symptom**: `Test Connection` shows most servers failing.
**Cause**: Volatile relays (volunteers), or ISP blocking relay IPs.
**Fix**: `Refresh List` → `Test Connection` → pick green ones.

## Settings Reference

| Setting | Default | Purpose |
|---------|---------|---------|
| Launch at login | Off | Autostart via `~/.config/autostart` |
| Reconnect automatically | On | VPN Gate: retry every 15s forever |
| Block IPv6 while connected | On | Prevents IPv6 leaks; DNS proxy answers AAAA with NODATA |
| TCP connections per VPN Gate connection | 1 | Raise to 3-4 to bypass per-connection throttling |
| Proxy | None | HTTP CONNECT / SOCKS5 |
| Routing → Default | Proxy | Unmatched traffic goes through tunnel |
| Routing → Bypass private networks | Off | RFC1918/CGNAT/link-local via original gateway |
| Routing → Bypass apps | Off | Selected apps keep their normal internet |
| Routing → Rules | Empty | IP/CIDR/domain rules (Direct/Proxy/Block) |
| Server list → Mirror URL | Empty | CSV mirror if vpngate.net is blocked |
| Diagnostics | Off | Opt-in anonymous telemetry |

## Log Reference (`/var/log/vpngate-helper.log`)

| Tag | Meaning |
|-----|---------|
| `[throughput]` | Every 5s: rates, totals, transport, sockets, UDP state |
| `[udp]` | UDP acceleration state changes (USABLE/NOT usable + reason) |
| `[path]` | Outbound data switched between UDP and TCP |
| `[pool]` | TCP socket added/removed (with reason) |
| `[dns]` | DNS publish/restore (including link isolation) |
| `[bypass]` | App bypass: processes moved/returned, live updates |
| `[route]` | Route add failures (e.g. "File exists" on reconnect) |
| `[session]` | Disconnect reason |

## DNS Flow (when connected)

```
App/browser → resolved → 127.0.0.1:53 (our DNS proxy)
                         ├─ AAAA (IPv6) → NODATA (falls back to A)
                         ├─ A (IPv4) → hub resolver via tunnel
                         └─ domain rules → Direct: physical resolver / Proxy: tunnel resolver
Physical link DNS: DISABLED (prevents merge with poisoned answers)
```

## Relay Failover

When the current relay stalls (60s no data) or disconnects:
1. The helper logs the stall warning
2. The app disconnects the dead session
3. The app rotates to the next relay (probe rank → score)
4. The last failed relay is skipped in each cycle
5. This repeats forever until a working relay is found

## Installing / Uninstalling

```sh
sudo scripts/install-helper.sh    # helper + systemd + bundled list
sudo scripts/uninstall-helper.sh  # remove everything
./bin/vpngate                     # run the app (no root needed)
python3 bin/vpngate-helper --version  # helper IPC version
```