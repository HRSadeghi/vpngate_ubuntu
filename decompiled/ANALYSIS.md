# VPN Gate Client (v4.44 build 9807) – analysis

Files: `client_exe.c`, `plugin_x86.c`, `plugin_x64.c` (Ghidra 12.1.4 pseudocode, symbols stripped → `FUN_<addr>`),
`decode_dat.py` (decoder for `VPNGate.dat`), `VPNGate_dat_hosts.csv` (decoded server list), `ExportC.java` (Ghidra script).

## Architecture
SoftEther VPN Client (Apache-2.0, open source) + closed "VG" layer (`.\VG.c`) + `VpnGatePlugin_{x86,x64}.dll`.

## Server-list sync (exe)
| Function | Role |
|---|---|
| `FUN_0041e5a0` | Loads `VpnGatePlugin_x86/x64.dll`, calls export `LoadPluginDll`, copies the returned 0x30-byte function table to `DAT_00919438` |
| `FUN_00411140` | Poll scheduler; reads `VGC_HTTP_POLL_INTERVAL_OK/ERROR`, `VGC_UDP_POLL_INTERVAL_*`, `VGC_NUM_TCP/UDP_TARGET_HOSTS` |
| `FUN_00413140` | Worker loop: pick target, call download, store result |
| `FUN_00412960` | Download: TCP (+optional SSL/proxy), `GET /vgc_download_dat/ HTTP/1.1` / `HOST: vpngate`, reads 4-byte BE length (max 32 MB) + payload, sends ack + 512 random bytes |
| `FUN_00413bc0` | Parse/verify downloaded `.dat` (format below) |
| `FUN_004136d0` / `FUN_00413760` | Read / write `@VPNGate.dat` |
| `FUN_00415600/ce0/e50` | HTTP polling against `x?.x?.client.api.vpngate2.jp/api/` and `/check/check.txt` |
| `FUN_004181a0` | DDNS update timing (`VG_DDNS_UPDATE_INTERVAL_MIN/MAX`) |
| `FUN_0041c6e0` | HTTP log upload (`VGC_HTTP_LOG_*`) |
| `FUN_00524180`, `FUN_005250a0`, `FUN_00525490`, `FUN_00525da0`, `FUN_005234e0` | UI: list columns, status strings, login/VPN counts, uptime, proxy dialog |

## `.dat` file format (verified by decoding the shipped file)
```
0x000  240 B   plaintext header, zero padded: "[VPNGate Data File]\r\n<timestamp>\r\n\r\n<SOAP_URL>…</SOAP_URL>"
0x0F0   20 B   random seed
0x104   rest   RC4( key = SHA1(seed) ) of a SoftEther "Pack":
                 data       bin   zlib stream (compressed=1), inflated size = data_size
                 data_size  int
                 sign       bin   128 B RSA-1024 signature (verified in FUN_006104f0 over timestamp+data+data_size)
                 soap_url   bin
                 timestamp  bin   8 B big-endian ms since epoch
                 compressed int
```
Inflated `data` is another Pack with 200 parallel arrays: IP, Fqdn, HostName, CountryShort/Full, Score, Ping/SpeedToJapan,
NumClients, NumLogin, Uptime, SslPorts, UdpPort, OpenVpnUdpPorts, L2TP, Os, Soft, Build, Owner, Abuse, Message, ...
Freshness check: `VG_ALLOW_TIME_DIFF` (default 0x7B98A00 ms ≈ 36 h) vs. local clock; stale lists are flagged invalid (+0x1080 = 0).

## Plugin DLL
Exports `LoadPluginDll` / `FreePluginDll`. Table at +0x18 (`FUN_10001410` x86) = RC4 decrypt with key SHA1(20 B seed);
+0x1c (`FUN_10001490`) = integrity helper (SHA1-based). Crypto is statically linked OpenSSL.

## Sample data
Shipped `VPNGate.dat` timestamp 2026-10-06 09:55:35 UTC, 200 hosts (JP 91, KR 44, RU 23, TH 16, US 7, VN 5).
