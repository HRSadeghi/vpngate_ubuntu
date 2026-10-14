#!/bin/sh
# Run this WHILE the VPN is connected. It tells you exactly where browsing breaks:
# tunnel → DNS → TCP → browser probe. Paste the whole output when reporting problems.
GW=$(ip route show | awk '/ dev tun/{print $1; exit}')
IFACE=$(ip -o link show | awk -F': ' '/tun[0-9]+|vpngate/{print $2; exit}')
echo "=== 1. tunnel ==="
if [ -z "$GW" ]; then echo "NOT CONNECTED (no tun gateway route)"; exit 0; fi
echo "interface $IFACE, gateway $GW — OK"
echo "=== 2. ping through tunnel (small / large) ==="
ping -c 3 -W 3 -q "$GW" | tail -2
echo "--- large packet (1200B payload): ---"
ping -c 3 -W 3 -s 1200 -q "$GW" 2>/dev/null | tail -1 || echo "large packets DIE (MTU/PMTUD issue)"
echo "=== 3. DNS: published on the tunnel? ==="
resolvectl status "$IFACE" 2>/dev/null | grep -E "DNS Server|DNS Domain" | head -3
echo "--- resolving youtube (which link answers?) ---"
resolvectl query www.youtube.com 2>&1 | grep -E "youtube|link:" | head -3
echo "=== 4. TCP through tunnel ==="
curl -s -o /dev/null -w "cloudflare: code=%{http_code} size=%{size_download} time=%{time_total}s\n" \
  --max-time 12 "https://speed.cloudflare.com/__down?bytes=1000000"
echo "=== 5. Chrome connectivity probe (what Chrome checks for 'offline') ==="
curl -s -o /dev/null -w "gstatic generate_204: code=%{http_code}\n" --max-time 10 \
  "http://www.gstatic.com/generate_204"
echo "=== 6. YouTube itself ==="
curl -s -o /dev/null -w "youtube: code=%{http_code} size=%{size_download} time=%{time_total}s\n" \
  --max-time 15 "https://www.youtube.com/"
echo ""
echo "READING THE RESULT:"
echo "- large ping DEAD, small OK        → MTU/PMTUD blackhole"
echo "- DNS via 'link: ens33'            → DNS is leaking (tunnel resolver not used)"
echo "- gstatic 204 FAILS but ping OK    → TCP data is being cut (DPI/relay)"
echo "- everything OK here but browser fails → the BROWSER is the problem:"
echo "  * disable any 'VPN' browser extension (it proxies browser traffic itself!)"
echo "  * test in an Incognito window (extensions off by default)"
echo "  * chrome://net-internals/#dns → Clear host cache"