#!/bin/sh
# Read-only check, run while the VPN is connected:
# shows whether DNS goes through the tunnel (fix for censored sites like YouTube).
IFACE=$(ip -o link show | awk -F': ' '/vpngate|tun/{print $2; exit}')
echo "tunnel interface: ${IFACE:-none}"
if [ -z "$IFACE" ]; then echo "VPN is not connected."; exit 0; fi
echo "--- per-link DNS (systemd-resolved) ---"
resolvectl status "$IFACE" 2>/dev/null | grep -E "DNS Server|DNS Domain|DefaultRoute" || echo "NO DNS published on the tunnel  <-- that is the bug"
echo "--- where www.youtube.com resolves (must NOT be via the physical link) ---"
resolvectl query www.youtube.com 2>&1 | grep -E "link:|www.youtube.com"
echo "If it says 'link: <physical nic>' or returns 10.10.34.x, DNS is still leaking to the censored resolver."
