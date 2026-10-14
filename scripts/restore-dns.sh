#!/bin/sh
# Run this if internet stops working after disconnecting the VPN.
# Restores DNS and routing to their original state.
echo "Restoring DNS and routes..."
IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo\|tun\|docker\|veth\|br-" | head -1)
echo "physical interface: $IFACE"
resolvectl revert "$IFACE" 2>/dev/null && echo "  DNS reverted on $IFACE"
resolvectl default-route "$IFACE" yes 2>/dev/null && echo "  default-route restored on $IFACE"
resolvectl flush-caches 2>/dev/null && echo "  DNS cache flushed"
# leftover tunnel routes (should already be gone, but just in case)
ip route del 0.0.0.0/1 2>/dev/null && echo "  removed leftover 0.0.0.0/1"
ip route del 128.0.0.0/1 2>/dev/null && echo "  removed leftover 128.0.0.0/1"
ip -6 route del ::/1 2>/dev/null && echo "  removed leftover ::/1"
ip -6 route del 8000::/1 2>/dev/null && echo "  removed leftover 8000::/1"
echo ""
echo "Testing internet..."
curl -s -o /dev/null -w "google: code=%{http_code} time=%{time_total}s\n" --max-time 10 https://www.google.com/
echo "Done. If it still fails: sudo systemctl restart systemd-resolved"
