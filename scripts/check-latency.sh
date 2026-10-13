#!/bin/sh
# Compares the tunnel's latency against the direct path to the relay.
# Healthy client: tunnel RTT ≈ direct RTT + 5-20 ms. If the tunnel RTT is ~200 ms higher,
# the small-frame delay (Nagle) bug is back or the helper is stale.
GW=$(ip route show | awk '/ dev tun/{print $1; exit}')
IFACE=$(ip -o link show | awk -F': ' '/tun[0-9]+|vpngate/{print $2; exit}')
if [ -z "$GW" ] || [ -z "$IFACE" ]; then
  echo "VPN is not connected (no tun gateway route)."; exit 0
fi
echo "tunnel interface: $IFACE, gateway: $GW"
echo "--- ping the tunnel gateway (through the tunnel) ---"
ping -c 5 -W 3 "$GW" | tail -2
RELAY=$(ip route show | awk '/via/ && /dev ens|dev eth|dev wlp/{for(i=1;i<=NF;i++) if($i=="via") print $(i+1); exit}')
if [ -n "$RELAY" ]; then
  echo "--- ping the relay directly (baseline) ---"
  ping -c 5 -W 3 "$RELAY" | tail -2
fi
echo "Expect: tunnel RTT ≈ baseline + a few ms. Tunnel ≫ baseline (e.g. 440 vs 234 ms) = latency bug."