#!/bin/sh
# Run when the tunnel feels slow. Measures latency under load and whether the limit is
# per-connection (parallel downloads add up) or the whole link (they share).
GW=$(ip route show | awk '/ dev tun/{print $1; exit}')
if [ -z "$GW" ]; then echo "VPN is not connected."; exit 0; fi
echo "=== 1. latency idle vs under load (bufferbloat check) ==="
ping -c 4 -W 3 -q "$GW" | tail -2
curl -s -o /dev/null --max-time 20 "https://speed.cloudflare.com/__down?bytes=50000000" &
CURL_PID=$!
sleep 3
echo "ping DURING download:"
ping -c 4 -W 3 -q "$GW" | tail -2
wait $CURL_PID
echo "=== 2. single vs parallel downloads (20s each) ==="
S1=$(curl -s -o /dev/null -w "%{speed_download}" --max-time 20 "https://speed.cloudflare.com/__down?bytes=200000000")
echo "single: $S1 B/s"
P1=$(curl -s -o /dev/null -w "%{speed_download}" --max-time 20 "https://speed.cloudflare.com/__down?bytes=200000000") &
P2=$(curl -s -o /dev/null -w "%{speed_download}" --max-time 20 "https://speed.cloudflare.com/__down?bytes=200000000") &
wait
echo "parallel streams: $P1 and $P2 B/s"
echo "=== interpretation ==="
# parallel total ≈ single  → per-connection limit: raise "TCP connections" in Settings → Advanced
# parallel total ≈ single  → also possible: relay uplink saturated → try another relay
# ping idle ≈ ping loaded  → no bufferbloat; ping under load ≫ idle → queueing on the relay