#!/bin/sh
# Bring up a wireguard-go tunnel on the Mac pointing at the Wii's kernel WG.
# Run with: sudo sh wg_mac_up.sh
set -e

S=/private/tmp/claude-501/-Users-kaimizuguchi-gba-to-pc/6e48f361-1899-4995-955a-46ac8d44ab96/scratchpad
WII_PUB="1M3mzKjwZAImNPzuS+XfTc+KtLs6hrqvdwCGazYKq3s="

export WG_TUN_NAME_FILE=/tmp/wgtest_tun.name
rm -f /tmp/wgtest_tun.name
/usr/local/bin/wireguard-go utun
sleep 1
TUN=$(cat /tmp/wgtest_tun.name)
echo "tunnel device: $TUN"

/usr/local/bin/wg set "$TUN" \
	listen-port 51821 \
	private-key "$S/mac_wg.key" \
	peer "$WII_PUB" \
	allowed-ips 10.99.0.2/32 \
	endpoint 192.168.0.50:51820 \
	persistent-keepalive 5

ifconfig "$TUN" inet 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up
route -q add -host 10.99.0.2 -interface "$TUN" 2>/dev/null || true

echo "--- handshake test (3 pings) ---"
ping -c 3 -t 10 10.99.0.2 || true
echo "--- wg state ---"
/usr/local/bin/wg show "$TUN"
