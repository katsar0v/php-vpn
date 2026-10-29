#!/bin/bash
# Selftest-only WireGuard client: applies a wg-quick client conf with plain
# `wg setconf` + `ip` (no resolvconf, no wg-quick) so the server side can be
# validated.  Everything the lab considers "internet" is forced through wg0.
set -Eeuo pipefail
CONF=${WG_CLIENT_CONF:-/lab/clients/client1.conf}
FORCE_ROUTES=${WG_FORCE_ROUTES:-198.51.100.30}   # on-link hosts that must still use the tunnel
rm -f /run/wg-ready

ADDR=$(sed -nE 's/^Address[[:space:]]*=[[:space:]]*([^[:space:],]+).*/\1/Ip' "$CONF" | head -n1)
MTU=$(sed -nE 's/^MTU[[:space:]]*=[[:space:]]*([0-9]+).*/\1/Ip' "$CONF" | head -n1)
MTU=${MTU:-1420}

sed -E '/^[[:space:]]*(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)[[:space:]]*=/Id' "$CONF" >/run/wg0.conf
ip link del wg0 2>/dev/null || true
ip link add wg0 type wireguard
wg setconf wg0 /run/wg0.conf
ip addr add "$ADDR" dev wg0
ip link set dev wg0 mtu "$MTU" up
ip route add default dev wg0
for h in $FORCE_ROUTES; do ip route add "$h/32" dev wg0; done

touch /run/wg-ready
echo "wg-client: wg0 up with $ADDR from $CONF"
exec sleep infinity
