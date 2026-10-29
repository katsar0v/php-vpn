#!/bin/bash
# WireGuard server of the lab + DNS inside the tunnel.
#   wg0 10.13.13.1/24, UDP 51820, clients 10.13.13.2+, MASQUERADE out of eth*,
#   dnsmasq on 10.13.13.1 only (log: state/logs/tunneldns.log).
# Generates (only if missing) server/client keys into state/wg and the wg-quick
# client confs into state/clients.
set -Eeuo pipefail
umask 022
export TZ=UTC

STATE=/state
WGDIR=$STATE/wg
CLIENTS=$STATE/clients
LOGS=$STATE/logs
SERVER_ADDR=10.13.13.1
SERVER_ENDPOINT_IP=198.51.100.10
SERVER_PORT=51820
MTU=1420

rm -f /run/wg-ready
mkdir -p "$WGDIR" "$CLIENTS" "$LOGS"

# ---------------------------------------------------------------- keys
keypair() { # name -> $WGDIR/name.key / name.pub (generated once)
    local n=$1
    if [[ ! -s $WGDIR/$n.key ]]; then
        (umask 077; wg genkey >"$WGDIR/$n.key")
        echo "wg-server: generated key $n"
    fi
    wg pubkey <"$WGDIR/$n.key" >"$WGDIR/$n.pub"
}

declare -A ADDR=(
    [client1]=10.13.13.2
    [client2]=10.13.13.3
    [client3]=10.13.13.4
    [client4]=10.13.13.5
    [nodns]=10.13.13.6
)
PEERS=(client1 client2 client3 client4 nodns)

keypair server
keypair badserver     # a valid-looking but wrong "server" public key
for p in "${PEERS[@]}"; do keypair "$p"; done

# ---------------------------------------------------------------- client confs
write_conf() { # <file> <client-key-name> <address> <server-pubkey-file> <endpoint> <dns:1|0>
    local file=$1 key=$2 addr=$3 spub=$4 endpoint=$5 dns=$6 tmp
    tmp=$(mktemp)
    {
        echo "[Interface]"
        echo "PrivateKey = $(<"$WGDIR/$key.key")"
        echo "Address = $addr/32"
        if [[ $dns == 1 ]]; then echo "DNS = $SERVER_ADDR"; fi
        echo "MTU = $MTU"
        echo
        echo "[Peer]"
        echo "PublicKey = $(<"$spub")"
        echo "AllowedIPs = 0.0.0.0/0"
        echo "Endpoint = $endpoint"
        echo "PersistentKeepalive = 25"
    } >"$tmp"
    if ! cmp -s "$tmp" "$CLIENTS/$file"; then
        install -m 0644 "$tmp" "$CLIENTS/$file"
        echo "wg-server: wrote $file"
    fi
    rm -f "$tmp"
}

EP="$SERVER_ENDPOINT_IP:$SERVER_PORT"
write_conf client1.conf client1 "${ADDR[client1]}" "$WGDIR/server.pub" "$EP" 1
write_conf client2.conf client2 "${ADDR[client2]}" "$WGDIR/server.pub" "$EP" 1
write_conf client3.conf client3 "${ADDR[client3]}" "$WGDIR/server.pub" "$EP" 1
write_conf client4.conf client4 "${ADDR[client4]}" "$WGDIR/server.pub" "wg.lab.test:$SERVER_PORT" 1
# same identity as client1 but pointing at a wrong server public key
write_conf client-badkey.conf client1 "${ADDR[client1]}" "$WGDIR/badserver.pub" "$EP" 1
# valid peer, no DNS line
write_conf client-nodns.conf nodns "${ADDR[nodns]}" "$WGDIR/server.pub" "$EP" 0

# ---------------------------------------------------------------- wg0
ip link del wg0 2>/dev/null || true
WG_BACKEND=kernel
if [[ ${WG_FORCE_GO:-0} == 1 ]] || ! ip link add wg0 type wireguard 2>/dev/null; then
    if [[ -c /dev/net/tun ]] && command -v wireguard-go >/dev/null; then
        if [[ ${WG_FORCE_GO:-0} == 1 ]]; then echo "wg-server: wireguard-go forced (LAB_WG_GO=1)"; else echo "wg-server: kernel wireguard unavailable, falling back to wireguard-go"; fi
        WG_BACKEND=wireguard-go
        wireguard-go wg0
        for _ in $(seq 50); do ip link show wg0 >/dev/null 2>&1 && break; sleep 0.1; done
    else
        echo "wg-server: cannot create wg0: no kernel wireguard and no /dev/net/tun (see compose.wggo.yaml)" >&2
        exit 1
    fi
fi
echo "wg-server: backend=$WG_BACKEND"

{
    echo "[Interface]"
    echo "PrivateKey = $(<"$WGDIR/server.key")"
    echo "ListenPort = $SERVER_PORT"
    for p in "${PEERS[@]}"; do
        echo
        echo "[Peer]"
        echo "PublicKey = $(<"$WGDIR/$p.pub")"
        echo "AllowedIPs = ${ADDR[$p]}/32"
    done
} | wg setconf wg0 /dev/stdin

ip addr add "$SERVER_ADDR/24" dev wg0
ip link set dev wg0 mtu "$MTU" up

# ---------------------------------------------------------------- forwarding + NAT
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]]
iptables -t nat -C POSTROUTING -s 10.13.13.0/24 ! -o wg0 -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s 10.13.13.0/24 ! -o wg0 -j MASQUERADE
iptables -P FORWARD ACCEPT

# ---------------------------------------------------------------- tunnel DNS
/lab/dnsmasq-run.sh /lab/tunneldns.conf "$LOGS/tunneldns.log" &
DNS_PID=$!

cleanup() {
    kill -TERM "$DNS_PID" 2>/dev/null || true
    ip link del wg0 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

chown -R "${LAB_UID:-0}:${LAB_GID:-0}" "$WGDIR" "$CLIENTS" 2>/dev/null || true
chmod 0700 "$WGDIR"; chown "${LAB_UID:-0}:${LAB_GID:-0}" "$WGDIR" 2>/dev/null || true

touch /run/wg-ready
echo "wg-server: ready (pubkey $(<"$WGDIR/server.pub"), endpoint $EP)"
wait "$DNS_PID"
echo "wg-server: tunnel dnsmasq exited" >&2
exit 1
