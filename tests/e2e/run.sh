#!/usr/bin/env bash
# End-to-end tests against the Docker lab (lab/). Usage:
#
#   ./dev e2e [VER] [cli|fpm|apache|all]      (or PHP_VERSION=8.4 tests/e2e/run.sh all)
#
# Prints one PASS/FAIL line per check and exits non-zero on any failure.
set -Eeuo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly lab="${root}/lab/lab.sh"
readonly assert="${root}/lab/assert"
readonly state="${root}/lab/state"
readonly cases=/src/tests/e2e/cases
readonly wg_endpoint=198.51.100.10
export PHP_VERSION="${PHP_VERSION:-8.4}"

pass=0
fail=0

ok() {
    printf 'PASS  %s\n' "$1"
    pass=$((pass + 1))
}

bad() {
    printf 'FAIL  %s\n' "$1"
    fail=$((fail + 1))
}

# Echoes PHP case output and counts its PASS/FAIL lines.
record() {
    local line
    while IFS= read -r line; do
        printf '%s\n' "${line}"
        case "${line}" in
            PASS*) pass=$((pass + 1)) ;;
            FAIL*) fail=$((fail + 1)) ;;
        esac
    done
}

php_case() {
    "${lab}" php "${cases}/$1" "${@:2}" 2>&1 || true
}

section() {
    printf '\n== %s\n' "$1"
}

now() {
    date +%s.%N
}

# mDNS announcements the host (avahi) multicasts onto the Docker bridge arrive
# in the container's capture; the PHP containers have no IPv6 address and run
# no mDNS, so this is inbound noise, not a leak.
readonly host_noise=(--allow "udp:[ff02::fb]:5353" --allow "udp:224.0.0.251:5353")

check_pcap() {
    local name="$1" what="$2"
    shift 2
    if python3 "${assert}/pcap_only.py" --pcap "${state}/pcap/${name}.pcap" "${host_noise[@]}" "$@" >"${state}/pcap/${name}.result" 2>&1; then
        ok "${what}"
    else
        bad "${what}"
        sed 's/^/      /' "${state}/pcap/${name}.result"
    fi
}

check_dns() {
    local what="$1"
    shift
    if python3 "${assert}/dns_log.py" "$@" >/tmp/php-vpn-e2e-dns.$$ 2>&1; then
        ok "${what}"
    else
        bad "${what}"
        sed 's/^/      /' /tmp/php-vpn-e2e-dns.$$
    fi
    rm -f /tmp/php-vpn-e2e-dns.$$
}

restore_tunnel() {
    "${lab}" tunnel up >/dev/null 2>&1 || true
    "${lab}" tunnel undrop >/dev/null 2>&1 || true
}
trap restore_tunnel EXIT

suite_cli() {
    section "CLI: exit IP (AC2)"
    record < <(php_case exit_ip.php 198.51.100.40)

    section "CLI: only UDP to the WireGuard endpoint, no host DNS (AC4/AC5/AC6)"
    local t0 routes_before
    routes_before="$("${lab}" exec php-cli ip route 2>/dev/null || true)"
    t0="$(now)"
    "${lab}" capture start e2e-vpn-only >/dev/null
    record < <(php_case vpn_only.php)
    "${lab}" capture stop e2e-vpn-only >/dev/null
    check_pcap e2e-vpn-only "pcap: every packet is UDP to/from ${wg_endpoint}:51820" \
        --allow "udp:${wg_endpoint}:51820" --require "udp:${wg_endpoint}:51820"
    check_dns "host resolver never asked for echo.lab.test / secret.vpn.test" \
        --log "${state}/logs/hostdns.log" --since "${t0}" --forbid secret.vpn.test --forbid echo.lab.test
    check_dns "tunnel resolver (10.13.13.1) answered secret.vpn.test" \
        --log "${state}/logs/tunneldns.log" --since "${t0}" --expect secret.vpn.test
    if [[ "$("${lab}" exec php-cli ip route 2>/dev/null || true)" == "${routes_before}" ]]; then
        ok "routing table of the PHP container unchanged"
    else
        bad "routing table of the PHP container changed"
    fi

    section "CLI: hostname endpoint (only the VPN server name uses the host resolver)"
    t0="$(now)"
    "${lab}" capture start e2e-endpoint-name >/dev/null
    record < <("${lab}" php -r 'echo VPN::wireguard("/etc/php-vpn/client4.conf")->request("GET", "http://echo.lab.test/ip")->body() === "198.51.100.10" ? "PASS  client4 (Endpoint = wg.lab.test:51820) works\n" : "FAIL  client4\n";' 2>&1)
    "${lab}" capture stop e2e-endpoint-name >/dev/null
    check_pcap e2e-endpoint-name "pcap: WireGuard UDP plus the endpoint lookup only" \
        --allow "udp:${wg_endpoint}:51820" --allow "udp:*:53" --allow "udp:127.0.0.11:*"
    check_dns "host resolver was asked for the endpoint name wg.lab.test" \
        --log "${state}/logs/hostdns.log" --since "${t0}" --expect wg.lab.test
    check_dns "...and never for the destination echo.lab.test" \
        --log "${state}/logs/hostdns.log" --since "${t0}" --forbid echo.lab.test

    section "CLI: fail closed when the tunnel is down (AC4)"
    "${lab}" tunnel down >/dev/null
    "${lab}" capture start e2e-tunnel-down >/dev/null
    record < <(php_case fail.php client1 http://echo.lab.test/ip VPN\\TunnelException 3 5 3.5)
    "${lab}" capture stop e2e-tunnel-down >/dev/null
    "${lab}" tunnel up >/dev/null
    check_pcap e2e-tunnel-down "pcap: nothing but WireGuard UDP (and the server's ICMP) while the tunnel is down" \
        --allow "udp:${wg_endpoint}:51820" --allow "icmp:${wg_endpoint}"

    "${lab}" tunnel drop >/dev/null
    "${lab}" capture start e2e-tunnel-drop >/dev/null
    record < <(php_case fail.php client1 http://echo.lab.test/ip VPN\\TunnelException 2 5 2.5)
    "${lab}" capture stop e2e-tunnel-drop >/dev/null
    "${lab}" tunnel undrop >/dev/null
    check_pcap e2e-tunnel-drop "pcap: silent packet loss does not trigger any other traffic" \
        --allow "udp:${wg_endpoint}:51820"

    section "CLI: tunnel lost in the middle of a response (AC4)"
    "${lab}" capture start e2e-midstream >/dev/null
    php_case fail.php client1 'http://echo.lab.test/drip?bytes=300000&ms=4000' VPN\\TimeoutException 3 6 7 >"${state}/e2e-midstream.out" &
    local bg=$!
    sleep 1.5
    "${lab}" tunnel drop >/dev/null
    wait "${bg}" || true
    "${lab}" tunnel undrop >/dev/null
    "${lab}" capture stop e2e-midstream >/dev/null
    record <"${state}/e2e-midstream.out"
    # The kernel may answer a late WireGuard packet with ICMP port unreachable
    # once PHP has exited; that is still only traffic with the endpoint.
    check_pcap e2e-midstream "pcap: no direct connection attempt after the loss" \
        --allow "udp:${wg_endpoint}:51820" --allow "icmp:${wg_endpoint}"

    section "CLI: wrong server key"
    record < <(php_case fail.php client-badkey http://198.51.100.30/ip VPN\\TunnelException 2 5 2.5)

    section "CLI: HTTP"
    record < <(php_case http.php)
    section "CLI: TLS"
    record < <(php_case tls.php)
    section "CLI: policy and DNS"
    record < <(php_case policy.php)
    section "CLI: sessions, fork, memory"
    record < <(php_case session.php 500)

    section "CLI: one key, several processes (cross-process lock)"
    local start elapsed outputs
    start="$(now)"
    outputs="$(for _ in 1 2 3 4; do php_case slow.php client1 300 2 & done; wait)"
    elapsed="$(echo "$(now) - ${start}" | bc)"
    record <<<"${outputs}"
    if (( $(echo "${elapsed} >= 2.4" | bc) )); then
        ok "8 requests of 300 ms on one key were serialised (${elapsed} s)"
    else
        bad "8 requests of 300 ms on one key overlapped (${elapsed} s < 2.4 s)"
    fi
    php_case slow.php client1 2500 >/dev/null &
    bg=$!
    sleep 0.6
    record < <(php_case lock.php)
    wait "${bg}" || true

    section "CLI: pool of two keys runs in parallel"
    start="$(now)"
    outputs="$(for _ in 1 2; do php_case slow.php client1,client2 1500 & done; wait)"
    elapsed="$(echo "$(now) - ${start}" | bc)"
    record <<<"${outputs}"
    if (( $(echo "${elapsed} < 2.9" | bc) )); then
        ok "two 1.5 s requests on a pool of two finished together (${elapsed} s)"
    else
        bad "pool requests did not run in parallel (${elapsed} s)"
    fi
}

suite_fpm() {
    section "PHP-FPM: two pools as different users, parallel load"
    local out good total pids
    out="$("${lab}" exec php-cli sh -c '
        { seq 24 | xargs -P 8 -I{} curl -s "http://a.lab.test/vpn.php?conf=/etc/php-vpn/client2.conf"; echo;
          seq 24 | xargs -P 8 -I{} curl -s "http://b.lab.test/vpn.php?conf=/etc/php-vpn/client3.conf"; echo; } ' 2>&1)"
    total="$(grep -c 'sapi=' <<<"${out}" || true)"
    good="$(grep -c '^vpn=198.51.100.10 direct=198.51.100.41 .*sapi=fpm-fcgi' <<<"${out}" || true)"
    pids="$(grep -o 'pid=[0-9]*' <<<"${out}" | sort -u | wc -l)"
    if [[ "${good}" == 48 && "${total}" == 48 ]]; then
        ok "48 FPM requests: VPN from 198.51.100.10, direct from 198.51.100.41 (${pids} workers)"
    else
        bad "FPM: ${good}/48 correct"
        grep -v '^vpn=198.51.100.10 direct=198.51.100.41' <<<"${out}" | head -5 | sed 's/^/      /'
    fi
    if "${lab}" exec php-cli curl -s 'http://b.lab.test/vpn.php?conf=/etc/php-vpn/client2.conf' | grep -q 'VPN\\ConfigException'; then
        ok "pool b cannot load pool a's profile"
    else
        bad "pool b could load pool a's profile"
    fi
}

suite_apache() {
    section "Apache mod_php (prefork)"
    local out good
    out="$("${lab}" exec php-cli sh -c 'seq 16 | xargs -P 4 -I{} curl -s http://198.51.100.43/vpn.php; echo' 2>&1)"
    good="$(grep -c '^vpn=198.51.100.10 direct=198.51.100.43 .*sapi=apache2handler' <<<"${out}" || true)"
    if [[ "${good}" == 16 ]]; then
        ok "16 Apache requests through the VPN, direct traffic unchanged"
    else
        bad "Apache: ${good}/16 correct"
        head -5 <<<"${out}" | sed 's/^/      /'
    fi

    # The CLI container uses the same key with its own lock directory, so its
    # handshake replaces the Apache workers' session at the server. They must
    # notice and re-key instead of hanging.
    "${lab}" php -r 'VPN::wireguard("/etc/php-vpn/client1.conf")->request("GET", "http://echo.lab.test/ip");' >/dev/null 2>&1
    out="$("${lab}" exec php-cli sh -c 'for i in 1 2 3 4; do curl -s -m 10 -w " t=%{time_total}\n" -o - http://198.51.100.43/vpn.php; done' 2>&1)"
    good="$(grep -c '^vpn=198.51.100.10' <<<"${out}" || true)"
    if [[ "${good}" == 4 ]]; then
        ok "Apache workers recover after the key was used elsewhere ($(grep -o ' t=[0-9.]*' <<<"${out}" | tr -d '\n'))"
    else
        bad "Apache workers did not recover after a session takeover"
        sed 's/^/      /' <<<"${out}"
    fi
}

main() {
    local which="${1:-all}"
    command -v bc >/dev/null || { echo "e2e: bc is required" >&2; exit 2; }
    "${lab}" up >/dev/null
    "${lab}" restart >/dev/null 2>&1
    "${lab}" php -r 'exit(extension_loaded("vpn") ? 0 : 1);' || { echo "e2e: php-vpn.so is not loaded in the lab (build it first)" >&2; exit 2; }
    printf 'php-vpn e2e, PHP %s\n' "$("${lab}" php -r 'echo PHP_VERSION;')"

    case "${which}" in
        cli) suite_cli ;;
        fpm) suite_fpm ;;
        apache) suite_apache ;;
        all) suite_cli; suite_fpm; suite_apache ;;
        *) echo "usage: $0 [cli|fpm|apache|all]" >&2; exit 2 ;;
    esac

    printf '\n== e2e summary (PHP %s): %d passed, %d failed\n' "${PHP_VERSION}" "${pass}" "${fail}"
    ((fail == 0))
}

main "$@"
