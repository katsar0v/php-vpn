#!/usr/bin/env bash
# Self-test of the php-vpn lab itself (run via `lab/lab.sh selftest`, lab must be up).
# Validates the server side with the profile-gated wg-client container and the
# plumbing PHP tests rely on (DNS split, nginx/FPM pools, Apache, capture, tunnel loss).
set -Euo pipefail

LAB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_DIR=$(dirname -- "$LAB_DIR")
LAB=$LAB_DIR/lab.sh
STATE=$LAB_DIR/state
export PHP_VERSION=${PHP_VERSION:-8.4}
HOSTDNS_LOG=$STATE/logs/hostdns.log
TUNNELDNS_LOG=$STATE/logs/tunneldns.log

PASS=0; FAIL=0; FAILED=()
pass() { printf 'PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf 'FAIL  %s%s\n' "$1" "${2:+  -- $2}"; FAIL=$((FAIL + 1)); FAILED+=("$1"); }
section() { printf '\n== %s\n' "$1"; }
now() { date +%s.%N; }

cli() { "$LAB" exec php-cli "$@"; }
wgc() { "$LAB" exec wg-client "$@"; }
tr_cr() { tr -d '\r'; }

check_eq() { # name expected cmd...
    local name=$1 expected=$2 out; shift 2
    if out=$("$@" 2>&1 | tr_cr) && [[ $out == "$expected" ]]; then pass "$name"; else fail "$name" "expected '$expected', got '${out:0:300}'"; fi
}
check_has() { # name needle cmd...
    local name=$1 needle=$2 out; shift 2
    if out=$("$@" 2>&1 | tr_cr) && [[ $out == *"$needle"* ]]; then pass "$name"; else fail "$name" "expected to contain '$needle', got '${out:0:300}'"; fi
}
check_ok() { # name cmd...
    local name=$1 out; shift
    if out=$("$@" 2>&1); then pass "$name"; else fail "$name" "rc=$? ${out:0:300}"; fi
}
check_fails() { # name cmd...
    local name=$1 out; shift
    if out=$("$@" 2>&1); then fail "$name" "unexpectedly succeeded: ${out:0:200}"; else pass "$name"; fi
}

cleanup() {
    "$LAB" tunnel undrop >/dev/null 2>&1 || true
    "$LAB" tunnel up >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ------------------------------------------------------------------ preconditions
section "preconditions (PHP_VERSION=$PHP_VERSION)"
if ! "$LAB" exec wg-server wg show wg0 >/dev/null 2>&1; then
    echo "lab is not up; run: $LAB up" >&2; exit 2
fi
"$LAB" compose up -d --wait wg-client >/dev/null 2>&1 || { echo "could not start wg-client" >&2; exit 2; }
SO=$REPO_DIR/dist/php$PHP_VERSION/php-vpn.so
if [[ -f $SO ]]; then echo "php-vpn extension: present ($SO)"; else echo "php-vpn extension: not built yet (extension checks skipped)"; fi

# ------------------------------------------------------------------ 1. WireGuard server (via wg-client)
section "wg-server <-> wg-client (userspace-free kernel client, tunnel only)"
T_TUN0=$(now)
wgc dig @10.13.13.1 echo.lab.test +short +time=3 +tries=3 >/dev/null 2>&1
hs=0
for _ in $(seq 20); do
    hs=$(wgc wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -n1)
    [[ ${hs:-0} -gt 0 ]] && break
    sleep 1
done
if [[ ${hs:-0} -gt 0 ]]; then pass "wg-client handshake succeeds"; else fail "wg-client handshake succeeds" "latest handshake=${hs:-none}"; fi

check_eq "tunnel DNS (10.13.13.1) resolves secret.vpn.test -> 203.0.113.20" 203.0.113.20 \
    wgc dig @10.13.13.1 secret.vpn.test +short +time=3 +tries=2
check_eq "tunnel DNS resolves echo.lab.test -> 198.51.100.30" 198.51.100.30 \
    wgc dig @10.13.13.1 echo.lab.test +short +time=3 +tries=2
check_eq "through tunnel: curl http://echo.lab.test/ip == 198.51.100.10 (wg-server NAT)" 198.51.100.10 \
    wgc curl -sS --max-time 8 --resolve echo.lab.test:80:198.51.100.30 http://echo.lab.test/ip
check_has "through tunnel: https://secret.vpn.test/ works with the lab CA" "lab server secret" \
    wgc curl -sS --max-time 8 --cacert /lab/ca/lab-ca.pem --resolve secret.vpn.test:443:203.0.113.20 https://secret.vpn.test/
check_eq "through tunnel: secret sees the wg-server (203.0.113.10) as client" 203.0.113.10 \
    wgc curl -sS --max-time 8 --cacert /lab/ca/lab-ca.pem --resolve secret.vpn.test:443:203.0.113.20 https://secret.vpn.test/ip
T_TUN1=$(now)

section "DNS split: tunnel names never reach the host resolver"
check_ok "hostdns.log: no echo.lab.test / secret.vpn.test query from wg-client during tunnel-only steps" \
    python3 "$LAB_DIR/assert/dns_log.py" --log "$HOSTDNS_LOG" --since "$T_TUN0" --until "$T_TUN1" \
        --client 198.51.100.60 --forbid secret.vpn.test --forbid echo.lab.test
check_ok "tunneldns.log: secret.vpn.test queried from tunnel address 10.13.13.2" \
    python3 "$LAB_DIR/assert/dns_log.py" --log "$TUNNELDNS_LOG" --since "$T_TUN0" --client 10.13.13.2 --expect secret.vpn.test

# ------------------------------------------------------------------ 2. direct path from php-cli
section "direct (non-VPN) path from php-cli"
T_DIRECT=$(now)
check_eq "direct curl http://echo.lab.test/ip from php-cli == 198.51.100.40" 198.51.100.40 \
    cli curl -sS --max-time 8 http://echo.lab.test/ip
check_eq "direct php file_get_contents from php-cli == 198.51.100.40" 198.51.100.40 \
    cli php -r 'echo file_get_contents("http://echo.lab.test/ip");'
check_eq "lab.sh php runs php in php-cli" "$PHP_VERSION" bash -c "'$LAB' php -r 'echo PHP_MAJOR_VERSION, \".\", PHP_MINOR_VERSION;'"
check_fails "secret.vpn.test does not resolve from php-cli (getent)" cli getent hosts secret.vpn.test
check_fails "https://secret.vpn.test/ is unreachable directly from php-cli" cli curl -sS --max-time 5 https://secret.vpn.test/
check_eq "wg.lab.test -> 198.51.100.10 via hostdns (client4 endpoint hostname)" 198.51.100.10 \
    bash -c "'$LAB' exec php-cli getent hosts wg.lab.test | awk '{print \$1}'"
check_ok "hostdns.log shows php-cli's (198.51.100.40) echo.lab.test query" \
    python3 "$LAB_DIR/assert/dns_log.py" --log "$HOSTDNS_LOG" --since "$T_DIRECT" --client 198.51.100.40 --expect echo.lab.test
check_ok "hostdns.log shows php-cli's secret.vpn.test lookup (so a tunnel-only test CAN detect leaks)" \
    python3 "$LAB_DIR/assert/dns_log.py" --log "$HOSTDNS_LOG" --since "$T_DIRECT" --client 198.51.100.40 --expect secret.vpn.test
check_ok "echo.log recorded the request (remote 198.51.100.40, host echo.lab.test, path /ip)" \
    bash -c "tail -n 40 '$STATE/logs/echo.log' | grep -qE ' 198\\.51\\.100\\.40 GET echo\\.lab\\.test /ip\$'"

section "TLS listeners (from php-cli, system trust store has the lab CA)"
check_eq "https://echo.lab.test/ip (443, lab CA) works" 198.51.100.40 cli curl -sS --max-time 8 https://echo.lab.test/ip
check_eq "PHP streams verify the lab CA (file_get_contents https://echo.lab.test/ip)" 198.51.100.40 \
    cli php -r 'echo file_get_contents("https://echo.lab.test/ip");'
check_eq "/etc/php-vpn/lab-ca.pem is installed (0644)" "644" "$LAB" exec php-cli stat -c '%a' /etc/php-vpn/lab-ca.pem
check_fails "https://echo.lab.test:8443 (wrong.lab.test cert) fails verification" cli curl -sS --max-time 8 https://echo.lab.test:8443/ip
check_fails "https://echo.lab.test:9443 (self-signed) fails verification" cli curl -sS --max-time 8 https://echo.lab.test:9443/ip
check_eq "https://echo.lab.test:8443 with -k works" 198.51.100.40 cli curl -ksS --max-time 8 https://echo.lab.test:8443/ip
check_eq "https://echo.lab.test:9443 with -k works" 198.51.100.40 cli curl -ksS --max-time 8 https://echo.lab.test:9443/ip

# ------------------------------------------------------------------ 3. echo server routes
section "echo server routes (smoke)"
E=http://echo.lab.test
check_has "/echo POST: method, headers pairs, body" '"method":"POST"' cli curl -sS --max-time 8 -X POST -H 'X-Dup: 1' -H 'X-Dup: 2' -d 'hello=world' "$E/echo?a=1&a=2"
check_has "/echo keeps duplicate request headers as pairs" '["X-Dup","1"],["X-Dup","2"]' cli curl -sS --max-time 8 -H 'X-Dup: 1' -H 'X-Dup: 2' "$E/echo"
check_eq "/status/418" 418 cli curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$E/status/418"
check_eq "/redirect?code=307 -> Location" "307 http://echo.lab.test/ip" \
    cli curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 8 "$E/redirect?code=307&to=http%3A%2F%2Fecho.lab.test%2Fip"
check_eq "/redirect-chain?n=3 followed -> /ip" 198.51.100.40 cli curl -sSL --max-time 8 "$E/redirect-chain?n=3"
check_eq "/redirect-chain?n=3 makes 3 redirects" 3 cli curl -sSL -o /dev/null -w '%{num_redirects}' --max-time 8 "$E/redirect-chain?n=3"
check_eq "/bytes?n=100000 length" 100000 cli curl -sS --max-time 8 -o /dev/null -w '%{size_download}' "$E/bytes?n=100000"
check_eq "/bytes sha256 matches X-Content-SHA256" ok \
    bash -c "'$LAB' exec php-cli sh -c 'h=\$(curl -sSD /tmp/h.txt --max-time 8 \"$E/bytes?n=1000003\" | sha256sum | cut -d\" \" -f1); grep -qi \"^x-content-sha256: \$h\" /tmp/h.txt && echo ok'"
check_has "/chunked is Transfer-Encoding: chunked" "chunked" cli sh -c "curl -sS -D - -o /dev/null --max-time 8 '$E/chunked?chunks=3&size=4' | grep -i '^transfer-encoding'"
check_eq "/chunked body" aaaabbbbcccc cli curl -sS --max-time 8 "$E/chunked?chunks=3&size=4"
check_has "/gzip has Content-Encoding: gzip and decodes" '"gzip":true' cli curl -sS --compressed --max-time 8 "$E/gzip"
check_eq "/gzip-bomb?mb=5 inflates to 5 MiB with --compressed" 5242880 cli sh -c "curl -sS --compressed --max-time 20 '$E/gzip-bomb?mb=5' | wc -c"
check_ok "/gzip-bomb?mb=5 is small on the wire (<20 KB)" \
    cli sh -c "[ \$(curl -sS --max-time 20 -o /dev/null -w '%{size_download}' '$E/gzip-bomb?mb=5') -lt 20000 ]"
check_eq "/headers-multi sends two Set-Cookie" 2 cli sh -c "curl -sSD - -o /dev/null --max-time 8 $E/headers-multi | grep -ci '^set-cookie:'"
check_eq "HEAD /ip: status 200" 200 cli curl -sSI -o /dev/null -w '%{http_code}' --max-time 8 "$E/ip"
check_eq "HEAD /ip: Content-Length 13, no body read" 13 \
    cli sh -c "curl -sSI --max-time 8 '$E/ip' | tr -d '\\r' | awk 'tolower(\$1)==\"content-length:\"{print \$2}'"
check_ok "/slow?ms=1200 delays the response (>=1.2s)" \
    cli sh -c "t=\$(curl -s -o /dev/null -w '%{time_starttransfer}' --max-time 8 '$E/slow?ms=1200'); awk -v t=\$t 'BEGIN{exit !(t>=1.15)}'"
check_ok "/drip?bytes=5&ms=300 takes >=1.1s total" \
    cli sh -c "t=\$(curl -s -o /dev/null -w '%{time_total}' --max-time 8 '$E/drip?bytes=5&ms=300'); awk -v t=\$t 'BEGIN{exit !(t>=1.1)}'"
check_ok "/stall never answers (client times out)" \
    cli sh -c "curl -s --max-time 2 '$E/stall'; [ \$? -eq 28 ]"
check_ok "OPTIONS/PUT/PATCH/DELETE are accepted" \
    cli sh -c "for m in OPTIONS PUT PATCH DELETE; do [ \$(curl -s -o /dev/null -w '%{http_code}' -X \$m --max-time 8 '$E/echo') = 200 ] || exit 1; done"

# ------------------------------------------------------------------ 4. nginx + php-fpm pools
section "nginx + php-fpm (two pools, different users)"
check_eq "a.lab.test/direct.php == 198.51.100.41" 198.51.100.41 cli curl -sS --max-time 10 http://a.lab.test/direct.php
check_eq "b.lab.test/direct.php == 198.51.100.41" 198.51.100.41 cli curl -sS --max-time 10 http://b.lab.test/direct.php
check_has "a.lab.test/info.php runs as poola (sapi fpm-fcgi)" "user=poola" cli curl -sS --max-time 10 http://a.lab.test/info.php
check_has "b.lab.test/info.php runs as poolb" "user=poolb" cli curl -sS --max-time 10 http://b.lab.test/info.php
check_has "info.php reports sapi=fpm-fcgi" "sapi=fpm-fcgi" cli curl -sS --max-time 10 http://a.lab.test/info.php
check_has "fpm pool a sees container env (clear_env=no)" "env_PHP_VPN_LAB=1" cli curl -sS --max-time 10 http://a.lab.test/info.php
check_eq "fpm /etc/php-vpn/client2.conf is 600 poola:poola" "600 poola:poola" "$LAB" exec php-fpm stat -c '%a %U:%G' /etc/php-vpn/client2.conf
check_eq "fpm /etc/php-vpn/client3.conf is 600 poolb:poolb" "600 poolb:poolb" "$LAB" exec php-fpm stat -c '%a %U:%G' /etc/php-vpn/client3.conf
check_eq "fpm /etc/php-vpn/client1.conf is 640 root:www-data" "640 root:www-data" "$LAB" exec php-fpm stat -c '%a %U:%G' /etc/php-vpn/client1.conf
check_ok "poola can read client2.conf but not client3.conf / client1.conf" \
    "$LAB" exec php-fpm su -s /bin/sh poola -c 'test -r /etc/php-vpn/client2.conf && ! test -r /etc/php-vpn/client3.conf && ! test -r /etc/php-vpn/client1.conf'
check_ok "poolb can read client3.conf but not client2.conf" \
    "$LAB" exec php-fpm su -s /bin/sh poolb -c 'test -r /etc/php-vpn/client3.conf && ! test -r /etc/php-vpn/client2.conf'

# ------------------------------------------------------------------ 5. Apache
section "php-apache (mod_php, prefork)"
check_has "apache info.php works and reports sapi=apache2handler" "sapi=apache2handler" cli curl -sS --max-time 10 http://198.51.100.43/info.php
check_eq "apache direct.php == 198.51.100.43" 198.51.100.43 cli curl -sS --max-time 10 http://198.51.100.43/direct.php
check_has "apache MPM is prefork" "prefork" "$LAB" exec php-apache apache2ctl -V
check_eq "apache /etc/php-vpn/client1.conf is 640 root:www-data" "640 root:www-data" "$LAB" exec php-apache stat -c '%a %U:%G' /etc/php-vpn/client1.conf
check_eq "php-cli /etc/php-vpn/client1.conf is 640 root:www-data" "640 root:www-data" "$LAB" exec php-cli stat -c '%a %U:%G' /etc/php-vpn/client1.conf
check_has "php-cli has pcntl" "pcntl" cli php -m

# ------------------------------------------------------------------ 6. client confs
section "generated client confs"
C=$STATE/clients
check_ok "client1..4, client-badkey, client-nodns exist" bash -c "cd '$C' && ls client1.conf client2.conf client3.conf client4.conf client-badkey.conf client-nodns.conf"
check_ok "client1..3: Endpoint 198.51.100.10:51820, DNS 10.13.13.1, MTU 1420, AllowedIPs 0.0.0.0/0, keepalive 25" \
    bash -c "cd '$C' && for f in client1 client2 client3; do grep -q '^Endpoint = 198.51.100.10:51820\$' \$f.conf && grep -q '^DNS = 10.13.13.1\$' \$f.conf && grep -q '^MTU = 1420\$' \$f.conf && grep -q '^AllowedIPs = 0.0.0.0/0\$' \$f.conf && grep -q '^PersistentKeepalive = 25\$' \$f.conf || exit 1; done"
check_ok "client4 uses Endpoint wg.lab.test:51820" grep -q '^Endpoint = wg.lab.test:51820$' "$C/client4.conf"
check_ok "client-nodns has no DNS line" bash -c "! grep -q '^DNS' '$C/client-nodns.conf'"
check_ok "client-badkey differs from client1 only in the server PublicKey" \
    bash -c "[ \"\$(diff '$C/client1.conf' '$C/client-badkey.conf' | grep -c '^[<>]')\" = 2 ] && diff '$C/client1.conf' '$C/client-badkey.conf' | grep -q PublicKey"
check_ok "distinct addresses 10.13.13.2..5 for client1..4" \
    bash -c "cd '$C' && [ \"\$(grep -h '^Address' client1.conf client2.conf client3.conf client4.conf | sort -u | wc -l)\" = 4 ]"

# ------------------------------------------------------------------ 7. isolation properties
section "isolation properties"
check_ok "no published host ports" bash -c "! docker ps --filter label=com.docker.compose.project=php-vpn-lab --format '{{.Ports}}' | grep -q -- '->'"
check_eq "internet network is internal" true docker network inspect php-vpn-lab_internet --format '{{.Internal}}'
check_eq "vpnside network is internal" true docker network inspect php-vpn-lab_vpnside --format '{{.Internal}}'
for svc in php-cli php-fpm php-apache; do
    cap=$("$LAB" exec "$svc" sh -c 'grep CapEff /proc/self/status' 2>/dev/null | awk '{print $2}' | tr -d '\r')
    if [[ -n $cap ]] && (( (0x$cap & 0x1000) == 0 )); then pass "$svc has no CAP_NET_ADMIN (CapEff=$cap)"; else fail "$svc has no CAP_NET_ADMIN" "CapEff=$cap"; fi
done
check_ok "php-cli has no default route (internal network)" bash -c "! '$LAB' exec php-cli ip route | grep -q '^default'"

# ------------------------------------------------------------------ 8. extension (only when built)
if [[ -f $SO ]]; then
    section "php-vpn extension is loaded"
    check_has "php-cli: extension_loaded('vpn')" "vpn loaded" cli php /src/lab/www/info.php
    check_has "php-fpm pool a: vpn loaded" "vpn loaded" cli curl -sS http://a.lab.test/info.php
    check_has "php-apache: vpn loaded" "vpn loaded" cli curl -sS http://198.51.100.43/info.php
fi

# ------------------------------------------------------------------ 9. capture
section "packet capture (sniff -> lab/state/pcap)"
PCAP=$STATE/pcap/selftest.pcap
rm -f "$PCAP"
check_ok "capture start" "$LAB" capture start selftest
cli curl -sS --max-time 8 http://echo.lab.test/ip >/dev/null 2>&1
cli getent hosts a.lab.test >/dev/null 2>&1
check_ok "capture stop" "$LAB" capture stop selftest
check_ok "pcap exists and is non-empty" test -s "$PCAP"
check_ok "pcap_only parses it; direct traffic is covered by tcp:echo:80 + udp:hostdns:53 + udp:127.0.0.11:*" \
    python3 "$LAB_DIR/assert/pcap_only.py" --pcap "$PCAP" --require tcp:198.51.100.30:80 --allow udp:198.51.100.53:53 --allow 'udp:127.0.0.11:*'
check_fails "pcap_only FAILS when only the WG endpoint is allowed (violation detection works)" \
    python3 "$LAB_DIR/assert/pcap_only.py" --pcap "$PCAP" --allow udp:198.51.100.10:51820
check_fails "pcap_only FAILS when a --require rule matched nothing" \
    python3 "$LAB_DIR/assert/pcap_only.py" --pcap "$PCAP" --allow tcp:198.51.100.30:80 --allow udp:198.51.100.53:53 --allow 'udp:127.0.0.11:*' --require udp:198.51.100.10:51820
rm -f "$STATE/pcap/selftest-eth0.pcap"
"$LAB" capture start selftest-eth0 eth0 >/dev/null 2>&1
cli curl -sS --max-time 8 http://echo.lab.test/ip >/dev/null 2>&1
"$LAB" capture stop selftest-eth0 >/dev/null 2>&1
check_ok "capture on eth0 (Ethernet link type) parses too" \
    python3 "$LAB_DIR/assert/pcap_only.py" --pcap "$STATE/pcap/selftest-eth0.pcap" --require tcp:198.51.100.30:80 --allow udp:198.51.100.53:53

# ------------------------------------------------------------------ 10. tunnel loss
tunnel_curl() { wgc curl -sS --max-time "${1:-6}" --resolve echo.lab.test:80:198.51.100.30 http://echo.lab.test/ip; }
wait_tunnel() { # up to ~75s
    local out
    for _ in $(seq 15); do
        out=$(tunnel_curl 5 2>/dev/null | tr_cr) && [[ $out == 198.51.100.10 ]] && return 0
        sleep 1
    done
    return 1
}
section "tunnel loss simulation"
T_REC0=$(now)
"$LAB" tunnel down >/dev/null
check_fails "tunnel down: wg-client tunnel curl fails" tunnel_curl 6
"$LAB" tunnel up >/dev/null
if wait_tunnel; then pass "tunnel up: wg-client tunnel curl recovers"; else fail "tunnel up: wg-client tunnel curl recovers"; fi

"$LAB" tunnel drop >/dev/null
check_fails "tunnel drop (iptables DROP udp/51820): tunnel curl fails" tunnel_curl 6
"$LAB" tunnel undrop >/dev/null
if wait_tunnel; then pass "tunnel undrop: wg-client tunnel curl recovers"; else fail "tunnel undrop: wg-client tunnel curl recovers"; fi
check_eq "direct path unaffected by tunnel loss (php-cli)" 198.51.100.40 cli curl -sS --max-time 8 http://echo.lab.test/ip

# ------------------------------------------------------------------ summary
printf '\n== summary: %d passed, %d failed\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then printf 'failed:\n'; printf '  - %s\n' "${FAILED[@]}"; exit 1; fi
echo "SELFTEST OK"
