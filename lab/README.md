# php-vpn Docker test lab

Self-contained lab to test `php-vpn.so` (userspace WireGuard egress for PHP) against a fake
internet. Everything runs in the compose project `php-vpn-lab`; **no host ports are published**
and both networks are `internal` (no real egress). The PHP containers get **no** `NET_ADMIN`, no
TUN device and no route to the WireGuard server other than the ordinary on-link UDP path.

```
lab/lab.sh up                 # build + start + wait healthy
lab/lab.sh selftest           # validate the lab itself
lab/lab.sh down               # stop (keeps lab/state)
```

## Addresses

| network | subnet | hosts |
|---|---|---|
| `internet` (internal) | 198.51.100.0/24 | wg-server .10, echo .30, hostdns .53, php-cli .40, php-fpm .41, nginx .42, php-apache .43, wg-client .60 |
| `vpnside` (internal) | 203.0.113.0/24 | wg-server .10, secret .20 |
| WireGuard tunnel | 10.13.13.0/24 | server 10.13.13.1 (UDP 51820), clients 10.13.13.2+ |

Documentation ranges on purpose: the extension's default "deny private destinations" policy does not block them.

## Services

| service | what it is for |
|---|---|
| `wg-server` | WireGuard server (kernel module; wireguard-go fallback), MASQUERADE out to both networks, dnsmasq **only on 10.13.13.1** (tunnel DNS: `secret.vpn.test`->203.0.113.20, `echo.lab.test`->198.51.100.30, no upstream). Generates keys + client confs on first start. |
| `echo` | Fake internet, 198.51.100.30: HTTP 80, HTTPS 443 (`echo.lab.test`, lab CA), 8443 (`wrong.lab.test` cert), 9443 (self-signed `echo.lab.test`). Routes below. |
| `secret` | Same server on `vpnside` only (203.0.113.20): HTTP 80, HTTPS 443 (`secret.vpn.test`, lab CA). Reachable only through the tunnel. |
| `hostdns` | dnsmasq 198.51.100.53, what PHP containers resolve through (Docker's embedded resolver forwards to it, from the container's own IP). Knows `echo.lab.test`, `wg.lab.test`, `a.lab.test`/`b.lab.test`; **never** `secret.vpn.test` (NXDOMAIN). |
| `php-cli` | `php:${PHP_VERSION}-cli` + pcntl, idle (`sleep infinity`); run things with `lab.sh php` / `lab.sh exec`. |
| `php-fpm` + `nginx` | FPM with pools `a` (user `poola`, :9001) and `b` (user `poolb`, :9002), static, 4 children, `clear_env=no`. nginx vhosts `a.lab.test` / `b.lab.test` -> pool a / b, docroot `/src/lab/www`. |
| `php-apache` | `php:${PHP_VERSION}-apache`: mod_php, prefork MPM, docroot `/src/lab/www`. |
| `sniff` | tcpdump sharing php-cli's network namespace; idle until `lab.sh capture start`. |
| `wg-client` | Profile `selftest` only: plain `wg setconf`/`ip` client (client1.conf) used to validate the server side. |

`PHP_VERSION` (default `8.4`, tested `8.0` and `8.4`; any `8.0`..`8.5` that has official `-cli/-fpm/-apache` images works) selects the
image tags, so `PHP_VERSION=8.0 lab/lab.sh up` switches the PHP containers.

## How the PHP containers pick up the extension

The repo root is mounted **read-only at `/src`**, and `dist/php${PHP_VERSION}/` at **`/opt/php-vpn/`** (created if missing).
On container start the entrypoint checks for `/opt/php-vpn/php-vpn.so`:

* present: writes `conf.d/zz-php-vpn.ini` with `extension=/opt/php-vpn/php-vpn.so` and `php_vpn.allow_private_destinations=0`
  (extra INI lines for a run: `PHP_VPN_EXTRA_INI=$'php_vpn.max_tunnels=2\nphp_vpn.lock_dir=/tmp' lab/lab.sh restart`);
* absent: starts **without** the extension and prints a notice (`lab.sh logs php-cli`).

After (re)building the `.so`: `lab/lab.sh restart` (recreates php-cli, sniff, php-fpm, nginx, php-apache; keeps state).

The entrypoint also copies the generated client confs to `/etc/php-vpn/` and the lab CA to `/etc/php-vpn/lab-ca.pem`
(also installed into the system trust store):

| container | permissions |
|---|---|
| php-cli, php-apache | all `client*.conf`: `0640 root:www-data` |
| php-fpm | `client2.conf` `0600 poola:poola`, `client3.conf` `0600 poolb:poolb`, the rest `0640 root:www-data` (unreadable to both pools) |

`lab/www/` (docroot of nginx and Apache, `/src/lab/www` in the containers): `direct.php` prints the `echo.lab.test/ip` seen
for a direct request; `info.php` prints `vpn loaded|missing`, `php=`, `sapi=`, `euid=`, `user=` (the real process user),
`get_current_user=` (script *owner*, not the process user), `pid=`. Put new test scripts there.

## `lab/lab.sh`

```
up | down | reset | status | logs [svc] | restart [svc...] | selftest
capture start <name> [iface] | capture stop <name>
tunnel down|up | tunnel drop|undrop
exec <svc> <cmd...> | php <args...> | compose <docker compose args...>
```

* `reset` = `down` + delete `lab/state` (new keys, CA, logs, pcaps). Without it everything in `lab/state` persists across `up`/`down`.
* `capture start t1` captures in php-cli's netns (default interface `any` = Linux cooked, so **loopback is included**, e.g. a
  stray lookup via Docker's resolver on `127.0.0.11`; use `capture start t1 eth0` for the wire only) into `lab/state/pcap/t1.pcap`.
  `capture stop` interrupts tcpdump, waits for it to flush and exit.
* `tunnel down|up` = `ip link set wg0 down|up` on wg-server (UDP socket closes: clients see ICMP port unreachable).
  `tunnel drop|undrop` = iptables DROP of UDP 51820 in both directions (silent loss). After `up`/`undrop` an *established*
  client re-handshakes by itself within ~15 s (WireGuard's retransmit timer).
* `exec` / `php` run as root; `LAB_EXEC_USER=www-data lab/lab.sh php ...` runs as another user.
* Honours `PHP_VERSION`; `LAB_WG_GO=1` forces wireguard-go (+ `/dev/net/tun`) instead of the kernel module (use it for `up` and every
  later command that recreates wg-server); `LAB_PULL=1 lab.sh up` refreshes the base images (`build --pull`; otherwise a locally cached
  `php:X-cli` may be an older patch release than the freshly pulled `-fpm`/`-apache`); `LAB_WAIT_TIMEOUT` (seconds, default 300) bounds `up`.

## `lab/state/` (gitignored, generated)

```
ca/       lab-ca.pem lab-ca.key, echo.lab.test.* wrong.lab.test.* secret.vpn.test.* echo.lab.test.selfsigned.* (.pem/.key)
wg/       server + client key pairs (persist across restarts; regenerated only if missing)
clients/  client1..4.conf, client-badkey.conf, client-nodns.conf
logs/     echo.log secret.log hostdns.log tunneldns.log
pcap/     <name>.pcap, <name>.log
```

Client confs (wg-quick format): `client1..4` = `10.13.13.2..5/32`, `DNS = 10.13.13.1`, `MTU = 1420`, `AllowedIPs = 0.0.0.0/0`,
`Endpoint = 198.51.100.10:51820`, `PersistentKeepalive = 25`; **client4** uses `Endpoint = wg.lab.test:51820`;
**client-badkey** = client1 with a wrong server `PublicKey`; **client-nodns** = valid peer (10.13.13.6) without a `DNS` line.

Logs: `echo.log`/`secret.log` one line per request: `2026-10-29T15:50:12.345Z <remote-ip> <METHOD> <Host header> <request target>`
(docker healthchecks on 127.0.0.1 are not logged; TLS handshake failures go to `docker logs` only).
`hostdns.log`/`tunneldns.log` are dnsmasq `log-queries=extra` lines prefixed with an ISO-8601 UTC ms timestamp.

## echo / secret routes (all methods; plain text unless noted)

`/` name · `/ip` client IP (no trailing newline) · `/echo` JSON `{method,path,query,query_params,raw_target,headers:[[name,value],..],body,body_length,remote,remote_port,scheme,server_port,server,http_version}` ·
`/redirect?code=302&to=<urlencoded>` · `/redirect-chain?n=N[&code=302][&rel=1]` (N hops then `/ip`) · `/status/<code>[?to=]` ·
`/slow?ms=N` · `/drip?bytes=N&ms=M[&chunk=K]` · `/stall` · `/bytes?n=N` (bytes `i%251`, `X-Content-SHA256`) ·
`/chunked?chunks=N&size=M` (chunk i = letter(i)*M) · `/gzip` · `/gzip-bomb?mb=N` · `/headers-multi` (2x Set-Cookie, 2x X-Multi) · `/healthz`.

## Assertions (`lab/assert/`, python3 stdlib, run on the host or in a container)

```
python3 lab/assert/pcap_only.py --pcap lab/state/pcap/t1.pcap --allow udp:198.51.100.10:51820 [--allow udp:198.51.100.53:53] \
        [--require RULE] [--ip IP] [--json]
python3 lab/assert/dns_log.py --log lab/state/logs/hostdns.log --since <unix-ts|ISO> --forbid secret.vpn.test [--forbid NAME] \
        [--until T] [--client IP] [--expect NAME] [--show]
```

`pcap_only.py` parses classic pcap (Ethernet, Linux cooked v1/v2, raw IP; IPv4/IPv6, TCP/UDP/ICMP) and fails (exit 1) listing every
packet not covered by an allow rule (`proto:host[:port]`, host may be a CIDR or `*`, IPv6 as `[addr]`; a rule covers traffic
to *or* from the endpoint). ARP and IPv6 ND/MLD are ignored. An empty capture passes vacuously (prints a warning): add `--require`.
A typical VPN-only check allows just `udp:198.51.100.10:51820`; allow `udp:127.0.0.11:*` + `udp:198.51.100.53:53` for runs that
also do direct lookups, and `icmp:198.51.100.10` if the run includes `tunnel down` (wg-server then answers with ICMP port unreachable).

`dns_log.py` fails when a forbidden name was queried in `[since, until]` (optionally only from `--client` addresses) or an
`--expect`ed one was not. It waits 0.3 s first (`--settle`) because dnsmasq's log reaches the file asynchronously. A leading
`.`/`*.` in a name matches the domain and everything under it. `lab.sh selftest` shows the intended usage.

## Notes

* `php-cli` etc. use `dns: [198.51.100.53]`: the container's resolver is Docker's embedded `127.0.0.11`, which forwards to `hostdns`
  from the container's own address, so `hostdns.log` shows exactly what a PHP process asked the host resolver.
* `wg-client` routes `198.51.100.30` (echo, on-link) through `wg0` explicitly; the extension's userspace stack needs no such routes.
* The first `up` pulls the official `php` images and builds a few small images (needs Docker Hub / Debian mirrors). PHP 8.0 images are
  Debian 11, so the Dockerfile switches apt to `archive.debian.org` for them.
