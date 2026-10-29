# Architecture

```
PHP code ── VPN::wireguard($conf)->request('GET', $url)
   │
   │  php_vpn.c (Zend API): classes, option parsing, INI, path checks,
   │  exception mapping. Builds a vpn_request_spec and calls the core.
   ▼
vpn-ffi (C ABI, include/php_vpn_core.h): catch_unwind at every entry,
   Rust memory freed only by Rust (*_free functions)
   ▼
vpn-core
   client.rs  per-process registry of tunnels, lock + session decisions
   lock.rs    flock() per WireGuard key + record of the last handshake
   tunnel.rs  boringtun session, one UDP socket, smoltcp interface, DNS, TCP
   http.rs    hyper HTTP/1.1, redirects, limits, gzip/deflate
   tls.rs     rustls configurations
   policy.rs  scheme / private-address / AllowedIPs rules
   config.rs  wg-quick profile parser
```

## One request

1. **Validate** (no I/O): method, URL, headers, options. Private or reserved IP
   literals are refused here unless `allow_private` is set.
2. **Lock** the profile's key: `flock(LOCK_EX|LOCK_NB)` on
   `{php_vpn.lock_dir}/php-vpn-<hash of key pair>.lock`, polled until
   `connect_timeout`. For a pool, members are tried in rotation.
3. **Tunnel** for the profile from this process's registry (created on first
   use: resolves the endpoint, opens one connected UDP socket, builds the
   smoltcp interface with the profile's addresses and an MTU from the profile).
4. **Session decision**: reuse the WireGuard session only if it is younger
   than `php_vpn.session_ttl` *and* the lock file says this tunnel instance did
   the last handshake. Otherwise drop it, wait until 30 ms have passed since
   the last handshake by anyone (server flood protection), and handshake again.
5. **Run** inside a current-thread tokio runtime: the request future and the
   tunnel driver are polled together with `select!`. The driver moves packets
   between UDP ⇄ boringtun ⇄ smoltcp and ticks WireGuard timers. A fatal driver
   error ends the request.
6. **Resolve** host names with smoltcp's DNS socket against the profile's
   `DNS =` servers, through the tunnel (60 s cache per tunnel).
7. **Filter** resolved addresses: must be routed by the peer's `AllowedIPs`;
   private/reserved ones are refused unless allowed.
8. **Connect / TLS / HTTP**: smoltcp TCP socket → optional rustls → hyper
   HTTP/1.1. Body collected with `max_response_size`, then decoded.
9. **Redirects** repeat 6–8 per hop with the same rules, dropping credentials
   across origins and refusing HTTPS→HTTP unless allowed.
10. **Cleanup**: all TCP sockets aborted and removed; the WireGuard session and
    the tunnel stay for the next request in this process. The lock is released.

There is no code path that opens a socket other than the tunnel's UDP socket
(plus the host lookup of an endpoint *name*), so failures cannot fall back to
the normal network.

## Process model

* `MINIT` only registers classes and INI entries. No threads, sockets or
  runtime exist in a PHP-FPM / Apache master.
* Per-process state lives in a thread-local, created on first use. Its PID is
  recorded; a process that finds state from another PID (it was forked after
  using a tunnel) leaks that state instead of closing descriptors the parent
  still uses.
* Between requests nothing runs. WireGuard timers are evaluated when the next
  request starts; boringtun drops expired sessions then.
* Each PHP-FPM worker / Apache child has its own tunnel(s), at most
  `php_vpn.max_tunnels` (least recently used are closed).

## Concurrency per key

A WireGuard server keeps one session and one endpoint per peer key, so a key
serves one request at a time across all processes sharing `php_vpn.lock_dir`.
Use `VPN::pool()` with several key pairs for parallelism.

If the same key is also used *outside* the lock (another container, host or a
wireproxy), the server's session can change under a long-lived worker. The
tunnel notices — packets for an unknown session index, or a TCP connect that
stalls for a second on an established session — and forces a new handshake
(at most once per second), inside the tunnel.

## Timeouts

* `connect_timeout` bounds waiting for the lock, the handshake, DNS, TCP
  connect and the TLS handshake of the first hop (later hops get a fresh
  budget).
* `timeout` bounds the whole request including redirects.
* A lost tunnel shows up as `TunnelException` (handshake/ICMP),
  `ConnectException` or `TimeoutException`; there is never a retry outside it.
