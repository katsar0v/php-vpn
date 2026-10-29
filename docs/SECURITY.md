# Security notes

## What php-vpn guarantees

* **Fail closed.** A request made with `VPN::request()` either goes through the
  WireGuard tunnel or fails with a `VPN\Exception`. Nothing is retried over the
  host's normal connection. The only network I/O of the extension is the UDP
  socket to the WireGuard endpoint (and, for an endpoint given as a host name,
  one lookup of that name through the host resolver).
* **No DNS leaks for destinations.** Destination names are resolved by the
  profile's `DNS =` servers through the tunnel. A profile without `DNS =`
  cannot resolve names at all (`VPN\DnsException`); it never falls back to the
  host resolver.
* **No system changes.** No routes, interfaces, firewall rules or capabilities.
  Other PHP code (curl, streams, other workers and sites) is unaffected.
* **Cryptokey routing.** Packets from the peer are accepted only from source
  addresses inside its `AllowedIPs`; destinations outside `AllowedIPs` are
  refused (`VPN\PolicyException`).

These properties are tested in the Docker lab with packet captures and DNS
query logs (`tests/e2e/run.sh`).

## Private keys

* A profile contains a private key. With `php_vpn.enforce_key_permissions=1`
  (default) files readable or writable by "other" users are refused. Typical:
  `chown root:www-data profile.conf && chmod 0640 profile.conf`, or owned by
  the PHP-FPM pool user with `0600`.
* `php_vpn.allowed_config_dir` restricts which directories profiles may be
  loaded from (recommended on shared servers); `open_basedir` applies too.
* Keys are wiped from memory when profiles are freed. They never appear in
  exception messages, `var_dump()`, `print_r()`, `info()` or logs.
  `VPN::wireguardFromString()` marks its argument `#[\SensitiveParameter]`
  (stack traces on PHP 8.2+ show it redacted). Production servers should run
  with `zend.exception_ignore_args=On` anyway.
* VPN objects cannot be serialized or cloned.

## Untrusted URLs (SSRF)

If request URLs come from users, the tunnel becomes a proxy into whatever the
VPN can reach. Defaults that limit this:

* only `http` and `https`;
* private, loopback, link-local, CGNAT, multicast and reserved destinations are
  refused (`allow_private` / `php_vpn.allow_private_destinations` to permit),
  checked again after DNS resolution and on every redirect hop;
* HTTPS → HTTP redirects are refused (`allow_https_downgrade`);
* `Authorization`, `Cookie` and `Proxy-Authorization` are dropped on
  cross-origin redirects;
* response size (`max_response_size`, also after decompression), redirects and
  time are capped.

Still validate URLs against an allow-list in your application when they come
from users; the VPN provider's exit IP is shared with other customers and may
itself be blocked or rate-limited.

## TLS

Certificates are verified by default against the bundled Mozilla root store
(webpki-roots, updated with each release) or the PEM file in `ca_file` /
`php_vpn.ca_file`. `verify_tls => false` disables verification for that
request only; do not use it for anything that matters.

## Concurrency and lock files

A WireGuard key holds one session at the server. Processes using the same key
serialise on a lock file in `php_vpn.lock_dir` (default: the system temporary
directory), named after a hash of the key pair (not the key itself). All
processes using a profile must share the lock directory and be able to write
it. On shared hosting, give each site its own `lock_dir` and keys. Lock files
are opened with `O_NOFOLLOW` and released by the kernel when a process dies.

## Known limitations

* The endpoint host name is resolved by the host resolver (it reveals which VPN
  server is used, not what is requested). Use an IP address in `Endpoint =` to
  avoid it.
* The provider sees the traffic leaving its network as it would for any VPN;
  use HTTPS.
* `.ovpn` (OpenVPN) profiles are not supported (see `docs/OPENVPN.md`).
