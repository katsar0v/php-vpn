# php-vpn

A PHP 8 extension that sends **selected HTTP(S) requests through a WireGuard
VPN** — in userspace, inside the PHP process. No root, no TUN device, no route
changes, no proxy daemon. Everything else your server does keeps using its
normal connection.

Useful when a provider (e.g. Surfshark's manual setup) gives you WireGuard
`.conf` files but no HTTP/SOCKS proxy, and a remote site blocks your server's IP.

```php
$vpn = VPN::wireguard('/etc/php-vpn/surfshark-de.conf');

echo $vpn->request('GET', 'https://api.ipify.org')->body();  // the VPN's exit IP
echo file_get_contents('https://api.ipify.org');             // your server's IP, unchanged
```

* **Fail closed**: a VPN request either goes through the tunnel or throws; it is
  never retried over the normal network.
* **DNS through the tunnel**: names are resolved by the profile's `DNS =`
  servers, never by the host resolver.
* **PHP CLI, PHP-FPM, Apache mod_php**; per-process tunnels created lazily after fork.
* **Standard WireGuard profiles** (`wg-quick` format), any provider.

How it works: boringtun (WireGuard) + smoltcp (TCP/IP + DNS) + rustls (TLS) +
hyper (HTTP/1.1), written in Rust and linked statically into the extension. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

```ini
; php.ini or conf.d/50-php-vpn.ini
extension=php-vpn.so
```

Copy the `php-vpn.so` built for your PHP version (8.0–8.5, 8.6 RC; NTS;
glibc >= 2.28 or musl) into the
extension directory (`php -i | grep extension_dir`) and restart PHP-FPM /
Apache. Details, compatible binaries and building from source:
[docs/INSTALL.md](docs/INSTALL.md).

Put the profile somewhere only PHP can read it:

```sh
install -m 0640 -o root -g www-data surfshark-de.conf /etc/php-vpn/surfshark-de.conf
```

## API

```php
VPN::wireguard(string $path, array $options = []): VPN
VPN::wireguardFromString(#[\SensitiveParameter] string $config, array $options = []): VPN
VPN::pool(array $profiles /* VPN objects or paths */, array $options = []): VPN

$vpn->request(string $method, string $url, array $options = []): VPN\Response
$vpn->info(): array     // endpoint, addresses, dns, allowed_ips, mtu, public keys, session_age
                        // (a list of those for a pool of two or more profiles)
$vpn->close(): void     // close this process's tunnel(s) for the profile

$response->status(): int
$response->headers(): array            // ['content-type' => ['text/html'], ...]
$response->header(string $name): ?string   // values joined with ", "
$response->body(): string
$response->effectiveUrl(): string       // after redirects
$response->redirectCount(): int
$response->remoteAddress(): string      // server IP (as seen inside the tunnel)
```

Options given to `wireguard()` / `pool()` are defaults for every request of
that object; options given to `request()` override them.

| Option | Default | |
|---|---|---|
| `headers` | `[]` | `['Name' => 'value']`, `['Name' => ['v1', 'v2']]` or `['Name: value']`. Request headers replace default headers of the same name. |
| `body` | `''` | Request body (string). Use `http_build_query()` / `json_encode()` and set `Content-Type`. |
| `timeout` | `php_vpn.default_timeout` (30) | Seconds for the whole request, including redirects. |
| `connect_timeout` | `php_vpn.connect_timeout` (10) | Seconds for lock wait, handshake, DNS, TCP and TLS of the first hop. |
| `follow_redirects` | `true` | `false`, `true` (`php_vpn.max_redirects`) or a number (0–50). Exceeding it throws `LimitException`. |
| `verify_tls` | `true` | Verify certificates. |
| `ca_file` | `php_vpn.ca_file` | PEM bundle to trust instead of the bundled Mozilla roots. |
| `max_response_size` | `php_vpn.max_response_size` (16M) | Bytes, applied before and after decompression. |
| `decode_content` | `true` | Send `Accept-Encoding: gzip, deflate` and decode. |
| `allow_private` | `php_vpn.allow_private_destinations` (off) | Allow private/loopback/link-local destinations. |
| `allow_https_downgrade` | `false` | Follow HTTPS → HTTP redirects. |

Unknown options and wrongly typed values throw `VPN\ConfigException` (e.g.
`'verify_tls' => 'false'` is rejected, not treated as true).

### Exceptions

All extend `VPN\Exception` (a `RuntimeException`); `getCode()` is stable.

| Class | Code | When |
|---|---|---|
| `VPN\Exception` | 1 | internal error |
| `VPN\ConfigException` | 2 | profile or option invalid, file not allowed |
| `VPN\TunnelException` | 3 | handshake failed, endpoint unreachable |
| `VPN\DnsException` | 4 | name not resolvable through the tunnel |
| `VPN\ConnectException` | 5 | TCP connection through the tunnel failed |
| `VPN\TlsException` | 6 | TLS handshake / certificate verification failed |
| `VPN\TimeoutException` | 7 | `timeout` exceeded |
| `VPN\ProtocolException` | 8 | invalid HTTP from the server |
| `VPN\PolicyException` | 9 | scheme, private address, `AllowedIPs`, downgrade |
| `VPN\LimitException` | 10 | response size or redirect limit |
| `VPN\LockTimeoutException` | 11 | the key stayed busy in other processes for `connect_timeout` |

### Several requests at once: pools

A WireGuard key can hold only one session at the server, so requests on one
profile are serialised across all PHP processes of the server (a lock file per
key). For parallel requests, create several key pairs at your provider:

```php
$vpn = VPN::pool(['/etc/php-vpn/de-1.conf', '/etc/php-vpn/de-2.conf', '/etc/php-vpn/de-3.conf']);
```

Each request takes a free member (rotating). Do not use the same key on two
machines or in a separate VPN client at the same time.

## php.ini

| Setting | Default | Changeable | |
|---|---|---|---|
| `php_vpn.default_timeout` | `30` | all | seconds |
| `php_vpn.connect_timeout` | `10` | all | seconds |
| `php_vpn.max_response_size` | `16M` | all | |
| `php_vpn.max_redirects` | `5` | all | |
| `php_vpn.allow_private_destinations` | `0` | all | |
| `php_vpn.ca_file` | (bundled roots) | system/perdir | PEM file |
| `php_vpn.lock_dir` | system temp dir | system | shared by all processes using the same keys |
| `php_vpn.session_ttl` | `120` | system | seconds before a fresh handshake |
| `php_vpn.max_tunnels` | `4` | system | tunnels kept per process |
| `php_vpn.allowed_config_dir` | (any) | system | `:`-separated directories profiles may be loaded from |
| `php_vpn.enforce_key_permissions` | `1` | system | refuse profiles accessible by "other" users |

## Security

Read [docs/SECURITY.md](docs/SECURITY.md) before passing user-supplied URLs to
`request()`. In short: private destinations, HTTPS→HTTP redirects and
cross-origin credentials are blocked by default, sizes and time are capped,
keys never appear in errors or dumps, and the endpoint host name (not the
destination) is the only lookup made outside the tunnel.

## Development

Everything builds and runs in Docker:

```sh
./dev build 8.4          # Rust core + extension for PHP 8.4 -> dist/php8.4/php-vpn.so
./dev test 8.4           # .phpt suite (offline)
./dev cargo-test         # Rust unit tests
./dev lab up             # WireGuard test lab (fake internet, DNS logging, packet capture)
./dev e2e 8.4 all        # end-to-end: CLI, PHP-FPM (2 pools), Apache prefork
./dev poc --conf /etc/php-vpn/client1.conf http://echo.lab.test/ip   # Rust proof of concept in the lab
./dev dist && ./dev check-so dist/release/*.so   # release builds (glibc 2.28 baseline + musl) and their checks
./dev lint && ./dev deny                          # rustfmt/clippy, licenses and advisories
tools/live.sh CONTAINER profile.conf [URL ...]   # real-provider check inside an existing PHP container
```

The lab ([lab/README.md](lab/README.md)) runs a WireGuard server, a fake
internet, a VPN-only host, two DNS servers with query logs and tcpdump, and
checks that VPN requests produce nothing but WireGuard UDP on the wire.

Research notes and component choices: [docs/RESEARCH.md](docs/RESEARCH.md).

## Limitations

* WireGuard only; OpenVPN is evaluated in [docs/OPENVPN.md](docs/OPENVPN.md).
* HTTP/1.1 (no HTTP/2), one connection per request, no streaming of bodies.
* NTS builds (ZTS untested). Linux only.
* VPN exit IPs are shared and may be blocked too.

## License

MIT, see [LICENSE](LICENSE). Bundled Rust dependencies are under permissive
licenses (MIT, Apache-2.0, BSD, ISC, 0BSD; Mozilla root certificates under
CDLA-Permissive-2.0).
