# Changelog

## 0.1.0 (unreleased)

First version (MVP):

* `VPN::wireguard()`, `VPN::wireguardFromString()`, `VPN::pool()`,
  `$vpn->request()`, `VPN\Response`, `VPN\*Exception`.
* Userspace WireGuard (boringtun) + smoltcp TCP/IP + DNS through the tunnel,
  rustls TLS (bundled Mozilla roots or `ca_file`), hyper HTTP/1.1, redirects,
  gzip/deflate, size and time limits.
* Fail closed; private destinations, HTTPS→HTTP redirects and cross-origin
  credentials blocked by default.
* Cross-process lock per WireGuard key, session reuse within a process,
  automatic re-keying when the key was used elsewhere.
* PHP 8.0–8.5 and 8.6 RC, NTS; PHP CLI, PHP-FPM, Apache mod_php.
* Release builds for x86_64 glibc (>= 2.28) and musl; see docs/COMPATIBILITY.md.
