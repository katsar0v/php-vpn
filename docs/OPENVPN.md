# OpenVPN (`.ovpn`) support — evaluation (M8)

Status: **not implemented**. WireGuard covers the MVP; this note records what
OpenVPN support would take.

## Why it is harder than WireGuard

WireGuard is a small, fixed protocol (one handshake, one AEAD data format), so
boringtun can sit between smoltcp and a UDP socket. OpenVPN is a family of
options negotiated per server:

* a TLS control channel (certificates, `tls-auth` / `tls-crypt` / `tls-crypt-v2`
  wrapping, username/password auth, server-pushed options),
* data channel ciphers (AES-GCM, ChaCha20-Poly1305, legacy CBC + HMAC),
  compression framing (discouraged), fragment/MSS options,
* UDP **and** TCP transports, proxies, `remote` lists with fallbacks,
* inline or referenced keys and certificates in the `.ovpn` file.

A userspace client must implement (or embed) all of that and expose IP packets
to smoltcp exactly like the WireGuard tunnel does today.

## Candidates

| Option | License | Fit |
|---|---|---|
| [OpenVPN 3 Core](https://github.com/OpenVPN/openvpn3) (C++ client library) | AGPL-3.0 (Debian, Alpine and vcpkg package metadata), CLA-based relicensing by OpenVPN Inc. | Technically the best fit: `TunBuilderBase` lets the embedding app supply the "tun" (the model used on Android/iOS), so packets could be fed to smoltcp. Brings a C++ toolchain, asio and an SSL library (OpenSSL or mbedTLS) into the extension — OpenSSL symbol clashes with PHP's own OpenSSL must be avoided (hidden symbols / mbedTLS). **AGPL would apply to the extension**, which conflicts with an MIT project and with closed-source deployments; a commercial license would be needed otherwise. |
| OpenVPN 2.x (`openvpn` binary) | GPL-2.0 | A process with a TUN device: needs root/CAP_NET_ADMIN — violates the core requirements. |
| Pure-Rust OpenVPN client | — | No maintained, audited implementation found. Writing one is a substantial security-sensitive project. |
| Ask the provider for WireGuard | — | Most commercial VPNs (Surfshark included) offer WireGuard profiles; recommended path. |

## Recommendation

Do not add OpenVPN to `php-vpn.so`. If it is required later, build it as a
separate, AGPL-licensed optional module (`php-vpn-openvpn.so`) on OpenVPN 3
Core with mbedTLS and a `TunBuilderBase` bridge to the existing smoltcp/HTTP
code, keeping the WireGuard extension MIT. Estimated effort: several weeks,
plus a security review of the integration.
