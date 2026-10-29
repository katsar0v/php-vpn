# Compatibility

Release files: `dist/release/php-vpn-<version>-php<8.x>-nts-x86_64-<glibc|musl>.so`
(built by `./dev dist`, checked by `./dev check-so`, `SHA256SUMS` alongside).

## Matrix (0.1.0, 29 Oct 2026)

| PHP | glibc build | musl build | `.phpt` (38) | Lab end-to-end (88 checks: CLI, FPM, Apache) |
|---|---|---|---|---|
| 8.0 | yes | yes | pass (1 skip: `#[\SensitiveParameter]` is 8.2+) | pass |
| 8.1 | yes | yes | pass (1 skip, as above) | - |
| 8.2 | yes | yes | pass | - |
| 8.3 | yes | yes | pass | - |
| 8.4 | yes | yes | pass | pass |
| 8.5 | yes | yes | pass | pass |
| 8.6 RC | yes | yes | pass on Alpine (NTS) | - |

* **Thread safety:** NTS only (PHP-FPM, Apache prefork + mod_php, CLI, the
  official Docker images). The `php:8.6-rc-cli` Debian image is ZTS and cannot
  load NTS builds.
* **Architecture:** x86_64. aarch64 builds are scripted (`./dev dist`, CI legs on
  `ubuntu-24.04-arm`) but not produced or tested yet.
* **PHP minor version must match.** Any patch release of a minor works (same
  `ZEND_MODULE_API_NO`), e.g. the 8.4 build loads on 8.4.5 and 8.4.27.

## C library

| Build | Requires | Works on (examples) |
|---|---|---|
| glibc | glibc >= 2.28 (`objdump -T`: newest symbol `GLIBC_2.28`) | RHEL/Alma/Rocky 8+, Debian 10+, Ubuntu 20.04+, Plesk on Debian 11 (verified with Plesk PHP 8.4) |
| musl | musl libc (`libc.musl-x86_64.so.1`), libgcc linked statically | Alpine (`php:<ver>-cli-alpine`, `-fpm-alpine`) |

Runtime dependencies besides libc: `libgcc_s` (glibc builds; present wherever a
C++ or Rust program runs, part of every PHP base system). No OpenSSL, no
WireGuard tools, no kernel module.

## Verified environments

| Environment | SAPI | Result |
|---|---|---|
| Docker lab, `php:8.0/8.4/8.5-{cli,fpm,apache}` | CLI, FPM (2 pools, different users), Apache prefork | 88/88 each |
| WordPress 7.1 container (`wordpress:*-php8.4-apache`, Debian 13) | CLI (WP-CLI), Apache mod_php prefork | real Surfshark WireGuard: exit IP differs from direct, a real site fetched through the tunnel by a WordPress plugin |
| Plesk Obsidian on Debian 11, Plesk PHP 8.4 | CLI | release build loads; fail-closed tunnel error as expected |
| valgrind (`USE_ZEND_ALLOC=0`, `pcre.jit=0`), PHP 8.4 | CLI | `.phpt` suite: 0 errors, 0 leaks |

## Building for other targets

`./dev dist [glibc|musl|all] [VER...]` builds PHP from php.net sources (checksum
verified) on AlmaLinux 8 for the glibc baseline and uses the official Alpine
images for musl. ZTS or other architectures need the same steps with a ZTS PHP
build or a native/QEMU builder.
