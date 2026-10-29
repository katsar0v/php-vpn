# Installing php-vpn

## 1. Pick the right binary

A PHP extension must match the PHP **minor version** (8.0, 8.1, ... — any
patch release of that minor works), **thread safety** (php-vpn ships NTS builds,
which is what PHP-FPM, Apache prefork and the official Docker images use) and
the **C library** (glibc or musl/Alpine). Check:

```sh
php -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION, PHP_ZTS ? " ZTS" : " NTS", "\n";'
ldd --version | head -1          # glibc version (musl prints "musl libc")
uname -m
```

Release files are named
`php-vpn-<version>-php<8.x>-nts-<arch>-<glibc|musl>.so`; see
[COMPATIBILITY.md](COMPATIBILITY.md) for the tested matrix and the minimum
glibc. Verify the download against `SHA256SUMS`.

## 2. Install

```sh
dir="$(php -r 'echo ini_get("extension_dir");')"
install -m 0644 php-vpn-0.1.0-php8.4-nts-x86_64-glibc.so "$dir/php-vpn.so"

# Debian/Ubuntu (ondrej/sury packages):  /etc/php/8.4/mods-available/php-vpn.ini + phpenmod php-vpn
# Official Docker images:               /usr/local/etc/php/conf.d/50-php-vpn.ini
echo 'extension=php-vpn.so' > /usr/local/etc/php/conf.d/50-php-vpn.ini

php -m | grep -x vpn     # CLI check
systemctl restart php8.4-fpm   # or: apachectl graceful
```

Nothing else is installed: no WireGuard tools, no daemon, no kernel module,
no extra packages. The extension needs only libc and libgcc_s, which every
Linux system with PHP has.

## 3. Add a WireGuard profile

Download a WireGuard `.conf` from your provider (Surfshark: *VPN → Manual setup
→ Desktop or mobile → WireGuard*, generate a key pair, choose a location).
Store it so only PHP can read it:

```sh
install -d -m 0750 -o root -g www-data /etc/php-vpn
install -m 0640 -o root -g www-data surfshark-de.conf /etc/php-vpn/surfshark-de.conf
```

Recommended `php.ini` for servers:

```ini
php_vpn.allowed_config_dir = /etc/php-vpn
php_vpn.lock_dir = /var/lib/php-vpn        ; writable by every PHP user of these profiles
zend.exception_ignore_args = On
```

Each key pair can serve one request at a time server-wide; create several key
pairs and use `VPN::pool()` if you need parallel requests. Do not use the same
key in another VPN client (or on another server) at the same time.

## 4. Test

```php
$vpn = VPN::wireguard('/etc/php-vpn/surfshark-de.conf');
var_dump($vpn->request('GET', 'https://api.ipify.org')->body(), file_get_contents('https://api.ipify.org'));
```

The two IPs must differ. `tools/live-check.php` does the same with more detail.

## Building from source

Requirements: PHP development files (`phpize`, `php-config`), a C compiler,
`make`, and Rust 1.85+ (`rustup`). From the source tree:

```sh
phpize
./configure --enable-vpn          # runs `cargo build --release` for the core
make
make test
sudo make install
```

`--with-vpn-core=/path/to/libvpn_ffi.a` links a prebuilt core instead of
running cargo. The Docker-based helper `./dev build <php-version>` does all of
this in containers.
