--TEST--
php-vpn: wireguard() loads profile files and rejects missing, unreadable-by-design and over-permissive ones
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-030-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
$real = realpath($dir);

$private = base64_encode(random_bytes(32));
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

function write(string $dir, string $name, string $content, int $mode = 0600): string {
    $path = "$dir/$name";
    file_put_contents($path, $content);
    chmod($path, $mode);
    return $path;
}

function attempt(string $label, callable $fn): void {
    global $dir, $real, $private;
    try {
        $result = $fn();
        $text = $result instanceof VPN ? 'loaded, endpoint ' . $result->info()['endpoint'] : var_export($result, true);
    } catch (Throwable $e) {
        $text = get_class($e) . ' (' . $e->getCode() . '): ' . str_replace([$real, $dir], '{DIR}', $e->getMessage());
        if (str_contains($e->getMessage(), $private)) {
            $text .= ' <<< LEAKS KEY';
        }
    }
    printf("%-26s %s\n", $label, $text);
}

echo "-- paths that cannot be loaded\n";
attempt('missing file', fn() => VPN::wireguard("$dir/missing.conf"));
attempt('missing directory', fn() => VPN::wireguard("$dir/nope/missing.conf"));
attempt('empty path', fn() => VPN::wireguard(''));
attempt('directory', fn() => VPN::wireguard($dir));
attempt('NUL byte', fn() => VPN::wireguard("$dir/a\0b.conf"));

echo "-- file modes (php_vpn.enforce_key_permissions=1 by default)\n";
foreach ([0600, 0640, 0660, 0400] as $mode) {
    $path = write($dir, sprintf('mode-%04o.conf', $mode), $conf, $mode);
    attempt(sprintf('mode %04o', $mode), fn() => VPN::wireguard($path));
}
foreach ([0644, 0604, 0602, 0666] as $mode) {
    $path = write($dir, sprintf('mode-%04o.conf', $mode), $conf, $mode);
    attempt(sprintf('mode %04o', $mode), fn() => VPN::wireguard($path));
}

echo "-- symlinks and relative paths\n";
symlink("$dir/mode-0600.conf", "$dir/link.conf");
attempt('symlink', fn() => VPN::wireguard("$dir/link.conf"));
symlink("$dir/mode-0644.conf", "$dir/link-to-open.conf");
attempt('symlink to mode 0644', fn() => VPN::wireguard("$dir/link-to-open.conf"));
chdir($dir);
attempt('relative path', fn() => VPN::wireguard('mode-0600.conf'));
attempt('path with ..', fn() => VPN::wireguard("$dir/../" . basename($dir) . '/mode-0600.conf'));

echo "-- file contents\n";
attempt('empty file', fn() => VPN::wireguard(write($dir, 'empty.conf', '')));
attempt('invalid profile', fn() => VPN::wireguard(write($dir, 'bad.conf', str_replace('Address', 'Adress', $conf))));
attempt('larger than 64 KiB', fn() => VPN::wireguard(write($dir, 'big.conf', $conf . '#' . str_repeat('x', 65536))));
attempt('invalid UTF-8', fn() => VPN::wireguard(write($dir, 'binary.conf', $conf . "# \xFF\xFE\n")));

echo "-- options are validated\n";
attempt('unknown option', fn() => VPN::wireguard("$dir/mode-0600.conf", ['bogus' => true]));
attempt('valid options', fn() => VPN::wireguard("$dir/mode-0600.conf", ['timeout' => 5, 'headers' => ['X-Test' => '1']]));
?>
--CLEAN--
<?php
function rm(string $path): void {
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            rm("$path/$entry");
        }
    }
    @rmdir($path);
}
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-030-*') ?: [] as $path) {
    rm($path);
}
?>
--EXPECT--
-- paths that cannot be loaded
missing file               VPN\ConfigException (2): WireGuard profile `{DIR}/missing.conf` cannot be opened: No such file or directory
missing directory          VPN\ConfigException (2): WireGuard profile `{DIR}/nope/missing.conf` cannot be opened: No such file or directory
empty path                 VPN\ConfigException (2): WireGuard profile path must be a non-empty string without NUL bytes
directory                  VPN\ConfigException (2): WireGuard profile `{DIR}` is not a regular file
NUL byte                   ValueError (0): VPN::wireguard(): Argument #1 ($path) must not contain any null bytes
-- file modes (php_vpn.enforce_key_permissions=1 by default)
mode 0600                  loaded, endpoint 127.0.0.1:9
mode 0640                  loaded, endpoint 127.0.0.1:9
mode 0660                  loaded, endpoint 127.0.0.1:9
mode 0400                  loaded, endpoint 127.0.0.1:9
mode 0644                  VPN\ConfigException (2): WireGuard profile `{DIR}/mode-0644.conf` is accessible by all users (mode 0644); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)
mode 0604                  VPN\ConfigException (2): WireGuard profile `{DIR}/mode-0604.conf` is accessible by all users (mode 0604); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)
mode 0602                  VPN\ConfigException (2): WireGuard profile `{DIR}/mode-0602.conf` is accessible by all users (mode 0602); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)
mode 0666                  VPN\ConfigException (2): WireGuard profile `{DIR}/mode-0666.conf` is accessible by all users (mode 0666); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)
-- symlinks and relative paths
symlink                    loaded, endpoint 127.0.0.1:9
symlink to mode 0644       VPN\ConfigException (2): WireGuard profile `{DIR}/mode-0644.conf` is accessible by all users (mode 0644); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)
relative path              loaded, endpoint 127.0.0.1:9
path with ..               loaded, endpoint 127.0.0.1:9
-- file contents
empty file                 VPN\ConfigException (2): WireGuard profile: missing [Interface] PrivateKey
invalid profile            VPN\ConfigException (2): WireGuard profile, line 3: unsupported [Interface] key `adress`
larger than 64 KiB         VPN\ConfigException (2): WireGuard profile `{DIR}/big.conf` is larger than 65536 bytes
invalid UTF-8              VPN\ConfigException (2): cannot read WireGuard profile `{DIR}/binary.conf`: stream did not contain valid UTF-8
-- options are validated
unknown option             VPN\ConfigException (2): unknown option `bogus`
valid options              loaded, endpoint 127.0.0.1:9
