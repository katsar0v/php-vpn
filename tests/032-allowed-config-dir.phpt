--TEST--
php-vpn: php_vpn.allowed_config_dir restricts profile paths by their resolved real path
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.allowed_config_dir={TMP}/php-vpn-phpt-032/allowed
--FILE--
<?php
$base = sys_get_temp_dir() . '/php-vpn-phpt-032';
mkdir($base, 0700);
foreach (['allowed', 'allowed/sub', 'allowed-evil', 'outside'] as $d) {
    mkdir("$base/$d", 0700);
}

function conf(): string {
    return "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
}
foreach (['allowed/ok.conf', 'allowed/sub/nested.conf', 'allowed-evil/evil.conf', 'outside/out.conf'] as $file) {
    file_put_contents("$base/$file", conf());
    chmod("$base/$file", 0600);
}
symlink("$base/outside/out.conf", "$base/allowed/escape.conf");   // inside -> outside
symlink("$base/allowed/ok.conf", "$base/outside/inward.conf");    // outside -> inside
symlink("$base/outside", "$base/allowed/escape-dir");             // directory symlink out

function attempt(string $label, callable $fn): void {
    global $base;
    try {
        $fn();
        $text = 'loaded';
    } catch (VPN\ConfigException $e) {
        $text = str_replace($base, '{BASE}', $e->getMessage());
    }
    printf("%-30s %s\n", $label, $text);
}

var_dump(ini_get('php_vpn.allowed_config_dir') === "$base/allowed");

echo "-- wireguard()\n";
attempt('inside', fn() => VPN::wireguard("$base/allowed/ok.conf"));
attempt('inside, nested', fn() => VPN::wireguard("$base/allowed/sub/nested.conf"));
attempt('inside, via ..', fn() => VPN::wireguard("$base/allowed/sub/../ok.conf"));
attempt('outside', fn() => VPN::wireguard("$base/outside/out.conf"));
attempt('outside, via ..', fn() => VPN::wireguard("$base/allowed/../outside/out.conf"));
attempt('same prefix, other dir', fn() => VPN::wireguard("$base/allowed-evil/evil.conf"));
attempt('symlink inside -> outside', fn() => VPN::wireguard("$base/allowed/escape.conf"));
attempt('symlink outside -> inside', fn() => VPN::wireguard("$base/outside/inward.conf"));
attempt('dir symlink inside -> out', fn() => VPN::wireguard("$base/allowed/escape-dir/out.conf"));
chdir("$base/allowed");
attempt('relative, inside', fn() => VPN::wireguard('ok.conf'));
attempt('relative, outside', fn() => VPN::wireguard('../outside/out.conf'));

echo "-- pool() of paths\n";
attempt('pool, all inside', fn() => VPN::pool(["$base/allowed/ok.conf", "$base/allowed/sub/nested.conf"]));
attempt('pool, one outside', fn() => VPN::pool(["$base/allowed/ok.conf", "$base/outside/out.conf"]));

echo "-- profiles from strings are not paths\n";
attempt('wireguardFromString', fn() => VPN::wireguardFromString(file_get_contents("$base/outside/out.conf")));
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
rm(sys_get_temp_dir() . '/php-vpn-phpt-032');
?>
--EXPECT--
bool(true)
-- wireguard()
inside                         loaded
inside, nested                 loaded
inside, via ..                 loaded
outside                        WireGuard profile `{BASE}/outside/out.conf` is outside php_vpn.allowed_config_dir
outside, via ..                WireGuard profile `{BASE}/allowed/../outside/out.conf` is outside php_vpn.allowed_config_dir
same prefix, other dir         WireGuard profile `{BASE}/allowed-evil/evil.conf` is outside php_vpn.allowed_config_dir
symlink inside -> outside      WireGuard profile `{BASE}/allowed/escape.conf` is outside php_vpn.allowed_config_dir
symlink outside -> inside      loaded
dir symlink inside -> out      WireGuard profile `{BASE}/allowed/escape-dir/out.conf` is outside php_vpn.allowed_config_dir
relative, inside               loaded
relative, outside              WireGuard profile `../outside/out.conf` is outside php_vpn.allowed_config_dir
-- pool() of paths
pool, all inside               loaded
pool, one outside              WireGuard profile `{BASE}/outside/out.conf` is outside php_vpn.allowed_config_dir
-- profiles from strings are not paths
wireguardFromString            loaded
