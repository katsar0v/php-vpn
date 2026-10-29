--TEST--
php-vpn: php_vpn.allowed_config_dir accepts a list separated by ":" and skips entries that do not exist
--SKIPIF--
<?php
if (!extension_loaded('vpn')) die('skip vpn extension not loaded');
if (PATH_SEPARATOR !== ':') die('skip the list separator is ":"');
?>
--INI--
php_vpn.allowed_config_dir={TMP}/php-vpn-phpt-033/missing::{TMP}/php-vpn-phpt-033/a/:{TMP}/php-vpn-phpt-033/b
--FILE--
<?php
$base = sys_get_temp_dir() . '/php-vpn-phpt-033';
mkdir($base, 0700);
foreach (['a', 'b', 'c'] as $d) {
    mkdir("$base/$d", 0700);
    file_put_contents("$base/$d/profile.conf", "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32))
        . "\nAddress = 10.13.13.2/32\n[Peer]\nPublicKey = " . base64_encode(random_bytes(32))
        . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n");
    chmod("$base/$d/profile.conf", 0600);
}

foreach (['a' => 'first entry (trailing slash)', 'b' => 'second entry', 'c' => 'not listed'] as $d => $label) {
    try {
        VPN::wireguard("$base/$d/profile.conf");
        $result = 'loaded';
    } catch (VPN\ConfigException $e) {
        $result = str_replace($base, '{BASE}', $e->getMessage());
    }
    printf("%-30s %s\n", $label, $result);
}

echo "-- pool() mixes entries of the list\n";
var_dump(count(VPN::pool(["$base/a/profile.conf", "$base/b/profile.conf"])->info()));
try {
    VPN::pool(["$base/a/profile.conf", "$base/c/profile.conf"]);
} catch (VPN\ConfigException $e) {
    echo str_replace($base, '{BASE}', $e->getMessage()), "\n";
}
?>
--CLEAN--
<?php
$base = sys_get_temp_dir() . '/php-vpn-phpt-033';
foreach (glob("$base/*/*") ?: [] as $file) {
    @unlink($file);
}
foreach (glob("$base/*") ?: [] as $dir) {
    @rmdir($dir);
}
@rmdir($base);
?>
--EXPECT--
first entry (trailing slash)   loaded
second entry                   loaded
not listed                     WireGuard profile `{BASE}/c/profile.conf` is outside php_vpn.allowed_config_dir
-- pool() mixes entries of the list
int(2)
WireGuard profile `{BASE}/c/profile.conf` is outside php_vpn.allowed_config_dir
