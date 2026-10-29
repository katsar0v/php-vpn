--TEST--
php-vpn: php_vpn.enforce_key_permissions=0 accepts world-readable profile files
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.enforce_key_permissions=0
--FILE--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-031-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);

function conf(): string {
    return "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
}

var_dump(ini_get('php_vpn.enforce_key_permissions'));
foreach ([0600, 0644, 0666, 0604] as $mode) {
    $path = sprintf('%s/mode-%04o.conf', $dir, $mode);
    file_put_contents($path, conf());
    chmod($path, $mode);
    $vpn = VPN::wireguard($path);
    printf("mode %04o: loaded, endpoint %s\n", $mode, $vpn->info()['endpoint']);
}

echo "-- pool() of paths follows the same setting\n";
$pool = VPN::pool(["$dir/mode-0644.conf", "$dir/mode-0666.conf"]);
var_dump(count($pool->info()));

echo "-- other checks still apply\n";
try {
    VPN::wireguard($dir);
} catch (VPN\ConfigException $e) {
    echo str_replace($dir, '{DIR}', $e->getMessage()), "\n";
}
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-031-*') ?: [] as $dir) {
    array_map('unlink', glob("$dir/*") ?: []);
    @rmdir($dir);
}
?>
--EXPECT--
string(1) "0"
mode 0600: loaded, endpoint 127.0.0.1:9
mode 0644: loaded, endpoint 127.0.0.1:9
mode 0666: loaded, endpoint 127.0.0.1:9
mode 0604: loaded, endpoint 127.0.0.1:9
-- pool() of paths follows the same setting
int(2)
-- other checks still apply
WireGuard profile `{DIR}` is not a regular file
