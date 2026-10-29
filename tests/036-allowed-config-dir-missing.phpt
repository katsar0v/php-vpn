--TEST--
php-vpn: php_vpn.allowed_config_dir that resolves to nothing refuses every profile path (fail closed)
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.allowed_config_dir={TMP}/php-vpn-phpt-036-does-not-exist
--FILE--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-036-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);
$path = "$dir/profile.conf";
file_put_contents($path, "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
    . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n");
chmod($path, 0600);

var_dump(file_exists(ini_get('php_vpn.allowed_config_dir')));
foreach (['wireguard' => fn() => VPN::wireguard($path), 'pool' => fn() => VPN::pool([$path])] as $label => $call) {
    try {
        $call();
        echo "$label: loaded (the restriction was ignored)\n";
    } catch (VPN\ConfigException $e) {
        echo "$label: ", str_replace($dir, '{DIR}', $e->getMessage()), "\n";
    }
}
echo "from string: ", get_class(VPN::wireguardFromString(file_get_contents($path))), "\n";
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-036-*') ?: [] as $dir) {
    array_map('unlink', glob("$dir/*") ?: []);
    @rmdir($dir);
}
?>
--EXPECT--
bool(false)
wireguard: WireGuard profile `{DIR}/profile.conf` is outside php_vpn.allowed_config_dir
pool: WireGuard profile `{DIR}/profile.conf` is outside php_vpn.allowed_config_dir
from string: VPN
