--TEST--
php-vpn: php_vpn.lock_dir pointing to a directory that does not exist fails at request time
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-080-does-not-exist/nested
--FILE--
<?php
function conf(): string {
    return "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
}

$lockDir = ini_get('php_vpn.lock_dir');
var_dump($lockDir === sys_get_temp_dir() . '/php-vpn-phpt-080-does-not-exist/nested');
var_dump(file_exists($lockDir));

// Creating a profile does not touch the lock directory...
$single = VPN::wireguardFromString(conf());
$pool = VPN::pool([VPN::wireguardFromString(conf()), VPN::wireguardFromString(conf())]);
echo "profiles created\n";

// ...the first request does, before any packet is sent.
foreach (['single profile' => $single, 'pool' => $pool] as $label => $profile) {
    $start = microtime(true);
    try {
        $profile->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 5]);
        echo "$label: no exception\n";
    } catch (VPN\ConfigException $e) {
        $message = str_replace(sys_get_temp_dir(), '{TMP}', $e->getMessage());
        $message = preg_replace('/php-vpn-[0-9a-f]{32}\.lock/', 'php-vpn-<id>.lock', $message);
        $message = preg_replace('/: [^:]+ \(os error \d+\)$/', ': <os error>', $message);
        printf("%s: ConfigException (%d): %s\n", $label, $e->getCode(), $message);
        printf("%s: failed at once: %s\n", $label, var_export(microtime(true) - $start < 1.0, true));
    }
}

echo "-- nothing was created\n";
var_dump(file_exists($lockDir));
var_dump(file_exists(dirname($lockDir)));
?>
--EXPECT--
bool(true)
bool(false)
profiles created
single profile: ConfigException (2): cannot open lock file `{TMP}/php-vpn-phpt-080-does-not-exist/nested/php-vpn-<id>.lock` (php_vpn.lock_dir must be writable by every process using this profile): <os error>
single profile: failed at once: true
pool: ConfigException (2): cannot open lock file `{TMP}/php-vpn-phpt-080-does-not-exist/nested/php-vpn-<id>.lock` (php_vpn.lock_dir must be writable by every process using this profile): <os error>
pool: failed at once: true
-- nothing was created
bool(false)
bool(false)
