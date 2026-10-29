--TEST--
php-vpn: a refused WireGuard endpoint (ICMP port unreachable) fails the request well before connect_timeout
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-053-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

// Nothing listens on UDP 127.0.0.1:9: the kernel answers the handshake
// initiation with ICMP port unreachable. The request must fail because of
// that, not wait for the 10 s connect timeout.
$start = microtime(true);
try {
    $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 10, 'timeout' => 20]);
    echo "no exception\n";
} catch (VPN\TunnelException $e) {
    $elapsed = microtime(true) - $start;
    var_dump($e->getCode());
    var_dump(str_contains($e->getMessage(), 'unreachable'));
    var_dump($elapsed < 3.0);
}

echo "-- the next request fails the same way (a fresh tunnel is built)\n";
$start = microtime(true);
try {
    $vpn->request('GET', 'https://198.51.100.30/', ['connect_timeout' => 10, 'timeout' => 20]);
} catch (VPN\TunnelException $e) {
    var_dump(microtime(true) - $start < 3.0);
}
var_dump($vpn->info()['session_age']);
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-053-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
int(3)
bool(true)
bool(true)
-- the next request fails the same way (a fresh tunnel is built)
bool(true)
NULL
