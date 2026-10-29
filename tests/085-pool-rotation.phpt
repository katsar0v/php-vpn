--TEST--
php-vpn: successive requests through a pool take different members in rotation
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-085
--FILE--
<?php
$lockDir = ini_get('php_vpn.lock_dir');
mkdir($lockDir, 0700);

function profile(): VPN {
    return VPN::wireguardFromString("[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
        . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n");
}
function lock_count(): int {
    global $lockDir;
    return count(glob("$lockDir/*"));
}
function fail(VPN $vpn): void {
    try {
        $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 0.05]);
    } catch (VPN\TunnelException $e) {
    }
}

// Every member has its own lock file, created the first time the member is used.
// With no contention, a pool that rotates uses a different member for each request.
$pool = VPN::pool([profile(), profile(), profile()]);
var_dump(lock_count());
for ($i = 1; $i <= 3; $i++) {
    fail($pool);
    printf("after request %d: %d lock file(s)\n", $i, lock_count());
}
fail($pool);
fail($pool);
var_dump(lock_count());
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-085';
foreach (glob("$dir/*") ?: [] as $file) {
    @unlink($file);
}
@rmdir($dir);
?>
--EXPECT--
int(0)
after request 1: 1 lock file(s)
after request 2: 2 lock file(s)
after request 3: 3 lock file(s)
int(3)
