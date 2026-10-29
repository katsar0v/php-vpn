--TEST--
php-vpn: requests create one lock file per WireGuard key pair in php_vpn.lock_dir
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-083
--FILE--
<?php
$lockDir = ini_get('php_vpn.lock_dir');
var_dump($lockDir === sys_get_temp_dir() . '/php-vpn-phpt-083');
mkdir($lockDir, 0700);

function conf(string $private, string $peer): string {
    return "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = $peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
}
function locks(string $dir): array {
    $names = array_map('basename', glob("$dir/*") ?: []);
    sort($names);
    return $names;
}
function fail(VPN $vpn): void {
    try {
        $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 0.05]);
    } catch (VPN\TunnelException $e) {
    }
}

$private = base64_encode(random_bytes(32));
$peer = base64_encode(random_bytes(32));
$vpn = VPN::wireguardFromString(conf($private, $peer));

echo "-- creating the profile does not create a lock\n";
var_dump(locks($lockDir));

echo "-- a request creates one\n";
fail($vpn);
$locks = locks($lockDir);
var_dump(count($locks));
var_dump(preg_match('/^php-vpn-[0-9a-f]{32}\.lock$/', $locks[0]));
$mode = fileperms("$lockDir/{$locks[0]}") & 0777;
var_dump(($mode & 0007) === 0);              // never accessible by "other"
var_dump(is_file("$lockDir/{$locks[0]}"));

echo "-- the file name does not contain key material\n";
var_dump(!str_contains($locks[0], bin2hex(base64_decode($private))));
var_dump(!str_contains($locks[0], bin2hex(base64_decode($peer))));

echo "-- more requests, same key pair, same lock\n";
fail($vpn);
fail($vpn);
var_dump(locks($lockDir) === $locks);
fail(VPN::wireguardFromString(conf($private, $peer)));
var_dump(locks($lockDir) === $locks);

echo "-- another key pair gets its own lock\n";
fail(VPN::wireguardFromString(conf(base64_encode(random_bytes(32)), $peer)));
var_dump(count(locks($lockDir)));
fail(VPN::wireguardFromString(conf($private, base64_encode(random_bytes(32)))));
var_dump(count(locks($lockDir)));

echo "-- requests rejected before the tunnel create no lock\n";
$before = locks($lockDir);
foreach (['ftp://example.com/', 'http://127.0.0.1/', 'not a url'] as $url) {
    try {
        $vpn->request('GET', $url);
    } catch (VPN\ConfigException | VPN\PolicyException $e) {
    }
}
try {
    $vpn->request('GET', 'http://198.51.100.30/', ['timeout' => 0]);
} catch (VPN\ConfigException $e) {
}
var_dump(locks($lockDir) === $before);
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-083';
foreach (glob("$dir/*") ?: [] as $file) {
    @unlink($file);
}
@rmdir($dir);
?>
--EXPECT--
bool(true)
-- creating the profile does not create a lock
array(0) {
}
-- a request creates one
int(1)
int(1)
bool(true)
bool(true)
-- the file name does not contain key material
bool(true)
bool(true)
-- more requests, same key pair, same lock
bool(true)
bool(true)
-- another key pair gets its own lock
int(2)
int(3)
-- requests rejected before the tunnel create no lock
bool(true)
