--TEST--
php-vpn: php_vpn.lock_dir that cannot be written to fails at request time
--SKIPIF--
<?php
if (!extension_loaded('vpn')) die('skip vpn extension not loaded');
if (!is_dir('/proc/self')) die('skip needs a procfs (a directory nobody can create files in, not even root)');
?>
--INI--
php_vpn.lock_dir=/proc/self
--FILE--
<?php
// /proc/self is a directory, but no process may create files in it, whoever it runs as:
// a stand-in for a lock directory the PHP user cannot write to (root ignores file modes).
function conf(): string {
    return "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
}

var_dump(ini_get('php_vpn.lock_dir'));
var_dump(is_dir('/proc/self'));

$vpn = VPN::wireguardFromString(conf());
$start = microtime(true);
try {
    $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 5]);
    echo "no exception\n";
} catch (VPN\ConfigException $e) {
    printf("ConfigException (%d)\n", $e->getCode());
    $message = preg_replace('/php-vpn-[0-9a-f]{32}\.lock/', 'php-vpn-<id>.lock', $e->getMessage());
    echo preg_replace('/: [^:]+ \(os error \d+\)$/', ': <os error>', $message), "\n";
    var_dump(microtime(true) - $start < 1.0);
}
?>
--EXPECT--
string(10) "/proc/self"
bool(true)
ConfigException (2)
cannot open lock file `/proc/self/php-vpn-<id>.lock` (php_vpn.lock_dir must be writable by every process using this profile): <os error>
bool(true)
