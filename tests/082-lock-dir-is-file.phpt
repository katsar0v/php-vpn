--TEST--
php-vpn: php_vpn.lock_dir that is a regular file fails at request time
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={PWD}/082-lock-dir-is-file.phpt
--FILE--
<?php
// The lock "directory" is this test's own .phpt file.
$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

var_dump(is_file(ini_get('php_vpn.lock_dir')));
$start = microtime(true);
try {
    $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 5]);
    echo "no exception\n";
} catch (VPN\ConfigException $e) {
    printf("ConfigException (%d)\n", $e->getCode());
    $message = str_replace(ini_get('php_vpn.lock_dir'), '{LOCK_DIR}', $e->getMessage());
    $message = preg_replace('/php-vpn-[0-9a-f]{32}\.lock/', 'php-vpn-<id>.lock', $message);
    echo preg_replace('/: [^:]+ \(os error \d+\)$/', ': <os error>', $message), "\n";
    var_dump(microtime(true) - $start < 1.0);
}
?>
--EXPECT--
bool(true)
ConfigException (2)
cannot open lock file `{LOCK_DIR}/php-vpn-<id>.lock` (php_vpn.lock_dir must be writable by every process using this profile): <os error>
bool(true)
