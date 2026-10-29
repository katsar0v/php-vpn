--TEST--
php-vpn: open_basedir applies to profile paths and the ca_file option
--SKIPIF--
<?php
if (!extension_loaded('vpn')) die('skip vpn extension not loaded');
if (str_starts_with(realpath(PHP_BINARY), realpath(sys_get_temp_dir()) . '/')) die('skip the PHP binary lives in the temp dir');
?>
--INI--
open_basedir={TMP}
--FILE--
<?php
$base = sys_get_temp_dir() . '/php-vpn-phpt-034';
mkdir($base, 0700);
$profile = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
file_put_contents("$base/inside.conf", $profile);
chmod("$base/inside.conf", 0600);
file_put_contents("$base/ca.pem", "not a certificate\n");

// An existing file outside open_basedir (which is the temp dir here).
$outside = PHP_BINARY;

$via = "$base/" . str_repeat('../', substr_count($base, '/')) . ltrim($outside, '/');

function attempt(string $label, callable $fn): void {
    global $base, $outside, $via;
    try {
        $fn();
        $text = 'ok';
    } catch (VPN\ConfigException $e) {
        $text = str_replace([$via, $base, $outside], ['{VIA}', '{BASE}', '{OUTSIDE}'], $e->getMessage());
    }
    printf("%-28s %s\n", $label, $text);
}

var_dump(ini_get('open_basedir') === sys_get_temp_dir());

echo "-- profile paths\n";
attempt('inside', fn() => VPN::wireguard("$base/inside.conf"));
attempt('outside', fn() => VPN::wireguard($outside));
attempt('outside, via ..', fn() => VPN::wireguard($via));
attempt('missing, outside', fn() => VPN::wireguard('/nonexistent-dir/profile.conf'));
attempt('pool, one outside', fn() => VPN::pool(["$base/inside.conf", $outside]));
attempt('from string', fn() => VPN::wireguardFromString($profile));

echo "-- ca_file option\n";
attempt('ca_file inside', fn() => VPN::wireguardFromString($profile, ['ca_file' => "$base/ca.pem"]));
attempt('ca_file outside', fn() => VPN::wireguardFromString($profile, ['ca_file' => $outside]));
attempt('ca_file null', fn() => VPN::wireguardFromString($profile, ['ca_file' => null]));
attempt('request ca_file outside', fn() => VPN::wireguardFromString($profile)
    ->request('GET', 'http://198.51.100.30/', ['ca_file' => $outside]));
?>
--CLEAN--
<?php
$base = sys_get_temp_dir() . '/php-vpn-phpt-034';
foreach (glob("$base/*") ?: [] as $file) {
    @unlink($file);
}
@rmdir($base);
?>
--EXPECT--
bool(true)
-- profile paths
inside                       ok
outside                      WireGuard profile `{OUTSIDE}` is outside open_basedir
outside, via ..              WireGuard profile `{VIA}` is outside open_basedir
missing, outside             WireGuard profile `/nonexistent-dir/profile.conf` cannot be opened: No such file or directory
pool, one outside            WireGuard profile `{OUTSIDE}` is outside open_basedir
from string                  ok
-- ca_file option
ca_file inside               ok
ca_file outside              ca_file `{OUTSIDE}` is outside open_basedir
ca_file null                 ok
request ca_file outside      ca_file `{OUTSIDE}` is outside open_basedir
