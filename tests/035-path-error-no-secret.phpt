--TEST--
php-vpn: passing profile text where a path is expected does not echo the private key in the exception
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
// A common mistake: VPN::wireguard($config) instead of VPN::wireguardFromString($config).
$private = base64_encode(random_bytes(32));
$profile = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

$calls = [
    'wireguard()'       => fn() => VPN::wireguard($profile),
    'pool() member'     => fn() => VPN::pool([$profile]),
    'ca_file option'    => fn() => VPN::wireguardFromString($profile, ['ca_file' => $profile]),
];
foreach ($calls as $label => $call) {
    try {
        $call();
        echo "$label: no exception\n";
    } catch (VPN\ConfigException $e) {
        printf("%s: %s\n", $label, str_contains($e->getMessage(), $private) ? 'LEAKS THE PRIVATE KEY' : 'ok');
    }
}
?>
--EXPECT--
wireguard(): ok
pool() member: ok
ca_file option: ok
