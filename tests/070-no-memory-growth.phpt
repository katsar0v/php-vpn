--TEST--
php-vpn: repeated requests with default headers do not leak memory
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

// Requests that are refused right after their options were processed (ftp is not
// an allowed scheme), so no tunnel is involved.
function growth(callable $step, int $rounds = 5000): int {
    for ($i = 0; $i < 200; $i++) {
        $step();
    }
    $before = memory_get_usage();
    for ($i = 0; $i < $rounds; $i++) {
        $step();
    }
    return memory_get_usage() - $before;
}
function refused(VPN $vpn, array $options = []): callable {
    return function () use ($vpn, $options) {
        try {
            $vpn->request('GET', 'ftp://example.com/', $options);
        } catch (VPN\PolicyException $e) {
        }
    };
}

$cases = [
    'no headers'                  => refused(VPN::wireguardFromString($conf)),
    'request headers'             => refused(VPN::wireguardFromString($conf), ['headers' => ['X-A' => '1', 'accept' => 'b']]),
    'default headers'             => refused(VPN::wireguardFromString($conf, ['headers' => ['Accept' => 'a', 'x-trace' => 'b']])),
    'default and request headers' => refused(VPN::wireguardFromString($conf, ['headers' => ['Accept' => 'a']]), ['headers' => ['X-A' => '1']]),
    'creating profiles with default headers' => fn() => VPN::wireguardFromString($conf, ['headers' => ['Accept' => 'a']]),
];
foreach ($cases as $label => $step) {
    // 5000 rounds: a leak of even one 32-byte string per round is 160000 bytes.
    $bytes = growth($step);
    printf("%-40s %s\n", $label, $bytes < 20000 ? 'flat' : "grows by $bytes bytes");
}
?>
--EXPECT--
no headers                               flat
request headers                          flat
default headers                          flat
default and request headers              flat
creating profiles with default headers   flat
