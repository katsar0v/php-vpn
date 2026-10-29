--TEST--
php-vpn: wrong argument counts and types raise TypeError / ArgumentCountError before anything else happens
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

function attempt(string $label, callable $fn): void {
    try {
        $fn();
        echo "$label: no error\n";
    } catch (Throwable $e) {
        echo "$label: ", get_class($e), ': ', $e->getMessage(), "\n";
    }
}

attempt('wireguard()', fn() => VPN::wireguard());
attempt('wireguard([])', fn() => VPN::wireguard([]));
attempt('wireguard(path, string)', fn() => VPN::wireguard('/nonexistent', 'options'));
attempt('wireguard(path, [], extra)', fn() => VPN::wireguard('/nonexistent', [], 1));
attempt('wireguardFromString()', fn() => VPN::wireguardFromString());
attempt('wireguardFromString(array)', fn() => VPN::wireguardFromString([]));
attempt('wireguardFromString(obj)', fn() => VPN::wireguardFromString(new stdClass()));
attempt('wireguardFromString(c, str)', fn() => VPN::wireguardFromString($conf, 'x'));
attempt('pool()', fn() => VPN::pool());
attempt('pool(null)', fn() => VPN::pool(null));
attempt('request()', fn() => $vpn->request());
attempt('request(method)', fn() => $vpn->request('GET'));
attempt('request(array, url)', fn() => $vpn->request([], 'http://198.51.100.30/'));
attempt('request(m, url, null)', fn() => $vpn->request('GET', 'http://198.51.100.30/', null));
attempt('request(m, url, [], extra)', fn() => $vpn->request('GET', 'http://198.51.100.30/', [], 1));
attempt('request(named options)', fn() => $vpn->request(method: 'GET', url: 'http://198.51.100.30/', options: ['bogus' => 1]));
attempt('request(unknown name)', fn() => $vpn->request(method: 'GET', url: 'http://198.51.100.30/', headers: []));
attempt('info(1)', fn() => $vpn->info(1));
attempt('close(1)', fn() => $vpn->close(1));

echo "-- scalar coercion follows the usual rules\n";
attempt('wireguardFromString(123)', fn() => VPN::wireguardFromString(123));
attempt('request(m, Stringable)', fn() => $vpn->request('GET', new class { function __toString() { return 'ftp://x/'; } }));
?>
--EXPECT--
wireguard(): ArgumentCountError: VPN::wireguard() expects at least 1 argument, 0 given
wireguard([]): TypeError: VPN::wireguard(): Argument #1 ($path) must be of type string, array given
wireguard(path, string): TypeError: VPN::wireguard(): Argument #2 ($options) must be of type array, string given
wireguard(path, [], extra): ArgumentCountError: VPN::wireguard() expects at most 2 arguments, 3 given
wireguardFromString(): ArgumentCountError: VPN::wireguardFromString() expects at least 1 argument, 0 given
wireguardFromString(array): TypeError: VPN::wireguardFromString(): Argument #1 ($config) must be of type string, array given
wireguardFromString(obj): TypeError: VPN::wireguardFromString(): Argument #1 ($config) must be of type string, stdClass given
wireguardFromString(c, str): TypeError: VPN::wireguardFromString(): Argument #2 ($options) must be of type array, string given
pool(): ArgumentCountError: VPN::pool() expects at least 1 argument, 0 given
pool(null): TypeError: VPN::pool(): Argument #1 ($profiles) must be of type array, null given
request(): ArgumentCountError: VPN::request() expects at least 2 arguments, 0 given
request(method): ArgumentCountError: VPN::request() expects at least 2 arguments, 1 given
request(array, url): TypeError: VPN::request(): Argument #1 ($method) must be of type string, array given
request(m, url, null): TypeError: VPN::request(): Argument #3 ($options) must be of type array, null given
request(m, url, [], extra): ArgumentCountError: VPN::request() expects at most 3 arguments, 4 given
request(named options): VPN\ConfigException: unknown option `bogus`
request(unknown name): Error: Unknown named parameter $headers
info(1): ArgumentCountError: VPN::info() expects exactly 0 arguments, 1 given
close(1): ArgumentCountError: VPN::close() expects exactly 0 arguments, 1 given
-- scalar coercion follows the usual rules
wireguardFromString(123): VPN\ConfigException: WireGuard profile, line 1: expected `Key = Value`
request(m, Stringable): VPN\PolicyException: URL scheme `ftp` is not supported (only http and https)
