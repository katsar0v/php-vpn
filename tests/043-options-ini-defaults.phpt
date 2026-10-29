--TEST--
php-vpn: php_vpn.* INI values act as request defaults and are validated when a request starts
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-043-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

// The WireGuard endpoint is a UDP port that is open but never answers: the
// handshake is neither completed nor refused, so it fails exactly when the
// connect timeout runs out.
$sink = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
stream_set_blocking($sink, false);
$endpoint = stream_socket_get_name($sink, false);
$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = $endpoint\n";
$vpn = VPN::wireguardFromString($conf);

// Kinds of datagram that reached the endpoint since the last call.
function received(): array {
    global $sink;
    $sizes = [];
    while (($packet = @stream_socket_recvfrom($sink, 4096)) !== false && $packet !== '') {
        $sizes[] = strlen($packet) . ($packet[0] === "\x01" ? ' (handshake initiation)' : '');
    }
    return array_values(array_unique($sizes));
}

// Runs a request through the silent tunnel and reports how it ended. A tunnel
// failure is expected to take between $min and $max seconds; anything else is
// flagged.
function request(array $options = [], float $min = 0.0, float $max = 2.0): string {
    global $vpn;
    $start = microtime(true);
    try {
        $vpn->request('GET', 'http://198.51.100.30/', $options);
        return 'no error?';
    } catch (VPN\ConfigException $e) {
        $slow = microtime(true) - $start > 0.5 ? ' [SLOW: the tunnel was used]' : '';
        return 'ConfigException: ' . $e->getMessage() . $slow;
    } catch (VPN\Exception $e) {
        $elapsed = microtime(true) - $start;
        return get_class($e) . ($elapsed >= $min && $elapsed < $max ? '' : sprintf(' [took %.2f s, expected %.2f-%.2f s]', $elapsed, $min, $max));
    }
}

echo "-- invalid defaults are rejected before any traffic\n";
foreach ([
    ['php_vpn.default_timeout', '0'],
    ['php_vpn.default_timeout', '-5'],
    ['php_vpn.default_timeout', 'soon'],
    ['php_vpn.default_timeout', '86401'],
    ['php_vpn.connect_timeout', '0'],
    ['php_vpn.connect_timeout', '-1'],
    ['php_vpn.connect_timeout', '100000'],
] as [$name, $value]) {
    $old = ini_set($name, $value);
    printf("%s=%s: %s\n", $name, $value, request());
    ini_set($name, $old);
}
var_dump(received());

echo "-- request options take precedence over the INI value\n";
ini_set('php_vpn.default_timeout', '0');
echo request(['timeout' => 30, 'connect_timeout' => 0.2], 0.15), "\n";
ini_set('php_vpn.default_timeout', '30');
ini_set('php_vpn.connect_timeout', '0');
echo request(['connect_timeout' => 0.2], 0.15), "\n";
ini_set('php_vpn.connect_timeout', '10');

echo "-- php_vpn.connect_timeout bounds the handshake\n";
ini_set('php_vpn.connect_timeout', '0.3');
echo request([], 0.25), "\n";
ini_set('php_vpn.connect_timeout', '10');
var_dump(received());

echo "-- lenient settings that are clamped instead of rejected\n";
foreach ([['php_vpn.max_redirects', '-3'], ['php_vpn.max_redirects', '1000'], ['php_vpn.max_response_size', '0'], ['php_vpn.max_response_size', '-1']] as [$name, $value]) {
    $old = ini_set($name, $value);
    printf("%s=%s: %s\n", $name, $value, request(['connect_timeout' => 0.05], 0.04));
    ini_set($name, $old);
}
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-043-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- invalid defaults are rejected before any traffic
php_vpn.default_timeout=0: ConfigException: timeout must be greater than 0 and at most 86400 seconds
php_vpn.default_timeout=-5: ConfigException: timeout must be greater than 0 and at most 86400 seconds
php_vpn.default_timeout=soon: ConfigException: timeout must be greater than 0 and at most 86400 seconds
php_vpn.default_timeout=86401: ConfigException: timeout must be greater than 0 and at most 86400 seconds
php_vpn.connect_timeout=0: ConfigException: connect_timeout must be greater than 0 and at most 86400 seconds
php_vpn.connect_timeout=-1: ConfigException: connect_timeout must be greater than 0 and at most 86400 seconds
php_vpn.connect_timeout=100000: ConfigException: connect_timeout must be greater than 0 and at most 86400 seconds
array(0) {
}
-- request options take precedence over the INI value
VPN\TunnelException
VPN\TunnelException
-- php_vpn.connect_timeout bounds the handshake
VPN\TunnelException
array(1) {
  [0]=>
  string(26) "148 (handshake initiation)"
}
-- lenient settings that are clamped instead of rejected
php_vpn.max_redirects=-3: VPN\TunnelException
php_vpn.max_redirects=1000: VPN\TunnelException
php_vpn.max_response_size=0: VPN\TunnelException
php_vpn.max_response_size=-1: VPN\TunnelException
