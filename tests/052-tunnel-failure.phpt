--TEST--
php-vpn: an unreachable tunnel endpoint fails closed with TunnelException and never falls back to a direct connection
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-052-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

// Nothing listens on UDP 127.0.0.1:9, so the WireGuard handshake cannot succeed.
$private = base64_encode(random_bytes(32));
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\nDNS = 10.13.13.1\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

// A server on the loopback interface that a direct connection would reach.
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
stream_set_blocking($server, false);

function attempt(VPN $vpn, string $url, array $options = []): string {
    $start = microtime(true);
    try {
        $response = $vpn->request('GET', $url, $options + ['connect_timeout' => 0.3]);
        return 'RESPONSE ' . $response->status();
    } catch (VPN\Exception $e) {
        $elapsed = microtime(true) - $start;
        $reason = preg_match('/handshake|unreachable/', $e->getMessage()) ? 'handshake failed' : $e->getMessage();
        return sprintf('%s (%d): %s%s', $e::class, $e->getCode(), $reason, $elapsed < 2.0 ? '' : sprintf(' [took %.1f s]', $elapsed));
    }
}

echo "-- public IP literal\n";
echo attempt($vpn, 'http://198.51.100.30/'), "\n";
echo attempt($vpn, 'https://198.51.100.30/'), "\n";
echo "-- host names: the handshake comes first, so no DNS lookup happens\n";
echo attempt($vpn, 'http://example.com/'), "\n";
echo attempt($vpn, 'https://this-name-does-not-exist.invalid/'), "\n";
echo "-- every method, with a body\n";
foreach (['POST', 'PUT', 'DELETE'] as $method) {
    try {
        $vpn->request($method, 'http://198.51.100.30/', ['body' => 'a=b', 'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'], 'connect_timeout' => 0.3]);
    } catch (VPN\TunnelException $e) {
        echo "$method: TunnelException\n";
    }
}

echo "-- no fallback: a server on the loopback interface never sees a connection\n";
echo attempt($vpn, "http://127.0.0.1:$port/", ['allow_private' => true]), "\n";
echo attempt($vpn, "http://localhost:$port/", ['allow_private' => true]), "\n";
echo attempt($vpn, "https://localhost:$port/", ['allow_private' => true, 'verify_tls' => false]), "\n";
echo 'connections accepted: ', var_export(@stream_socket_accept($server, 0), true), "\n";
fclose($server);

echo "-- the object stays usable\n";
var_dump($vpn->info()['session_age']);
var_dump($vpn->info()['endpoint']);
var_dump($vpn->close());
echo attempt($vpn, 'http://198.51.100.30/'), "\n";
var_dump($vpn->info()['session_age']);

echo "-- a pool of unreachable profiles\n";
$other = str_replace($private, base64_encode(random_bytes(32)), $conf);
$pool = VPN::pool([$vpn, VPN::wireguardFromString($other)]);
echo attempt($pool, 'http://198.51.100.30/'), "\n";
echo attempt($pool, 'http://198.51.100.30/'), "\n";
var_dump(array_column($pool->info(), 'session_age'));

echo "-- the exception does not leak the key\n";
try {
    $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 0.3]);
} catch (VPN\TunnelException $e) {
    var_dump(str_contains((string) $e, $private));
}
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-052-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- public IP literal
VPN\TunnelException (3): handshake failed
VPN\TunnelException (3): handshake failed
-- host names: the handshake comes first, so no DNS lookup happens
VPN\TunnelException (3): handshake failed
VPN\TunnelException (3): handshake failed
-- every method, with a body
POST: TunnelException
PUT: TunnelException
DELETE: TunnelException
-- no fallback: a server on the loopback interface never sees a connection
VPN\TunnelException (3): handshake failed
VPN\TunnelException (3): handshake failed
VPN\TunnelException (3): handshake failed
connections accepted: false
-- the object stays usable
NULL
string(11) "127.0.0.1:9"
NULL
VPN\TunnelException (3): handshake failed
NULL
-- a pool of unreachable profiles
VPN\TunnelException (3): handshake failed
VPN\TunnelException (3): handshake failed
array(2) {
  [0]=>
  NULL
  [1]=>
  NULL
}
-- the exception does not leak the key
bool(false)
