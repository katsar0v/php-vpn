--TEST--
php-vpn: request() rejects invalid URLs, other schemes, URL credentials and unsupported methods before any traffic
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-050-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

// Valid requests stop at the unreachable tunnel (TunnelException, code 3).
// Rejections must return at once, long before the 0.1 s connect timeout.
function send(string $method, string $url): string {
    global $vpn;
    $start = microtime(true);
    try {
        $vpn->request($method, $url, ['connect_timeout' => 0.1]);
        return 'no error?';
    } catch (VPN\Exception $e) {
        $slow = microtime(true) - $start > 0.09 && !($e instanceof VPN\TunnelException) ? ' [SLOW]' : '';
        $message = $e instanceof VPN\TunnelException ? 'the tunnel endpoint cannot be reached' : $e->getMessage();
        // The reason after "invalid URL:" comes from the URL parser and may change between versions.
        $message = preg_replace('/^(invalid URL): .*/', '$1: ...', $message);
        return sprintf('%s (%d): %s%s', $e::class, $e->getCode(), addcslashes($message, "\0..\37\177..\377"), $slow);
    }
}

echo "-- URLs that do not parse\n";
foreach (['not a url', '', 'http://', '//example.com/x', 'example.com/path', '/relative',
          'http://exa mple.com/', 'http://[::1/', 'http://example.com:99999/', 'http://exa<mple.com/'] as $url) {
    printf("%-28s %s\n", var_export($url, true), send('GET', $url));
}

echo "-- schemes other than http and https\n";
foreach (['ftp://example.com/', 'file:///etc/passwd', 'gopher://example.com/', 'javascript:alert(1)',
          'data:text/plain,hi', 'ws://example.com/', 'wss://example.com/', 'ssh://198.51.100.30/'] as $url) {
    printf("%-28s %s\n", $url, send('GET', $url));
}

echo "-- credentials in the URL\n";
foreach (['http://user:pass@198.51.100.30/', 'http://user@198.51.100.30/', 'http://:pass@198.51.100.30/',
          'https://user:@example.com/'] as $url) {
    printf("%-34s %s\n", $url, send('GET', $url));
}

echo "-- methods\n";
foreach (['GET', 'get', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'PROPFIND', 'M-SEARCH'] as $method) {
    printf("%-10s %s\n", $method, send($method, 'http://198.51.100.30/'));
}
foreach (['CONNECT', 'connect', 'TRACE', 'Trace', '', 'GE T', "GET\r\nHost: evil", "G\xC3\x89T", 'GET /'] as $method) {
    printf("%-10s %s\n", addcslashes($method === '' ? '(empty)' : $method, "\0..\37\177..\377"), send($method, 'http://198.51.100.30/'));
}

echo "-- accepted URLs\n";
foreach (['http://198.51.100.30/', 'HTTP://198.51.100.30/', 'https://198.51.100.30/', 'http://198.51.100.30:8080/a?b=c#d',
          'https://example.com/', 'http://example.com:8080', 'http://EXAMPLE.com/%7Euser', 'http://xn--bcher-kva.example/',
          'http:///198.51.100.30/'] as $url) {
    printf("%-36s %s\n", $url, send('GET', $url));
}

echo "-- no session was ever established\n";
var_dump($vpn->info()['session_age']);
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-050-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- URLs that do not parse
'not a url'                  VPN\ConfigException (2): invalid URL: ...
''                           VPN\ConfigException (2): invalid URL: ...
'http://'                    VPN\ConfigException (2): invalid URL: ...
'//example.com/x'            VPN\ConfigException (2): invalid URL: ...
'example.com/path'           VPN\ConfigException (2): invalid URL: ...
'/relative'                  VPN\ConfigException (2): invalid URL: ...
'http://exa mple.com/'       VPN\ConfigException (2): invalid URL: ...
'http://[::1/'               VPN\ConfigException (2): invalid URL: ...
'http://example.com:99999/'  VPN\ConfigException (2): invalid URL: ...
'http://exa<mple.com/'       VPN\ConfigException (2): invalid URL: ...
-- schemes other than http and https
ftp://example.com/           VPN\PolicyException (9): URL scheme `ftp` is not supported (only http and https)
file:///etc/passwd           VPN\PolicyException (9): URL scheme `file` is not supported (only http and https)
gopher://example.com/        VPN\PolicyException (9): URL scheme `gopher` is not supported (only http and https)
javascript:alert(1)          VPN\PolicyException (9): URL scheme `javascript` is not supported (only http and https)
data:text/plain,hi           VPN\PolicyException (9): URL scheme `data` is not supported (only http and https)
ws://example.com/            VPN\PolicyException (9): URL scheme `ws` is not supported (only http and https)
wss://example.com/           VPN\PolicyException (9): URL scheme `wss` is not supported (only http and https)
ssh://198.51.100.30/         VPN\PolicyException (9): URL scheme `ssh` is not supported (only http and https)
-- credentials in the URL
http://user:pass@198.51.100.30/    VPN\ConfigException (2): credentials in the URL are not supported; send an Authorization header
http://user@198.51.100.30/         VPN\ConfigException (2): credentials in the URL are not supported; send an Authorization header
http://:pass@198.51.100.30/        VPN\ConfigException (2): credentials in the URL are not supported; send an Authorization header
https://user:@example.com/         VPN\ConfigException (2): credentials in the URL are not supported; send an Authorization header
-- methods
GET        VPN\TunnelException (3): the tunnel endpoint cannot be reached
get        VPN\TunnelException (3): the tunnel endpoint cannot be reached
HEAD       VPN\TunnelException (3): the tunnel endpoint cannot be reached
POST       VPN\TunnelException (3): the tunnel endpoint cannot be reached
PUT        VPN\TunnelException (3): the tunnel endpoint cannot be reached
DELETE     VPN\TunnelException (3): the tunnel endpoint cannot be reached
PATCH      VPN\TunnelException (3): the tunnel endpoint cannot be reached
OPTIONS    VPN\TunnelException (3): the tunnel endpoint cannot be reached
PROPFIND   VPN\TunnelException (3): the tunnel endpoint cannot be reached
M-SEARCH   VPN\TunnelException (3): the tunnel endpoint cannot be reached
CONNECT    VPN\ConfigException (2): HTTP method CONNECT is not supported
connect    VPN\ConfigException (2): HTTP method CONNECT is not supported
TRACE      VPN\ConfigException (2): HTTP method TRACE is not supported
Trace      VPN\ConfigException (2): HTTP method TRACE is not supported
(empty)    VPN\ConfigException (2): invalid HTTP method ``
GE T       VPN\ConfigException (2): invalid HTTP method `GE T`
GET\r\nHost: evil VPN\ConfigException (2): invalid HTTP method `GET\r\nHost: evil`
G\303\211T VPN\ConfigException (2): invalid HTTP method `G\303\211T`
GET /      VPN\ConfigException (2): invalid HTTP method `GET /`
-- accepted URLs
http://198.51.100.30/                VPN\TunnelException (3): the tunnel endpoint cannot be reached
HTTP://198.51.100.30/                VPN\TunnelException (3): the tunnel endpoint cannot be reached
https://198.51.100.30/               VPN\TunnelException (3): the tunnel endpoint cannot be reached
http://198.51.100.30:8080/a?b=c#d    VPN\TunnelException (3): the tunnel endpoint cannot be reached
https://example.com/                 VPN\TunnelException (3): the tunnel endpoint cannot be reached
http://example.com:8080              VPN\TunnelException (3): the tunnel endpoint cannot be reached
http://EXAMPLE.com/%7Euser           VPN\TunnelException (3): the tunnel endpoint cannot be reached
http://xn--bcher-kva.example/        VPN\TunnelException (3): the tunnel endpoint cannot be reached
http:///198.51.100.30/               VPN\TunnelException (3): the tunnel endpoint cannot be reached
-- no session was ever established
NULL
