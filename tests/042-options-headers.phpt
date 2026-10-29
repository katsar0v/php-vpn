--TEST--
php-vpn: header options are validated (shape, managed headers, injection, names) without network traffic
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-042-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

// Outcome of a request: 'accepted' once it got as far as the (unreachable) tunnel.
function request_outcome(array $options): string {
    global $vpn;
    $start = microtime(true);
    try {
        $vpn->request('GET', 'http://198.51.100.30/', $options + ['connect_timeout' => 0.05]);
        return 'accepted (no error?)';
    } catch (VPN\TunnelException | VPN\TimeoutException $e) {
        return 'accepted';
    } catch (VPN\ConfigException $e) {
        // A rejection returns at once; reaching the tunnel would take at least the 0.05 s connect timeout.
        $slow = microtime(true) - $start > 0.04 ? ' [SLOW: the tunnel was used]' : '';
        return addcslashes($e->getMessage(), "\0..\37\177..\377") . $slow;
    }
}

// Default options (given when the profile is created) must be rejected too:
// either right away or, at the latest, by the first request.
function defaults_outcome(array $options): string {
    global $conf;
    try {
        $profile = VPN::wireguardFromString($conf, $options);
        $profile->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 0.05]);
        return 'accepted';
    } catch (VPN\TunnelException | VPN\TimeoutException $e) {
        return 'accepted';
    } catch (VPN\ConfigException $e) {
        return 'rejected';
    }
}

function check(string $label, array $headers): void {
    $options = ['headers' => $headers];
    $request = request_outcome($options);
    $defaults = defaults_outcome($options);
    printf("%-34s %s%s\n", $label, $request, $defaults === ($request === 'accepted' ? 'accepted' : 'rejected') ? '' : "  [as defaults: $defaults]");
}

echo "-- accepted shapes\n";
check('no headers', []);
check('name => value', ['Accept' => 'text/plain', 'X-Trace' => 'abc']);
check('name => list of values', ['Accept' => ['text/html', 'text/plain']]);
check('"Name: value" list', ['Accept: text/plain', 'X-Trace:abc', 'X-Spaced  :   padded  ']);
check('mixed forms', ['Accept: */*', 'X-A' => '1', 'X-B' => ['2', '3']]);
check('scalar values', ['X-Int' => 5, 'X-Float' => 1.5, 'X-True' => true, 'X-False' => false, 'X-Null' => null]);
check('tab and UTF-8 in a value', ['X-A' => "a\tb", 'X-B' => "caf\xC3\xA9"]);
check('empty value', ['X-Empty' => '']);
check('case-different duplicates', ['accept' => 'a', 'Accept' => 'b']);

echo "-- rejected shapes\n";
check('nested array value', ['X-A' => ['a' => ['nested']]]);
check('object value', ['X-A' => new stdClass()]);
check('object in a value list', ['X-A' => ['ok', new stdClass()]]);
check('list entry without colon', ['NoColonHeader']);
check('list entry, accepted first', ['Accept: */*', 'NoColonHeader']);
check('list entry is an int', [123]);
check('list entry is null', [null]);
check('list entry is an array', [['Accept: */*']]);

echo "-- headers php-vpn owns\n";
foreach (['Content-Length', 'content-length', 'Transfer-Encoding', 'Connection', 'CONNECTION', 'Keep-Alive',
          'Upgrade', 'TE', 'Trailer', 'Proxy-Connection'] as $name) {
    check("$name => value", [$name => '5']);
}
check('"Content-Length: 5" list entry', ['Content-Length: 5']);
check('"Connection : close" list entry', ['Connection : close']);
check('managed header among valid ones', ['Accept' => '*/*', 'X-A' => '1', 'Transfer-Encoding' => 'chunked']);
check('managed header in a value list', ['Connection' => ['close', 'keep-alive']]);

echo "-- header injection and invalid names\n";
check('CRLF in a value', ['X-A' => "a\r\nB: c"]);
check('LF in a value', ['X-A' => "a\nB: c"]);
check('CR in a value', ['X-A' => "a\rB"]);
check('NUL in a value', ['X-A' => "a\0b"]);
check('DEL in a value', ['X-A' => "a\x7Fb"]);
check('CRLF in one of several values', ['X-A' => ['ok', "bad\r\nB: c"]]);
check('CRLF in a "Name: value" entry', ["X-A: a\r\nB: c"]);
check('CRLF in a name', ["X-A\r\nB" => 'c']);
check('space in a name', ['Bad Name' => 'v']);
check('parenthesis in a name', ['Bad(Name)' => 'v']);
check('colon in a name', ['X:Y' => 'v']);
check('empty name', ['' => 'v']);
check('empty name in a list entry', [': value']);
check('non-ASCII name', ["X-N\xC3\xA4me" => 'v']);

echo "-- no session was ever established\n";
var_dump($vpn->info()['session_age']);
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-042-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- accepted shapes
no headers                         accepted
name => value                      accepted
name => list of values             accepted
"Name: value" list                 accepted
mixed forms                        accepted
scalar values                      accepted
tab and UTF-8 in a value           accepted
empty value                        accepted
case-different duplicates          accepted
-- rejected shapes
nested array value                 header `X-A` values must be scalars
object value                       header `X-A` value must be a scalar
object in a value list             header `X-A` values must be scalars
list entry without colon           headers without a key must be strings like `Name: value`
list entry, accepted first         headers without a key must be strings like `Name: value`
list entry is an int               headers without a key must be strings like `Name: value`
list entry is null                 headers without a key must be strings like `Name: value`
list entry is an array             headers without a key must be strings like `Name: value`
-- headers php-vpn owns
Content-Length => value            header `Content-Length` is managed by php-vpn and cannot be set
content-length => value            header `content-length` is managed by php-vpn and cannot be set
Transfer-Encoding => value         header `Transfer-Encoding` is managed by php-vpn and cannot be set
Connection => value                header `Connection` is managed by php-vpn and cannot be set
CONNECTION => value                header `CONNECTION` is managed by php-vpn and cannot be set
Keep-Alive => value                header `Keep-Alive` is managed by php-vpn and cannot be set
Upgrade => value                   header `Upgrade` is managed by php-vpn and cannot be set
TE => value                        header `TE` is managed by php-vpn and cannot be set
Trailer => value                   header `Trailer` is managed by php-vpn and cannot be set
Proxy-Connection => value          header `Proxy-Connection` is managed by php-vpn and cannot be set
"Content-Length: 5" list entry     header `Content-Length` is managed by php-vpn and cannot be set
"Connection : close" list entry    header `Connection` is managed by php-vpn and cannot be set
managed header among valid ones    header `Transfer-Encoding` is managed by php-vpn and cannot be set
managed header in a value list     header `Connection` is managed by php-vpn and cannot be set
-- header injection and invalid names
CRLF in a value                    invalid value for header `X-A`
LF in a value                      invalid value for header `X-A`
CR in a value                      invalid value for header `X-A`
NUL in a value                     invalid value for header `X-A`
DEL in a value                     invalid value for header `X-A`
CRLF in one of several values      invalid value for header `X-A`
CRLF in a "Name: value" entry      invalid value for header `X-A`
CRLF in a name                     invalid header name `X-A\r\nB`
space in a name                    invalid header name `Bad Name`
parenthesis in a name              invalid header name `Bad(Name)`
colon in a name                    invalid header name `X:Y`
empty name                         invalid header name ``
empty name in a list entry         invalid header name ``
non-ASCII name                     invalid header name `X-N\303\244me`
-- no session was ever established
NULL
