--TEST--
php-vpn: option names and value types are validated, at profile creation and at request time, without network traffic
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-040-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

// A request that passed option validation stops at the (unreachable) tunnel.
function outcome(callable $fn): string {
    try {
        $fn();
        return 'accepted';
    } catch (VPN\TunnelException | VPN\TimeoutException $e) {
        return 'accepted';
    } catch (VPN\ConfigException $e) {
        return 'ConfigException: ' . $e->getMessage();
    }
}

function check(string $label, array $options): void {
    global $conf, $vpn;
    $created = outcome(fn() => VPN::wireguardFromString($conf, $options));
    $start = microtime(true);
    $requested = outcome(fn() => $vpn->request('GET', 'http://198.51.100.30/', $options + ['connect_timeout' => 0.05]));
    $elapsed = microtime(true) - $start;
    printf("%-26s %s\n", $label, $created);
    if ($requested !== $created) {
        printf("%-26s   request() differs: %s\n", '', $requested);
    }
    // A rejected request returns at once; reaching the tunnel would take at least the 0.05 s connect timeout.
    if ($requested !== 'accepted' && $elapsed > 0.04) {
        printf("%-26s   SLOW rejection (%.3f s): the tunnel was used\n", '', $elapsed);
    }
}

echo "-- option names\n";
check('no options', []);
check('unknown', ['bogus' => 1]);
check('unknown, wrong case', ['Timeout' => 5]);
check('unknown, trailing space', ['timeout ' => 5]);
check('unknown after valid ones', ['timeout' => 5, 'verify_tls' => true, 'nope' => 1]);
check('integer key', [5 => 'x']);
check('list of options', ['timeout', 'verify_tls']);
check('valid and integer key', ['timeout' => 5, 'x']);

echo "-- bool options\n";
foreach (['verify_tls', 'allow_private', 'allow_https_downgrade', 'decode_content'] as $name) {
    check("$name => true", [$name => true]);
    check("$name => false", [$name => false]);
    check("$name => \"false\"", [$name => 'false']);
    check("$name => 0", [$name => 0]);
    check("$name => 1", [$name => 1]);
    check("$name => null", [$name => null]);
    check("$name => []", [$name => []]);
}

echo "-- ca_file\n";
check('ca_file => null', ['ca_file' => null]);
check('ca_file => existing file', ['ca_file' => __FILE__]);
check('ca_file => 123', ['ca_file' => 123]);
check('ca_file => true', ['ca_file' => true]);
check('ca_file => []', ['ca_file' => []]);
check('ca_file => ""', ['ca_file' => '']);
check('ca_file => NUL byte', ['ca_file' => "a\0b"]);

echo "-- body\n";
check('body => string', ['body' => 'a=b']);
check('body => empty string', ['body' => '']);
check('body => null', ['body' => null]);
check('body => array', ['body' => ['a' => 'b']]);
check('body => int', ['body' => 5]);
check('body => true', ['body' => true]);
check('body => object', ['body' => new stdClass()]);

echo "-- headers is an array\n";
check('headers => []', ['headers' => []]);
check('headers => string', ['headers' => 'Accept: */*']);
check('headers => null', ['headers' => null]);
check('headers => int', ['headers' => 1]);

echo "-- no session was ever established\n";
var_dump($vpn->info()['session_age']);
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-040-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- option names
no options                 accepted
unknown                    ConfigException: unknown option `bogus`
unknown, wrong case        ConfigException: unknown option `Timeout`
unknown, trailing space    ConfigException: unknown option `timeout `
unknown after valid ones   ConfigException: unknown option `nope`
integer key                ConfigException: options must be an array with string keys
list of options            ConfigException: options must be an array with string keys
valid and integer key      ConfigException: options must be an array with string keys
-- bool options
verify_tls => true         accepted
verify_tls => false        accepted
verify_tls => "false"      ConfigException: option `verify_tls` must be a bool, string given
verify_tls => 0            ConfigException: option `verify_tls` must be a bool, int given
verify_tls => 1            ConfigException: option `verify_tls` must be a bool, int given
verify_tls => null         ConfigException: option `verify_tls` must be a bool, null given
verify_tls => []           ConfigException: option `verify_tls` must be a bool, array given
allow_private => true      accepted
allow_private => false     accepted
allow_private => "false"   ConfigException: option `allow_private` must be a bool, string given
allow_private => 0         ConfigException: option `allow_private` must be a bool, int given
allow_private => 1         ConfigException: option `allow_private` must be a bool, int given
allow_private => null      ConfigException: option `allow_private` must be a bool, null given
allow_private => []        ConfigException: option `allow_private` must be a bool, array given
allow_https_downgrade => true accepted
allow_https_downgrade => false accepted
allow_https_downgrade => "false" ConfigException: option `allow_https_downgrade` must be a bool, string given
allow_https_downgrade => 0 ConfigException: option `allow_https_downgrade` must be a bool, int given
allow_https_downgrade => 1 ConfigException: option `allow_https_downgrade` must be a bool, int given
allow_https_downgrade => null ConfigException: option `allow_https_downgrade` must be a bool, null given
allow_https_downgrade => [] ConfigException: option `allow_https_downgrade` must be a bool, array given
decode_content => true     accepted
decode_content => false    accepted
decode_content => "false"  ConfigException: option `decode_content` must be a bool, string given
decode_content => 0        ConfigException: option `decode_content` must be a bool, int given
decode_content => 1        ConfigException: option `decode_content` must be a bool, int given
decode_content => null     ConfigException: option `decode_content` must be a bool, null given
decode_content => []       ConfigException: option `decode_content` must be a bool, array given
-- ca_file
ca_file => null            accepted
ca_file => existing file   accepted
ca_file => 123             ConfigException: option `ca_file` must be a string or null
ca_file => true            ConfigException: option `ca_file` must be a string or null
ca_file => []              ConfigException: option `ca_file` must be a string or null
ca_file => ""              ConfigException: ca_file path must be a non-empty string without NUL bytes
ca_file => NUL byte        ConfigException: ca_file path must be a non-empty string without NUL bytes
-- body
body => string             accepted
body => empty string       accepted
body => null               accepted
body => array              ConfigException: option `body` must be a string (use http_build_query() or json_encode()), array given
body => int                ConfigException: option `body` must be a string (use http_build_query() or json_encode()), int given
body => true               ConfigException: option `body` must be a string (use http_build_query() or json_encode()), bool given
body => object             ConfigException: option `body` must be a string (use http_build_query() or json_encode()), stdClass given
-- headers is an array
headers => []              accepted
headers => string          ConfigException: option `headers` must be an array
headers => null            ConfigException: option `headers` must be an array
headers => int             ConfigException: option `headers` must be an array
-- no session was ever established
NULL
