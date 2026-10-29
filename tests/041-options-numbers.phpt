--TEST--
php-vpn: timeouts, follow_redirects and max_response_size are range- and type-checked without network traffic
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-041-locks
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
    printf("%-30s %s\n", $label, $created);
    if ($requested !== $created) {
        printf("%-30s   request() differs: %s\n", '', $requested);
    }
    // A rejected request returns at once; reaching the tunnel would take at least the 0.05 s connect timeout.
    if ($requested !== 'accepted' && $elapsed > 0.04) {
        printf("%-30s   SLOW rejection (%.3f s): the tunnel was used\n", '', $elapsed);
    }
}

foreach (['timeout', 'connect_timeout'] as $name) {
    echo "-- $name\n";
    foreach ([1, 30, 86400, 0.5, 0.001, 86400.0] as $value) {
        check("$name => " . var_export($value, true), [$name => $value]);
    }
    foreach ([0, 0.0, -1, -0.5, 86401, 86400.5, 1e10, PHP_INT_MAX, NAN, INF, -INF] as $value) {
        check("$name => " . var_export($value, true), [$name => $value]);
    }
    foreach (['5', '1.5', '', null, true, false, [], [5], new stdClass()] as $value) {
        check("$name => " . str_replace("\n", '', var_export($value, true)), [$name => $value]);
    }
}

echo "-- follow_redirects\n";
foreach ([true, false, 0, 1, 5, 50] as $value) {
    check('follow_redirects => ' . var_export($value, true), ['follow_redirects' => $value]);
}
foreach ([51, 100, -1, PHP_INT_MAX, 1.0, 2.5, '3', '', null, [], [3]] as $value) {
    check('follow_redirects => ' . str_replace("\n", '', var_export($value, true)), ['follow_redirects' => $value]);
}

echo "-- max_response_size\n";
foreach ([1, 1024, 16 << 20, PHP_INT_MAX] as $value) {
    check('max_response_size => ' . $value, ['max_response_size' => $value]);
}
foreach ([0, -1, PHP_INT_MIN, 1.5, 1024.0, '1024', '16M', '', null, true, false, []] as $value) {
    check('max_response_size => ' . str_replace("\n", '', var_export($value, true)), ['max_response_size' => $value]);
}

echo "-- request options override profile defaults\n";
$strict = VPN::wireguardFromString($conf, ['timeout' => 10, 'follow_redirects' => 2]);
try {
    $strict->request('GET', 'http://198.51.100.30/', ['timeout' => 0]);
} catch (VPN\ConfigException $e) {
    echo $e->getMessage(), "\n";
}
try {
    $strict->request('GET', 'http://198.51.100.30/', ['timeout' => 10, 'follow_redirects' => 99]);
} catch (VPN\ConfigException $e) {
    echo $e->getMessage(), "\n";
}

echo "-- no session was ever established\n";
var_dump($vpn->info()['session_age']);
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-041-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- timeout
timeout => 1                   accepted
timeout => 30                  accepted
timeout => 86400               accepted
timeout => 0.5                 accepted
timeout => 0.001               accepted
timeout => 86400.0             accepted
timeout => 0                   ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => 0.0                 ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => -1                  ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => -0.5                ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => 86401               ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => 86400.5             ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => 10000000000.0       ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => 9223372036854775807 ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => NAN                 ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => INF                 ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => -INF                ConfigException: option `timeout` must be greater than 0 and at most 86400
timeout => '5'                 ConfigException: option `timeout` must be a number of seconds, string given
timeout => '1.5'               ConfigException: option `timeout` must be a number of seconds, string given
timeout => ''                  ConfigException: option `timeout` must be a number of seconds, string given
timeout => NULL                ConfigException: option `timeout` must be a number of seconds, null given
timeout => true                ConfigException: option `timeout` must be a number of seconds, bool given
timeout => false               ConfigException: option `timeout` must be a number of seconds, bool given
timeout => array ()            ConfigException: option `timeout` must be a number of seconds, array given
timeout => array (  0 => 5,)   ConfigException: option `timeout` must be a number of seconds, array given
timeout => (object) array()    ConfigException: option `timeout` must be a number of seconds, stdClass given
-- connect_timeout
connect_timeout => 1           accepted
connect_timeout => 30          accepted
connect_timeout => 86400       accepted
connect_timeout => 0.5         accepted
connect_timeout => 0.001       accepted
connect_timeout => 86400.0     accepted
connect_timeout => 0           ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => 0.0         ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => -1          ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => -0.5        ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => 86401       ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => 86400.5     ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => 10000000000.0 ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => 9223372036854775807 ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => NAN         ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => INF         ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => -INF        ConfigException: option `connect_timeout` must be greater than 0 and at most 86400
connect_timeout => '5'         ConfigException: option `connect_timeout` must be a number of seconds, string given
connect_timeout => '1.5'       ConfigException: option `connect_timeout` must be a number of seconds, string given
connect_timeout => ''          ConfigException: option `connect_timeout` must be a number of seconds, string given
connect_timeout => NULL        ConfigException: option `connect_timeout` must be a number of seconds, null given
connect_timeout => true        ConfigException: option `connect_timeout` must be a number of seconds, bool given
connect_timeout => false       ConfigException: option `connect_timeout` must be a number of seconds, bool given
connect_timeout => array ()    ConfigException: option `connect_timeout` must be a number of seconds, array given
connect_timeout => array (  0 => 5,) ConfigException: option `connect_timeout` must be a number of seconds, array given
connect_timeout => (object) array() ConfigException: option `connect_timeout` must be a number of seconds, stdClass given
-- follow_redirects
follow_redirects => true       accepted
follow_redirects => false      accepted
follow_redirects => 0          accepted
follow_redirects => 1          accepted
follow_redirects => 5          accepted
follow_redirects => 50         accepted
follow_redirects => 51         ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => 100        ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => -1         ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => 9223372036854775807 ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => 1.0        ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => 2.5        ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => '3'        ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => ''         ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => NULL       ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => array ()   ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
follow_redirects => array (  0 => 3,) ConfigException: option `follow_redirects` must be a bool or an int between 0 and 50
-- max_response_size
max_response_size => 1         accepted
max_response_size => 1024      accepted
max_response_size => 16777216  accepted
max_response_size => 9223372036854775807 accepted
max_response_size => 0         ConfigException: option `max_response_size` must be a positive int
max_response_size => -1        ConfigException: option `max_response_size` must be a positive int
max_response_size => -9223372036854775807-1 ConfigException: option `max_response_size` must be a positive int
max_response_size => 1.5       ConfigException: option `max_response_size` must be a positive int
max_response_size => 1024.0    ConfigException: option `max_response_size` must be a positive int
max_response_size => '1024'    ConfigException: option `max_response_size` must be a positive int
max_response_size => '16M'     ConfigException: option `max_response_size` must be a positive int
max_response_size => ''        ConfigException: option `max_response_size` must be a positive int
max_response_size => NULL      ConfigException: option `max_response_size` must be a positive int
max_response_size => true      ConfigException: option `max_response_size` must be a positive int
max_response_size => false     ConfigException: option `max_response_size` must be a positive int
max_response_size => array ()  ConfigException: option `max_response_size` must be a positive int
-- request options override profile defaults
option `timeout` must be greater than 0 and at most 86400
option `follow_redirects` must be a bool or an int between 0 and 50
-- no session was ever established
NULL
