--TEST--
php-vpn: private, loopback and reserved IP literals are refused before any handshake unless allow_private is set
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-051-locks
--FILE--
<?php
// Lock files of the requests below go to a directory of their own.
mkdir(ini_get('php_vpn.lock_dir'), 0700);

$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

$restricted = [
    // IPv4
    'http://127.0.0.1/', 'http://127.1.2.3/', 'http://127.255.255.254/',
    'http://10.0.0.1/', 'http://10.255.255.255/',
    'http://172.16.0.1/', 'http://172.31.255.255/',
    'http://192.168.0.1/', 'http://192.168.255.255/',
    'http://169.254.169.254/', 'http://169.254.0.1/',
    'http://100.64.0.1/', 'http://100.127.255.255/',
    'http://0.0.0.0/', 'http://0.1.2.3/',
    'http://224.0.0.1/', 'http://239.255.255.255/', 'http://255.255.255.255/', 'http://240.0.0.1/',
    'http://198.18.0.1/', 'http://198.19.255.255/', 'http://192.0.0.8/',
    // IPv6
    'http://[::1]/', 'http://[::]/', 'http://[0:0:0:0:0:0:0:1]/',
    'http://[fd00::1]/', 'http://[fc00::1]/', 'http://[fe80::1]/', 'http://[fec0::1]/', 'http://[ff02::1]/',
    // IPv4 hidden inside IPv6
    'http://[::ffff:127.0.0.1]/', 'http://[::ffff:10.0.0.1]/', 'http://[::ffff:7f00:1]/',
    'http://[64:ff9b::a00:1]/', 'http://[64:ff9b::7f00:1]/',
];
$encodings = [
    'http://2130706433/',      // 127.0.0.1 as one decimal number
    'http://0x7f000001/',      // hexadecimal
    'http://0177.0.0.1/',      // octal
    'http://127.1/',           // short form
    'http://0x7f.0.0.1/',
    'http://10.1/',            // 10.0.0.1
    'http://167772161/',       // 10.0.0.1
    'http:///127.0.0.1/',      // extra slashes are ignored by URL parsers
    'http://127.0.0.1:8080/admin',
    'https://127.0.0.1/',
    'http://[::1]:8080/',
];
$public = [
    'http://1.1.1.1/', 'http://8.8.8.8/', 'http://198.51.100.30/', 'http://203.0.113.20/', 'http://192.0.2.1/',
    'http://172.15.255.255/', 'http://172.32.0.1/', 'http://100.63.255.255/', 'http://100.128.0.1/',
    'http://198.17.255.255/', 'http://198.20.0.1/', 'http://169.253.255.255/', 'http://169.255.0.1/',
    'http://[2001:4860:4860::8888]/', 'http://[2001:db8::1]/', 'http://[::ffff:1.1.1.1]/', 'http://[64:ff9b::101:101]/',
];

// Runs every URL and summarises how the requests ended. Refusals must come back
// at once; the unreachable tunnel (TunnelException) takes about the 0.05 s connect timeout.
function run(array $urls, array $options = []): string {
    global $vpn;
    $outcomes = [];
    $slow = [];
    foreach ($urls as $url) {
        $start = microtime(true);
        try {
            $vpn->request('GET', $url, $options + ['connect_timeout' => 0.05]);
            $outcomes[$url] = 'no error?';
        } catch (VPN\Exception $e) {
            $outcomes[$url] = sprintf('%s (%d)', $e::class, $e->getCode());
            if (!($e instanceof VPN\TunnelException) && microtime(true) - $start > 0.04) {
                $slow[] = $url;
            }
        }
    }
    $summary = [];
    foreach (array_count_values($outcomes) as $outcome => $count) {
        $summary[] = "$count x $outcome";
    }
    $text = implode(', ', $summary);
    if (count($summary) > 1) {
        // Something deviates: list who got which outcome.
        $text .= "\n" . print_r($outcomes, true);
    }
    return $text . ($slow ? "\n  SLOW refusals (the tunnel was used): " . implode(' ', $slow) : '');
}

echo "-- refused by default\n";
echo "restricted:    ", run($restricted), "\n";
echo "encodings:     ", run($encodings), "\n";

echo "-- public addresses go on to the tunnel\n";
echo "public:        ", run($public), "\n";

echo "-- allow_private => true goes on to the tunnel, never to a direct connection\n";
$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
$port = (int) substr(strrchr(stream_socket_get_name($listener, false), ':'), 1);
echo "restricted:    ", run($restricted, ['allow_private' => true]), "\n";
echo "encodings:     ", run($encodings, ['allow_private' => true]), "\n";
echo "local server:  ", run(["http://127.0.0.1:$port/", "https://127.0.0.1:$port/"], ['allow_private' => true]), "\n";
stream_set_blocking($listener, false);
echo 'connections accepted by the local server: ', var_export(@stream_socket_accept($listener, 0), true), "\n";
fclose($listener);

echo "-- allow_private => false\n";
echo "explicit false: ", run($restricted, ['allow_private' => false]), "\n";

echo "-- profile defaults and per-request options\n";
$permissive = VPN::wireguardFromString($conf, ['allow_private' => true]);
$strict = VPN::wireguardFromString($conf, ['allow_private' => false]);
foreach (['permissive default' => $permissive, 'strict default' => $strict] as $label => $profile) {
    foreach ([[], ['allow_private' => true], ['allow_private' => false]] as $options) {
        try {
            $profile->request('GET', 'http://10.0.0.1/', $options + ['connect_timeout' => 0.05]);
        } catch (VPN\Exception $e) {
            printf("%-19s %-30s %s\n", $label, json_encode($options), $e::class);
        }
    }
}

echo "-- php_vpn.allow_private_destinations\n";
foreach (['0', '1', '0'] as $value) {
    ini_set('php_vpn.allow_private_destinations', $value);
    echo "ini=$value: ", run(['http://10.0.0.1/', 'http://127.0.0.1/']), "\n";
}
ini_set('php_vpn.allow_private_destinations', '1');
echo "ini=1, allow_private => false: ", run(['http://10.0.0.1/'], ['allow_private' => false]), "\n";
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-051-locks';
array_map('unlink', glob("$dir/*") ?: []);
@rmdir($dir);
?>
--EXPECT--
-- refused by default
restricted:    35 x VPN\PolicyException (9)
encodings:     11 x VPN\PolicyException (9)
-- public addresses go on to the tunnel
public:        17 x VPN\TunnelException (3)
-- allow_private => true goes on to the tunnel, never to a direct connection
restricted:    35 x VPN\TunnelException (3)
encodings:     11 x VPN\TunnelException (3)
local server:  2 x VPN\TunnelException (3)
connections accepted by the local server: false
-- allow_private => false
explicit false: 35 x VPN\PolicyException (9)
-- profile defaults and per-request options
permissive default  []                             VPN\TunnelException
permissive default  {"allow_private":true}         VPN\TunnelException
permissive default  {"allow_private":false}        VPN\PolicyException
strict default      []                             VPN\PolicyException
strict default      {"allow_private":true}         VPN\TunnelException
strict default      {"allow_private":false}        VPN\PolicyException
-- php_vpn.allow_private_destinations
ini=0: 2 x VPN\PolicyException (9)
ini=1: 2 x VPN\TunnelException (3)
ini=0: 2 x VPN\PolicyException (9)
ini=1, allow_private => false: 1 x VPN\PolicyException (9)
