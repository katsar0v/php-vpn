--TEST--
php-vpn: pools mix VPN objects and profile paths; info() is a list for pools and a flat array for one profile
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-061-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);

$privates = [];
function conf(string $endpoint): string {
    global $privates;
    $privates[] = $private = base64_encode(random_bytes(32));
    return "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\nDNS = 10.13.13.1\n"
         . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = $endpoint\n";
}
function is_list(array $a): bool {
    return $a === array_values($a);
}

echo "-- a single profile is described by a flat array\n";
$single = VPN::wireguardFromString(conf('127.0.0.1:9001'));
$info = $single->info();
var_dump(isset($info['endpoint']), is_list($info));
var_dump($info['endpoint']);

echo "-- a pool of objects\n";
$a = VPN::wireguardFromString(conf('127.0.0.1:9101'));
$b = VPN::wireguardFromString(conf('127.0.0.1:9102'));
$pool = VPN::pool([$a, $b]);
$info = $pool->info();
var_dump(is_list($info), count($info));
var_dump(array_column($info, 'endpoint'));
var_dump(array_keys($info[0]) === array_keys($single->info()));
var_dump($info[0]['public_key'] === $a->info()['public_key'], $info[1]['public_key'] === $b->info()['public_key']);
var_dump($info[0]['public_key'] !== $info[1]['public_key']);
var_dump(array_column($info, 'session_age'));

echo "-- a pool of paths and objects, in order\n";
file_put_contents("$dir/first.conf", conf('127.0.0.1:9201'));
chmod("$dir/first.conf", 0640);
file_put_contents("$dir/second.conf", conf('127.0.0.1:9202'));
chmod("$dir/second.conf", 0600);
$mixed = VPN::pool(["$dir/first.conf", $a, "$dir/second.conf", $b]);
var_dump(array_column($mixed->info(), 'endpoint'));

echo "-- pools of pools are flattened\n";
$c = VPN::wireguardFromString(conf('127.0.0.1:9301'));
$nested = VPN::pool([$pool, $c, VPN::pool(["$dir/first.conf", "$dir/second.conf"])]);
var_dump(array_column($nested->info(), 'endpoint'));

echo "-- members stay independent of the pool\n";
var_dump(count($a->info()) === count($single->info()));
var_dump(isset($a->info()['endpoint']));
$pool->close();
var_dump(count($pool->info()));
unset($pool);
var_dump($a->info()['endpoint']);

echo "-- options given to the pool do not change its members\n";
$configured = VPN::pool([$a, $b], ['headers' => ['X-Pool' => '1'], 'timeout' => 7]);
var_dump(count($configured->info()));

echo "-- no private key anywhere in the descriptions\n";
$dump = print_r([$single->info(), $mixed->info(), $nested->info()], true);
foreach ($privates as $private) {
    if (str_contains($dump, $private)) {
        echo "LEAK\n";
    }
}
echo "done\n";
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-061-*') ?: [] as $dir) {
    array_map('unlink', glob("$dir/*") ?: []);
    @rmdir($dir);
}
?>
--EXPECT--
-- a single profile is described by a flat array
bool(true)
bool(false)
string(14) "127.0.0.1:9001"
-- a pool of objects
bool(true)
int(2)
array(2) {
  [0]=>
  string(14) "127.0.0.1:9101"
  [1]=>
  string(14) "127.0.0.1:9102"
}
bool(true)
bool(true)
bool(true)
bool(true)
array(2) {
  [0]=>
  NULL
  [1]=>
  NULL
}
-- a pool of paths and objects, in order
array(4) {
  [0]=>
  string(14) "127.0.0.1:9201"
  [1]=>
  string(14) "127.0.0.1:9101"
  [2]=>
  string(14) "127.0.0.1:9202"
  [3]=>
  string(14) "127.0.0.1:9102"
}
-- pools of pools are flattened
array(5) {
  [0]=>
  string(14) "127.0.0.1:9101"
  [1]=>
  string(14) "127.0.0.1:9102"
  [2]=>
  string(14) "127.0.0.1:9301"
  [3]=>
  string(14) "127.0.0.1:9201"
  [4]=>
  string(14) "127.0.0.1:9202"
}
-- members stay independent of the pool
bool(true)
bool(true)
int(2)
string(14) "127.0.0.1:9101"
-- options given to the pool do not change its members
int(2)
-- no private key anywhere in the descriptions
done
