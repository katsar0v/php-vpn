--TEST--
php-vpn: VPN::pool() validates its members, its size and its options
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-060-' . bin2hex(random_bytes(6));
mkdir($dir, 0700);

function conf(?string $private = null, ?string $peer = null, string $address = '10.13.13.2/32'): string {
    return "[Interface]\nPrivateKey = " . ($private ?? base64_encode(random_bytes(32))) . "\nAddress = $address\n"
         . "[Peer]\nPublicKey = " . ($peer ?? base64_encode(random_bytes(32))) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
}

function profile(?string $private = null, ?string $peer = null, string $address = '10.13.13.2/32'): VPN {
    return VPN::wireguardFromString(conf($private, $peer, $address));
}

function attempt(string $label, callable $fn): void {
    global $dir;
    try {
        $result = $fn();
        $info = $result->info();
        $text = 'pool of ' . (isset($info['endpoint']) ? 1 : count($info));
    } catch (Throwable $e) {
        $text = get_class($e) . ($e->getCode() ? ' (' . $e->getCode() . ')' : '') . ': ' . str_replace($dir, '{DIR}', $e->getMessage());
    }
    printf("%-34s %s\n", $label, $text);
}

echo "-- size\n";
attempt('empty', fn() => VPN::pool([]));
attempt('one member', fn() => VPN::pool([profile()]));
attempt('2 members', fn() => VPN::pool([profile(), profile()]));
attempt('64 members', fn() => VPN::pool(array_map(fn() => profile(), range(1, 64))));
attempt('65 members', fn() => VPN::pool(array_map(fn() => profile(), range(1, 65))));
attempt('65 unchecked junk entries', fn() => VPN::pool(array_fill(0, 65, 'x')));
attempt('1000 junk entries', fn() => VPN::pool(array_fill(0, 1000, 5)));
attempt('pools count their members', fn() => VPN::pool([
    VPN::pool(array_map(fn() => profile(), range(1, 40))),
    VPN::pool(array_map(fn() => profile(), range(1, 40))),
]));

echo "-- the same key pair twice\n";
$a = profile();
attempt('same object twice', fn() => VPN::pool([$a, $a]));
$private = base64_encode(random_bytes(32));
$peer = base64_encode(random_bytes(32));
attempt('same profile text twice', fn() => VPN::pool([profile($private, $peer), profile($private, $peer)]));
attempt('same keys, other address', fn() => VPN::pool([profile($private, $peer), profile($private, $peer, '10.13.13.9/32')]));
attempt('same object, inside a pool', fn() => VPN::pool([VPN::pool([$a, profile()]), $a]));
file_put_contents("$dir/same.conf", conf($private, $peer));
chmod("$dir/same.conf", 0600);
attempt('profile and its file', fn() => VPN::pool([profile($private, $peer), "$dir/same.conf"]));
attempt('file twice', fn() => VPN::pool(["$dir/same.conf", "$dir/same.conf"]));
attempt('same private key, other peer', fn() => VPN::pool([profile($private, $peer), profile($private)]));
attempt('other private key, same peer', fn() => VPN::pool([profile($private, $peer), profile(null, $peer)]));

echo "-- member types\n";
attempt('int', fn() => VPN::pool([profile(), 5]));
attempt('float', fn() => VPN::pool([1.5]));
attempt('null', fn() => VPN::pool([null]));
attempt('bool', fn() => VPN::pool([true]));
attempt('nested array', fn() => VPN::pool([[profile()]]));
attempt('stdClass', fn() => VPN::pool([new stdClass()]));
attempt('closure', fn() => VPN::pool([fn() => 1]));
attempt('exception object', fn() => VPN::pool([new VPN\ConfigException()]));

echo "-- member paths\n";
attempt('missing file', fn() => VPN::pool([profile(), "$dir/missing.conf"]));
attempt('empty string', fn() => VPN::pool(['']));
attempt('NUL byte in a path', fn() => VPN::pool(["$dir/a\0b.conf"]));
attempt('directory', fn() => VPN::pool([$dir]));
file_put_contents("$dir/bad.conf", str_replace('Address', 'Adress', conf()));
chmod("$dir/bad.conf", 0600);
attempt('invalid profile file', fn() => VPN::pool([profile(), "$dir/bad.conf"]));
file_put_contents("$dir/open.conf", conf());
chmod("$dir/open.conf", 0644);
attempt('file readable by others', fn() => VPN::pool(["$dir/open.conf"]));

echo "-- argument types and options\n";
attempt('profiles is not an array', fn() => VPN::pool('profile.conf'));
attempt('profiles is a VPN', fn() => VPN::pool($a));
attempt('options is not an array', fn() => VPN::pool([profile()], 'timeout'));
attempt('unknown option', fn() => VPN::pool([profile(), profile()], ['bogus' => 1]));
attempt('invalid option value', fn() => VPN::pool([profile(), profile()], ['timeout' => 0]));
attempt('valid options', fn() => VPN::pool([profile(), profile()], ['timeout' => 5, 'headers' => ['X-A' => '1']]));
attempt('string keys are fine', fn() => VPN::pool(['de' => profile(), 'nl' => profile()]));
attempt('sparse keys are fine', fn() => VPN::pool([3 => profile(), 17 => profile()]));
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-060-*') ?: [] as $dir) {
    array_map('unlink', glob("$dir/*") ?: []);
    @rmdir($dir);
}
?>
--EXPECT--
-- size
empty                              VPN\ConfigException (2): a pool needs between 1 and 64 profiles
one member                         pool of 1
2 members                          pool of 2
64 members                         pool of 64
65 members                         VPN\ConfigException (2): a pool needs between 1 and 64 profiles
65 unchecked junk entries          VPN\ConfigException (2): a pool needs between 1 and 64 profiles
1000 junk entries                  VPN\ConfigException (2): a pool needs between 1 and 64 profiles
pools count their members          VPN\ConfigException (2): a pool can hold at most 64 profiles
-- the same key pair twice
same object twice                  VPN\ConfigException (2): a pool contains the same WireGuard key twice; each member needs its own key pair
same profile text twice            VPN\ConfigException (2): a pool contains the same WireGuard key twice; each member needs its own key pair
same keys, other address           VPN\ConfigException (2): a pool contains the same WireGuard key twice; each member needs its own key pair
same object, inside a pool         VPN\ConfigException (2): a pool contains the same WireGuard key twice; each member needs its own key pair
profile and its file               VPN\ConfigException (2): a pool contains the same WireGuard key twice; each member needs its own key pair
file twice                         VPN\ConfigException (2): a pool contains the same WireGuard key twice; each member needs its own key pair
same private key, other peer       pool of 2
other private key, same peer       pool of 2
-- member types
int                                VPN\ConfigException (2): pool members must be VPN objects or profile paths, int given
float                              VPN\ConfigException (2): pool members must be VPN objects or profile paths, float given
null                               VPN\ConfigException (2): pool members must be VPN objects or profile paths, null given
bool                               VPN\ConfigException (2): pool members must be VPN objects or profile paths, bool given
nested array                       VPN\ConfigException (2): pool members must be VPN objects or profile paths, array given
stdClass                           VPN\ConfigException (2): pool members must be VPN objects or profile paths, stdClass given
closure                            VPN\ConfigException (2): pool members must be VPN objects or profile paths, Closure given
exception object                   VPN\ConfigException (2): pool members must be VPN objects or profile paths, VPN\ConfigException given
-- member paths
missing file                       VPN\ConfigException (2): WireGuard profile `{DIR}/missing.conf` cannot be opened: No such file or directory
empty string                       VPN\ConfigException (2): WireGuard profile path must be a non-empty string without NUL bytes
NUL byte in a path                 VPN\ConfigException (2): WireGuard profile path must be a non-empty string without NUL bytes
directory                          VPN\ConfigException (2): WireGuard profile `{DIR}` is not a regular file
invalid profile file               VPN\ConfigException (2): WireGuard profile, line 3: unsupported [Interface] key `adress`
file readable by others            VPN\ConfigException (2): WireGuard profile `{DIR}/open.conf` is accessible by all users (mode 0644); it contains a private key, so run `chmod o-rwx` on it (or disable php_vpn.enforce_key_permissions)
-- argument types and options
profiles is not an array           TypeError: VPN::pool(): Argument #1 ($profiles) must be of type array, string given
profiles is a VPN                  TypeError: VPN::pool(): Argument #1 ($profiles) must be of type array, VPN given
options is not an array            TypeError: VPN::pool(): Argument #2 ($options) must be of type array, string given
unknown option                     VPN\ConfigException (2): unknown option `bogus`
invalid option value               VPN\ConfigException (2): option `timeout` must be greater than 0 and at most 86400
valid options                      pool of 2
string keys are fine               pool of 2
sparse keys are fine               pool of 2
