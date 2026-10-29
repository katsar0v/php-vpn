--TEST--
php-vpn: a profile held by another process makes request() wait, then throw LockTimeoutException; pools use a free member
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--INI--
php_vpn.lock_dir={TMP}/php-vpn-phpt-084
--FILE--
<?php
$lockDir = ini_get('php_vpn.lock_dir');
mkdir($lockDir, 0700);

function profile(): VPN {
    return VPN::wireguardFromString("[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
        . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n");
}

// Sends a request through the unreachable tunnel and says how it ended.
function send(VPN $vpn, float $connectTimeout = 0.3): string {
    $start = microtime(true);
    try {
        $vpn->request('GET', 'http://198.51.100.30/', ['connect_timeout' => $connectTimeout]);
        return 'no exception?';
    } catch (VPN\Exception $e) {
        $elapsed = microtime(true) - $start;
        // A busy profile is waited for until the connect timeout runs out; a dead tunnel may fail earlier.
        $waited = $e instanceof VPN\LockTimeoutException
            ? ($elapsed >= $connectTimeout - 0.05 && $elapsed < $connectTimeout + 1.5 ? ' after waiting for the timeout' : sprintf(' after %.2f s', $elapsed))
            : '';
        return sprintf('%s (%d)%s', $e::class, $e->getCode(), $waited);
    }
}

// Which lock file belongs to a profile: the one its first request creates.
function lock_file_of(VPN $vpn): string {
    global $lockDir;
    $before = glob("$lockDir/*");
    send($vpn, 0.05);
    $new = array_values(array_diff(glob("$lockDir/*"), $before));
    return $new[0];
}

// Takes the lock the way another PHP process would.
function hold(string $file) {
    $handle = fopen($file, 'c+');
    if (!flock($handle, LOCK_EX | LOCK_NB)) {
        throw new Exception('could not take the lock');
    }
    return $handle;
}

$a = profile();
$b = profile();
$fileA = lock_file_of($a);
$fileB = lock_file_of($b);
var_dump($fileA !== $fileB);

echo "-- nobody holds the lock\n";
echo send($a), "\n";

echo "-- another process holds the lock of a single profile\n";
$held = hold($fileA);
echo send($a), "\n";
try {
    $a->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 0.2]);
} catch (VPN\LockTimeoutException $e) {
    echo $e->getMessage(), "\n";
    var_dump($e instanceof VPN\Exception);
}
echo "-- profile b is not affected\n";
echo send($b), "\n";
echo "-- released\n";
fclose($held);
echo send($a), "\n";

echo "-- pool: one member busy, the other one is used\n";
$pool = VPN::pool([$a, $b]);
$held = hold($fileA);
foreach (range(1, 4) as $i) {
    echo send($pool), "\n";
}
fclose($held);

echo "-- pool: all members busy\n";
$heldA = hold($fileA);
$heldB = hold($fileB);
echo send($pool), "\n";
try {
    $pool->request('GET', 'http://198.51.100.30/', ['connect_timeout' => 0.2]);
} catch (VPN\LockTimeoutException $e) {
    echo $e->getMessage(), "\n";
}
fclose($heldA);
fclose($heldB);

echo "-- the lock is released when a request fails\n";
echo send($pool), "\n";
$probe = fopen($fileA, 'c+');
var_dump(flock($probe, LOCK_EX | LOCK_NB));
flock($probe, LOCK_UN);
fclose($probe);
$probe = fopen($fileB, 'c+');
var_dump(flock($probe, LOCK_EX | LOCK_NB));
?>
--CLEAN--
<?php
$dir = sys_get_temp_dir() . '/php-vpn-phpt-084';
foreach (glob("$dir/*") ?: [] as $file) {
    @unlink($file);
}
@rmdir($dir);
?>
--EXPECT--
bool(true)
-- nobody holds the lock
VPN\TunnelException (3)
-- another process holds the lock of a single profile
VPN\LockTimeoutException (11) after waiting for the timeout
the WireGuard profile is in use by another PHP process and did not become free within the connect timeout
bool(true)
-- profile b is not affected
VPN\TunnelException (3)
-- released
VPN\TunnelException (3)
-- pool: one member busy, the other one is used
VPN\TunnelException (3)
VPN\TunnelException (3)
VPN\TunnelException (3)
VPN\TunnelException (3)
-- pool: all members busy
VPN\LockTimeoutException (11) after waiting for the timeout
all 2 WireGuard profiles of the pool are in use by other PHP processes and none became free within the connect timeout
-- the lock is released when a request fails
VPN\TunnelException (3)
bool(true)
bool(true)
