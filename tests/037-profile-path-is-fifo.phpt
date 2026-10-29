--TEST--
php-vpn: a FIFO given as profile path is refused instead of blocking forever
--SKIPIF--
<?php
if (!extension_loaded('vpn')) die('skip vpn extension not loaded');
if (!function_exists('posix_mkfifo') || !function_exists('proc_open')) die('skip needs posix_mkfifo() and proc_open()');
$ext = null;
foreach (@file('/proc/self/maps') ?: [] as $line) {
    if (preg_match('~\s(/\S*php-vpn\S*\.so)\s*$~', $line, $m)) {
        $ext = $m[1];
        break;
    }
}
if ($ext === null) die('skip cannot tell where the extension was loaded from');
?>
--FILE--
<?php
$ext = null;
foreach (file('/proc/self/maps') as $line) {
    if (preg_match('~\s(/\S*php-vpn\S*\.so)\s*$~', $line, $m)) {
        $ext = $m[1];
        break;
    }
}
$fifo = sys_get_temp_dir() . '/php-vpn-phpt-037-' . bin2hex(random_bytes(6));
posix_mkfifo($fifo, 0600);

// The call runs in a child process so that a hang cannot stall the test run.
$code = 'try { VPN::wireguard($argv[1]); echo "loaded"; } catch (Throwable $e) { echo get_class($e), ": ", $e->getMessage(); }';
$process = proc_open([PHP_BINARY, '-d', "extension=$ext", '-r', $code, $fifo], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
$deadline = microtime(true) + 3;
while (proc_get_status($process)['running'] && microtime(true) < $deadline) {
    usleep(20000);
}
if (proc_get_status($process)['running']) {
    proc_terminate($process, 9);
    echo "HUNG: still blocked in open() after 3 s\n";
} else {
    echo str_replace($fifo, '{FIFO}', stream_get_contents($pipes[1])), "\n";
}
proc_close($process);
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-037-*') ?: [] as $fifo) {
    @unlink($fifo);
}
?>
--EXPECT--
VPN\ConfigException: WireGuard profile `{FIFO}` is not a regular file
