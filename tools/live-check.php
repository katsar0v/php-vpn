<?php
// Live check against a real WireGuard provider.
//   php -d extension=php-vpn.so tools/live-check.php PROFILE [URL ...]
// Compares the exit IP through the VPN with the direct one, then fetches each
// URL through the VPN (one request each) and prints status, size and time.

if (!extension_loaded('vpn')) {
    fwrite(STDERR, "php-vpn is not loaded\n");
    exit(2);
}
$profile = $argv[1] ?? '';
$urls = array_slice($argv, 2);
$ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
$failed = false;

function line(bool $ok, string $text): void
{
    global $failed;
    $failed = $failed || !$ok;
    printf("%s  %s\n", $ok ? 'PASS' : 'FAIL', $text);
}

printf("PHP %s %s, php-vpn %s\n", PHP_VERSION, PHP_SAPI, phpversion('vpn'));
$vpn = VPN::wireguard($profile, ['timeout' => 30, 'connect_timeout' => 15, 'headers' => ['User-Agent' => $ua]]);

$t = microtime(true);
try {
    $viaVpn = trim($vpn->request('GET', 'https://api.ipify.org')->body());
} catch (VPN\Exception $e) {
    $viaVpn = '';
    line(false, sprintf('VPN request to api.ipify.org: %s: %s', get_class($e), $e->getMessage()));
}
$vpnMs = (microtime(true) - $t) * 1000;
$direct = trim((string) @file_get_contents('https://api.ipify.org'));

if ($viaVpn !== '') {
    line(filter_var($viaVpn, FILTER_VALIDATE_IP) !== false, sprintf('exit IP through the VPN: %s (%.0f ms incl. handshake)', $viaVpn, $vpnMs));
}
line(filter_var($direct, FILTER_VALIDATE_IP) !== false, "direct exit IP (same script): $direct");
if ($viaVpn !== '' && $direct !== '') {
    line($viaVpn !== $direct, 'VPN and direct requests leave from different IPs');
}

$t = microtime(true);
try {
    $again = trim($vpn->request('GET', 'https://api.ipify.org')->body());
    line($again === $viaVpn, sprintf('second request reuses the session (%.0f ms)', (microtime(true) - $t) * 1000));
} catch (VPN\Exception $e) {
    line(false, 'second request: ' . $e->getMessage());
}

foreach ($urls as $url) {
    $t = microtime(true);
    try {
        $r = $vpn->request('GET', $url, ['headers' => ['Accept-Language' => 'bg,en;q=0.8']]);
        line($r->status() < 400, sprintf('%s -> HTTP %d, %d bytes, %.0f ms, final URL %s', $url, $r->status(), strlen($r->body()), (microtime(true) - $t) * 1000, $r->effectiveUrl()));
    } catch (VPN\Exception $e) {
        line(false, sprintf('%s -> %s: %s', $url, get_class($e), $e->getMessage()));
    }
}

$info = $vpn->info();
printf("profile: endpoint %s, address %s, DNS %s, session age %s s\n", $info['endpoint'], implode(',', $info['addresses']), implode(',', $info['dns']), var_export($info['session_age'], true));
exit($failed ? 1 : 0);
