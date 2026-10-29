<?php
// php -d extension=php-vpn.so examples/basic.php /etc/php-vpn/surfshark-de.conf

$vpn = VPN::wireguard($argv[1] ?? '/etc/php-vpn/surfshark-de.conf', [
    'timeout' => 20,
    'headers' => ['User-Agent' => 'Mozilla/5.0 (compatible; example)'],
]);

try {
    $response = $vpn->request('GET', 'https://api.ipify.org?format=json');
    printf("via VPN:  %s (HTTP %d)\n", $response->body(), $response->status());
} catch (VPN\Exception $e) {
    // Fail closed: nothing was sent outside the tunnel.
    printf("VPN request failed: %s: %s\n", get_class($e), $e->getMessage());
}

printf("direct:   %s\n", @file_get_contents('https://api.ipify.org?format=json') ?: 'n/a');
print_r($vpn->info());
