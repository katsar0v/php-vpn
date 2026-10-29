<?php
// Lab smoke page: one request through the VPN and one direct, side by side.
$conf = getenv('LAB_VPN_CONF') ?: ($_GET['conf'] ?? '/etc/php-vpn/client1.conf');
$vpn = VPN::wireguard($conf);
$started = microtime(true);
$viaVpn = $vpn->request('GET', 'http://echo.lab.test/ip')->body();
$ms = (int) round((microtime(true) - $started) * 1000);
$direct = file_get_contents('http://echo.lab.test/ip');
header('Content-Type: text/plain');
printf("vpn=%s direct=%s ms=%d pid=%d sapi=%s\n", $viaVpn, $direct, $ms, getmypid(), PHP_SAPI);
