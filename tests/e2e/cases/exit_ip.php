<?php
// AC2: the VPN request exits from the WireGuard server, a direct request in
// the same script from this container.
require __DIR__ . '/lib.php';
$selfIp = $argv[1] ?? '198.51.100.40';

$vpn = vpn();
$via = $vpn->request('GET', 'http://echo.lab.test/ip')->body();
$direct = file_get_contents('http://echo.lab.test/ip');
$viaAgain = $vpn->request('GET', 'http://echo.lab.test/ip')->body();
check('VPN request exits from the WireGuard server (198.51.100.10)', $via === '198.51.100.10', $via);
check("direct file_get_contents in the same script exits from $selfIp", $direct === $selfIp, (string) $direct);
check('a later VPN request in the same script still uses the tunnel', $viaAgain === '198.51.100.10', $viaAgain);
