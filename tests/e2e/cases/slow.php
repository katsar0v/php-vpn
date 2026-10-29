<?php
// php slow.php CLIENT[,CLIENT...] MS [REPEAT]: requests /slow and prints one line each.
require __DIR__ . '/lib.php';
$clients = explode(',', $argv[1]);
$ms = (int) $argv[2];
$repeat = (int) ($argv[3] ?? 1);

$vpn = count($clients) > 1
    ? VPN::pool(array_map(fn ($c) => "/etc/php-vpn/$c.conf", $clients))
    : vpn($clients[0]);
for ($i = 0; $i < $repeat; $i++) {
    [$e, $r, $s] = attempt(fn () => $vpn->request('GET', "http://echo.lab.test/slow?ms=$ms", ['connect_timeout' => 30, 'timeout' => 60]));
    check(sprintf('pid %d request %d via %s (%.2f s)', getmypid(), $i + 1, $argv[1], $s), $e === null && $r->status() === 200, $e ? get_class($e) . ': ' . $e->getMessage() : '');
}
