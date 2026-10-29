<?php
// Only VPN traffic: run.sh captures packets and DNS logs around this script.
require __DIR__ . '/lib.php';

$vpn = vpn();
$r = $vpn->request('GET', 'https://secret.vpn.test/ip');
check('VPN-only host secret.vpn.test over HTTPS (tunnel DNS + lab CA)', $r->status() === 200 && $r->body() === '203.0.113.10', $r->status() . ' ' . $r->body());
$r = $vpn->request('GET', 'http://echo.lab.test/ip');
check('echo.lab.test over HTTP through the tunnel', $r->body() === '198.51.100.10', $r->body());
$r = $vpn->request('POST', 'https://echo.lab.test/echo', ['body' => 'payload']);
check('echo.lab.test over HTTPS POST through the tunnel', $r->status() === 200, (string) $r->status());
