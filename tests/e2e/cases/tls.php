<?php
require __DIR__ . '/lib.php';
$vpn = vpn();

$r = $vpn->request('GET', 'https://echo.lab.test/ip');
check('HTTPS with the lab CA (ca_file)', $r->status() === 200 && $r->body() === '198.51.100.10', $r->body());
expect_exception('certificate for another host name', fn () => $vpn->request('GET', 'https://echo.lab.test:8443/ip'), VPN\TlsException::class);
expect_exception('self-signed certificate', fn () => $vpn->request('GET', 'https://echo.lab.test:9443/ip'), VPN\TlsException::class);
expect_exception('lab certificate without the lab CA (bundled roots)', fn () => VPN::wireguard('/etc/php-vpn/client1.conf')->request('GET', 'https://echo.lab.test/ip'), VPN\TlsException::class);
$r = $vpn->request('GET', 'https://echo.lab.test:9443/ip', ['verify_tls' => false]);
check('verify_tls=false accepts the self-signed certificate', $r->status() === 200);
