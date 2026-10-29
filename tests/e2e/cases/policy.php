<?php
require __DIR__ . '/lib.php';
$vpn = vpn();

expect_exception('private IP refused before any handshake', fn () => $vpn->request('GET', 'http://10.13.13.1/'), VPN\PolicyException::class, 0.5);
expect_exception('metadata IP refused', fn () => $vpn->request('GET', 'http://169.254.169.254/latest/meta-data/'), VPN\PolicyException::class, 0.5);
$to = urlencode('http://10.13.13.1/');
expect_exception('redirect to a private address refused', fn () => $vpn->request('GET', "http://echo.lab.test/redirect?code=302&to=$to"), VPN\PolicyException::class);
$to = urlencode('http://echo.lab.test/ip');
expect_exception('HTTPS to HTTP redirect refused', fn () => $vpn->request('GET', "https://echo.lab.test/redirect?code=302&to=$to"), VPN\PolicyException::class);
$r = $vpn->request('GET', "https://echo.lab.test/redirect?code=302&to=$to", ['allow_https_downgrade' => true]);
check('allow_https_downgrade permits it', $r->body() === '198.51.100.10');
expect_exception('allow_private reaches the private address inside the tunnel (nothing listens: connect error)', fn () => $vpn->request('GET', 'http://10.13.13.1:81/', ['allow_private' => true, 'connect_timeout' => 3]), VPN\ConnectException::class, 4);
expect_exception('profile without DNS refuses host names', fn () => vpn('client-nodns')->request('GET', 'http://echo.lab.test/ip'), VPN\DnsException::class, 1);
check('profile without DNS works with IP literals', vpn('client-nodns')->request('GET', 'http://198.51.100.30/ip')->body() === '198.51.100.10');
expect_exception('unknown name through the tunnel DNS', fn () => $vpn->request('GET', 'http://does-not-exist.lab.test/'), VPN\DnsException::class, 6);
