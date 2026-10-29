<?php
// HTTP semantics through the tunnel.
require __DIR__ . '/lib.php';
$vpn = vpn();

foreach (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as $m) {
    $e = echo_json($vpn, $m, 'http://echo.lab.test/echo?q=1', $m === 'GET' ? [] : ['body' => "body-$m"]);
    check("$m reaches the server with method, query and body", ($e['method'] ?? '') === $m && ($e['query'] ?? '') === 'q=1' && ($m === 'GET' || ($e['body'] ?? '') === "body-$m"), json_encode($e));
}
$r = $vpn->request('HEAD', 'http://echo.lab.test/bytes?n=1000');
check('HEAD returns headers and an empty body', $r->status() === 200 && $r->body() === '' && $r->header('content-length') === '1000', $r->status() . ' ' . strlen($r->body()));

$e = echo_json($vpn, 'GET', 'http://echo.lab.test/echo', ['headers' => ['X-Multi' => ['a', 'b'], 'X-Single: one', 'User-Agent' => 'lab-agent']]);
check('multi-value and "Name: value" request headers', header_values($e, 'x-multi') === ['a', 'b'] && header_values($e, 'x-single') === ['one'], json_encode($e['headers'] ?? null));
check('caller User-Agent replaces the default', header_values($e, 'user-agent') === ['lab-agent']);
$e = echo_json(vpn('client1', ['headers' => ['X-Default' => 'd', 'X-Over' => 'default']]), 'GET', 'http://echo.lab.test/echo', ['headers' => ['X-Over' => 'request']]);
check('default headers merge, request headers win', header_values($e, 'x-default') === ['d'] && header_values($e, 'x-over') === ['request'], json_encode($e['headers'] ?? null));

$r = $vpn->request('GET', 'http://echo.lab.test/headers-multi');
check('repeated response headers are kept as a list', count($r->headers()['set-cookie'] ?? []) === 2, json_encode($r->headers()));
$r = $vpn->request('GET', 'http://echo.lab.test/status/418');
check('non-2xx statuses are returned, not thrown', $r->status() === 418);

$r = $vpn->request('GET', 'http://echo.lab.test/chunked?chunks=50&size=1000');
check('chunked transfer encoding', strlen($r->body()) === 50000, (string) strlen($r->body()));
$r = $vpn->request('GET', 'http://echo.lab.test/gzip');
check('gzip responses are decoded', str_contains($r->body(), 'hello from echo'), substr($r->body(), 0, 40));
$r = $vpn->request('GET', 'http://echo.lab.test/gzip', ['decode_content' => false]);
check('decode_content=false returns the raw body', substr($r->body(), 0, 2) === "\x1f\x8b");
$r = $vpn->request('GET', 'http://echo.lab.test/bytes?n=3000000');
check('3 MB body arrives complete', strlen($r->body()) === 3000000, (string) strlen($r->body()));

expect_exception('response larger than max_response_size', fn () => $vpn->request('GET', 'http://echo.lab.test/bytes?n=200000', ['max_response_size' => 100000]), VPN\LimitException::class);
expect_exception('gzip bomb stops at max_response_size', fn () => $vpn->request('GET', 'http://echo.lab.test/gzip-bomb?mb=20', ['max_response_size' => 1 << 20]), VPN\LimitException::class);

// Redirects
$r = $vpn->request('GET', 'http://echo.lab.test/redirect-chain?n=3');
check('redirects are followed', $r->status() === 200 && $r->redirectCount() === 3 && $r->effectiveUrl() === 'http://echo.lab.test/ip', $r->effectiveUrl() . ' ' . $r->redirectCount());
$r = $vpn->request('GET', 'http://echo.lab.test/redirect-chain?n=3', ['follow_redirects' => false]);
check('follow_redirects=false returns the 3xx', $r->status() >= 300 && $r->status() < 400 && $r->header('location') !== null, (string) $r->status());
expect_exception('redirect limit', fn () => $vpn->request('GET', 'http://echo.lab.test/redirect-chain?n=4', ['follow_redirects' => 2]), VPN\LimitException::class);
foreach ([301 => 'GET', 302 => 'GET', 303 => 'GET', 307 => 'POST', 308 => 'POST'] as $code => $method) {
    $to = urlencode('http://echo.lab.test/echo');
    $e = echo_json($vpn, 'POST', "http://echo.lab.test/redirect?code=$code&to=$to", ['body' => 'data']);
    $bodyKept = ($e['body'] ?? '') === 'data';
    check("POST + $code redirect continues as $method", ($e['method'] ?? '') === $method && ($method === 'POST') === $bodyKept, json_encode([$e['method'] ?? null, $e['body'] ?? null]));
}
$to = urlencode('http://198.51.100.30/echo');
$e = echo_json($vpn, 'GET', "http://echo.lab.test/redirect?code=302&to=$to", ['headers' => ['Authorization' => 'Bearer secret', 'Cookie' => 'a=b', 'X-Keep' => 'y']]);
check('credentials are dropped on a cross-origin redirect', header_values($e, 'authorization') === [] && header_values($e, 'cookie') === [] && header_values($e, 'x-keep') === ['y'], json_encode($e['headers'] ?? null));

// Timeouts
expect_exception('total timeout on a stalled server', fn () => $vpn->request('GET', 'http://echo.lab.test/stall', ['timeout' => 1.5]), VPN\TimeoutException::class, 2.5);
expect_exception('total timeout on a slow server', fn () => $vpn->request('GET', 'http://echo.lab.test/slow?ms=3000', ['timeout' => 1]), VPN\TimeoutException::class, 2.0);
expect_exception('connect timeout to a silent address inside the tunnel', fn () => $vpn->request('GET', 'http://203.0.113.99/', ['connect_timeout' => 1.5, 'timeout' => 5]), VPN\ConnectException::class, 2.5);
