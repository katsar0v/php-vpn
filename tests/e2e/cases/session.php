<?php
// Session reuse inside one process, fork safety and memory stability.
require __DIR__ . '/lib.php';
$vpn = vpn();

[, , $first] = attempt(fn () => $vpn->request('GET', 'http://echo.lab.test/ip'));
[, , $second] = attempt(fn () => $vpn->request('GET', 'http://echo.lab.test/ip'));
$age = $vpn->info()['session_age'];
check(sprintf('second request reuses the session (%.0f ms then %.0f ms)', $first * 1000, $second * 1000), is_float($age) && $age > 0 && $second < 0.5);
$same = vpn();
[, , $third] = attempt(fn () => $same->request('GET', 'http://echo.lab.test/ip'));
check('another VPN object for the same profile shares the tunnel', $third < 0.5 && is_float($same->info()['session_age']));
$vpn->close();
check('close() drops the session', $vpn->info()['session_age'] === null);

if (function_exists('pcntl_fork')) {
    $vpn->request('GET', 'http://echo.lab.test/ip');
    $pid = pcntl_fork();
    if ($pid === 0) {
        [$e, $r] = attempt(fn () => $vpn->request('GET', 'http://echo.lab.test/ip'));
        exit($e === null && $r->body() === '198.51.100.10' ? 0 : 1);
    }
    pcntl_waitpid($pid, $status);
    check('a forked child gets its own tunnel', pcntl_wexitstatus($status) === 0);
    check('the parent keeps working after the fork', $vpn->request('GET', 'http://echo.lab.test/ip')->body() === '198.51.100.10');
}

$n = (int) ($argv[1] ?? 500);
for ($i = 0; $i < 50; $i++) {
    $vpn->request('GET', 'http://echo.lab.test/bytes?n=20000');
}
$before = rss_kb();
$t = microtime(true);
for ($i = 0; $i < $n; $i++) {
    $vpn->request('GET', 'http://echo.lab.test/bytes?n=20000');
}
$growth = rss_kb() - $before;
check(sprintf('%d requests (%.1f ms each): RSS grew %d KB', $n, (microtime(true) - $t) * 1000 / $n, $growth), $growth < 4096);
