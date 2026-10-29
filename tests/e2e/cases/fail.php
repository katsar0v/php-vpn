<?php
// php fail.php CLIENT URL EXPECTED_CLASS CONNECT_TIMEOUT TIMEOUT MAX_SECONDS
require __DIR__ . '/lib.php';
[, $client, $url, $class, $connect, $timeout, $max] = $argv;

expect_exception(
    "$client $url fails with $class (no fallback)",
    fn () => vpn($client)->request('GET', $url, ['connect_timeout' => (float) $connect, 'timeout' => (float) $timeout]),
    $class,
    (float) $max
);
