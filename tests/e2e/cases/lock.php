<?php
// Lock wait limit: another process holds the profile.
require __DIR__ . '/lib.php';
expect_exception('profile busy in another process -> LockTimeoutException after connect_timeout', fn () => vpn('client1')->request('GET', 'http://echo.lab.test/ip', ['connect_timeout' => 1]), VPN\LockTimeoutException::class, 1.6);
