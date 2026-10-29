<?php
// Direct (non-VPN) request: echo.lab.test/ip reports the address this PHP
// container connects from (the php-cli/-fpm/-apache lab IP).
if (PHP_SAPI !== 'cli') {
    header('Content-Type: text/plain');
}
$r = file_get_contents('http://echo.lab.test/ip');
if ($r === false) {
    if (PHP_SAPI !== 'cli') {
        http_response_code(502);
    }
    echo 'ERROR: direct request failed';
    exit(1);
}
echo $r;
