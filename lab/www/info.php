<?php
// Which SAPI / user / PHP version is this, and is the php-vpn extension loaded?
if (PHP_SAPI !== 'cli') {
    header('Content-Type: text/plain');
}
echo extension_loaded('vpn') ? 'vpn loaded' : 'vpn missing', "\n";
echo 'php=', PHP_VERSION, "\n";
echo 'sapi=', PHP_SAPI, "\n";
if (function_exists('posix_geteuid')) {
    $euid = posix_geteuid();
    $pw = function_exists('posix_getpwuid') ? posix_getpwuid($euid) : false;
    echo 'euid=', $euid, "\n";
    echo 'user=', $pw['name'] ?? '?', "\n";
}
// owner of this script file, NOT the user the process runs as
echo 'get_current_user=', get_current_user(), "\n";
echo 'pid=', getmypid(), "\n";
// FPM pools use clear_env=no, so container env must be visible here
echo 'env_PHP_VPN_LAB=', getenv('PHP_VPN_LAB') === false ? '(unset)' : getenv('PHP_VPN_LAB'), "\n";
