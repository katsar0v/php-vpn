--TEST--
php-vpn: php_vpn.* INI entries exist with the documented defaults
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$expected = [
    'php_vpn.default_timeout'           => '30',
    'php_vpn.connect_timeout'           => '10',
    'php_vpn.max_response_size'         => '16M',
    'php_vpn.max_redirects'             => '5',
    'php_vpn.ca_file'                   => '',
    'php_vpn.allow_private_destinations' => '0',
    'php_vpn.lock_dir'                  => '',
    'php_vpn.session_ttl'               => '120',
    'php_vpn.max_tunnels'               => '4',
    'php_vpn.allowed_config_dir'        => '',
    'php_vpn.enforce_key_permissions'   => '1',
];
foreach ($expected as $name => $default) {
    $value = ini_get($name);
    printf("%-36s %s\n", $name, $value === $default ? 'ok' : 'got ' . var_export($value, true));
}

echo "-- no unexpected entries\n";
$entries = array_keys(ini_get_all('vpn'));
sort($entries);
$names = array_keys($expected);
sort($names);
var_dump($entries === $names);

echo "-- unknown entry\n";
var_dump(ini_get('php_vpn.does_not_exist'));
?>
--EXPECT--
php_vpn.default_timeout              ok
php_vpn.connect_timeout              ok
php_vpn.max_response_size            ok
php_vpn.max_redirects                ok
php_vpn.ca_file                      ok
php_vpn.allow_private_destinations   ok
php_vpn.lock_dir                     ok
php_vpn.session_ttl                  ok
php_vpn.max_tunnels                  ok
php_vpn.allowed_config_dir           ok
php_vpn.enforce_key_permissions      ok
-- no unexpected entries
bool(true)
-- unknown entry
bool(false)
