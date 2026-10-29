--TEST--
php-vpn: INI entries that guard secrets cannot be changed from a script
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$user = ['php_vpn.default_timeout', 'php_vpn.connect_timeout', 'php_vpn.max_response_size',
         'php_vpn.max_redirects', 'php_vpn.allow_private_destinations'];
$system = ['php_vpn.lock_dir', 'php_vpn.session_ttl', 'php_vpn.max_tunnels',
           'php_vpn.allowed_config_dir', 'php_vpn.enforce_key_permissions'];

$all = ini_get_all('vpn', true);
foreach ($user as $name) {
    printf("%-36s ALL=%s\n", $name, var_export($all[$name]['access'] === INI_ALL, true));
}
foreach ($system as $name) {
    printf("%-36s SYSTEM=%s\n", $name, var_export($all[$name]['access'] === INI_SYSTEM, true));
}
// ca_file may also be set per directory (.htaccess-style), never from a script.
var_dump($all['php_vpn.ca_file']['access'] === (INI_SYSTEM | INI_PERDIR));

echo "-- ini_set\n";
foreach ($system as $name) {
    var_dump(ini_set($name, '0'));
    var_dump(ini_get($name) === $all[$name]['global_value']);
}
var_dump(ini_set('php_vpn.ca_file', '/etc/ssl/certs/ca-certificates.crt'));

var_dump(ini_set('php_vpn.default_timeout', '5'));
var_dump(ini_get('php_vpn.default_timeout'));
var_dump(ini_set('php_vpn.allow_private_destinations', '1'));
var_dump(ini_get('php_vpn.allow_private_destinations'));
?>
--EXPECT--
php_vpn.default_timeout              ALL=true
php_vpn.connect_timeout              ALL=true
php_vpn.max_response_size            ALL=true
php_vpn.max_redirects                ALL=true
php_vpn.allow_private_destinations   ALL=true
php_vpn.lock_dir                     SYSTEM=true
php_vpn.session_ttl                  SYSTEM=true
php_vpn.max_tunnels                  SYSTEM=true
php_vpn.allowed_config_dir           SYSTEM=true
php_vpn.enforce_key_permissions      SYSTEM=true
bool(true)
-- ini_set
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)
string(2) "30"
string(1) "5"
string(1) "0"
string(1) "1"
