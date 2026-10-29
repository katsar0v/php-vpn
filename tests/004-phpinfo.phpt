--TEST--
php-vpn: phpinfo(INFO_MODULES) and ReflectionExtension describe the extension
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
ob_start();
phpinfo(INFO_MODULES);
$info = ob_get_clean();

var_dump(str_contains($info, 'php-vpn support => enabled'));
var_dump(str_contains($info, 'Extension version => ' . VPN::VERSION));
var_dump(str_contains($info, 'php_vpn.lock_dir'));
var_dump(str_contains($info, 'php_vpn.enforce_key_permissions'));

$extension = new ReflectionExtension('vpn');
var_dump($extension->getName());
var_dump($extension->getVersion() === VPN::VERSION);
$classes = array_keys($extension->getClasses());
sort($classes);
echo implode("\n", $classes), "\n";
var_dump(array_key_exists('php_vpn.max_tunnels', $extension->getINIEntries()));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
string(3) "vpn"
bool(true)
VPN
VPN\ConfigException
VPN\ConnectException
VPN\DnsException
VPN\Exception
VPN\LimitException
VPN\LockTimeoutException
VPN\PolicyException
VPN\ProtocolException
VPN\Response
VPN\TimeoutException
VPN\TlsException
VPN\TunnelException
bool(true)
