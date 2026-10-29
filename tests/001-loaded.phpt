--TEST--
php-vpn: extension is loaded, VERSION constant, classes, final classes, exception hierarchy
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
var_dump(extension_loaded('vpn'));
var_dump(in_array('vpn', get_loaded_extensions(), true));

echo "-- version\n";
var_dump(is_string(VPN::VERSION));
var_dump(preg_match('/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/', VPN::VERSION));
var_dump(phpversion('vpn') === VPN::VERSION);
$constant = new ReflectionClassConstant('VPN', 'VERSION');
var_dump($constant->isPublic());

echo "-- classes\n";
$classes = [
    'VPN', 'VPN\Response', 'VPN\Exception', 'VPN\ConfigException', 'VPN\TunnelException',
    'VPN\DnsException', 'VPN\ConnectException', 'VPN\TlsException', 'VPN\TimeoutException',
    'VPN\ProtocolException', 'VPN\PolicyException', 'VPN\LimitException',
    'VPN\LockTimeoutException',
];
foreach ($classes as $class) {
    printf("%-26s %s\n", $class, class_exists($class, false) ? 'exists' : 'MISSING');
}

echo "-- final classes\n";
foreach (['VPN', 'VPN\Response'] as $class) {
    $reflection = new ReflectionClass($class);
    printf("%-13s final=%s internal=%s instantiable=%s\n", $class,
        var_export($reflection->isFinal(), true),
        var_export($reflection->isInternal(), true),
        var_export($reflection->isInstantiable(), true));
}

echo "-- exception hierarchy\n";
var_dump(get_parent_class('VPN\Exception'));
var_dump(is_subclass_of('VPN\Exception', 'Throwable'));
foreach (array_slice($classes, 3) as $class) {
    printf("%-26s parent=%s\n", $class, get_parent_class($class));
}

echo "-- catching\n";
foreach (array_slice($classes, 2) as $class) {
    try {
        throw new $class('message', 42);
    } catch (VPN\Exception $e) {
        $ok = $e instanceof RuntimeException && $e->getMessage() === 'message' && $e->getCode() === 42;
        printf("%-26s %s\n", $class, $ok ? 'ok' : 'FAIL');
    }
}
?>
--EXPECT--
bool(true)
bool(true)
-- version
bool(true)
int(1)
bool(true)
bool(true)
-- classes
VPN                        exists
VPN\Response               exists
VPN\Exception              exists
VPN\ConfigException        exists
VPN\TunnelException        exists
VPN\DnsException           exists
VPN\ConnectException       exists
VPN\TlsException           exists
VPN\TimeoutException       exists
VPN\ProtocolException      exists
VPN\PolicyException        exists
VPN\LimitException         exists
VPN\LockTimeoutException   exists
-- final classes
VPN           final=true internal=true instantiable=false
VPN\Response  final=true internal=true instantiable=false
-- exception hierarchy
string(16) "RuntimeException"
bool(true)
VPN\ConfigException        parent=VPN\Exception
VPN\TunnelException        parent=VPN\Exception
VPN\DnsException           parent=VPN\Exception
VPN\ConnectException       parent=VPN\Exception
VPN\TlsException           parent=VPN\Exception
VPN\TimeoutException       parent=VPN\Exception
VPN\ProtocolException      parent=VPN\Exception
VPN\PolicyException        parent=VPN\Exception
VPN\LimitException         parent=VPN\Exception
VPN\LockTimeoutException   parent=VPN\Exception
-- catching
VPN\Exception              ok
VPN\ConfigException        ok
VPN\TunnelException        ok
VPN\DnsException           ok
VPN\ConnectException       ok
VPN\TlsException           ok
VPN\TimeoutException       ok
VPN\ProtocolException      ok
VPN\PolicyException        ok
VPN\LimitException         ok
VPN\LockTimeoutException   ok
