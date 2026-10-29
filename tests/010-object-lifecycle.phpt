--TEST--
php-vpn: VPN and VPN\Response cannot be constructed, cloned or serialized, and take no dynamic properties
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
function attempt(string $label, callable $fn): void {
    try {
        $fn();
        echo "$label: no error\n";
    } catch (Throwable $e) {
        echo "$label: ", get_class($e), ': ', $e->getMessage(), "\n";
    }
}

$conf = "[Interface]\nPrivateKey = " . base64_encode(random_bytes(32)) . "\nAddress = 10.13.13.2/32\n"
      . "[Peer]\nPublicKey = " . base64_encode(random_bytes(32)) . "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";
$vpn = VPN::wireguardFromString($conf);

echo "-- constructors are private\n";
attempt('new VPN', fn() => new VPN());
attempt('new VPN\Response', fn() => new VPN\Response());
attempt('Reflection newInstance VPN', fn() => (new ReflectionClass('VPN'))->newInstance());
attempt('Reflection newInstance Response', fn() => (new ReflectionClass('VPN\Response'))->newInstance());

echo "-- no uninitialised objects\n";
attempt('newInstanceWithoutConstructor VPN', fn() => (new ReflectionClass('VPN'))->newInstanceWithoutConstructor());
attempt('newInstanceWithoutConstructor Response', fn() => (new ReflectionClass('VPN\Response'))->newInstanceWithoutConstructor());

echo "-- clone\n";
attempt('clone VPN', fn() => clone $vpn);

echo "-- serialization\n";
attempt('serialize VPN', fn() => serialize($vpn));
attempt('serialize in array', fn() => serialize(['x' => [$vpn]]));
attempt('var_export', fn() => var_export($vpn, true));

echo "-- properties\n";
attempt('dynamic property', function () use ($vpn) { $vpn->secret = 'x'; });
var_dump(get_object_vars($vpn));
var_dump((array) $vpn);
var_dump((new ReflectionClass('VPN'))->getProperties());
var_dump(isset($vpn->anything));
attempt('to string', fn() => (string) $vpn);

echo "-- still usable\n";
var_dump($vpn instanceof VPN);
var_dump(count($vpn->info()));
?>
--EXPECT--
-- constructors are private
new VPN: Error: Call to private VPN::__construct() from global scope
new VPN\Response: Error: Call to private VPN\Response::__construct() from global scope
Reflection newInstance VPN: ReflectionException: Access to non-public constructor of class VPN
Reflection newInstance Response: ReflectionException: Access to non-public constructor of class VPN\Response
-- no uninitialised objects
newInstanceWithoutConstructor VPN: ReflectionException: Class VPN is an internal class marked as final that cannot be instantiated without invoking its constructor
newInstanceWithoutConstructor Response: ReflectionException: Class VPN\Response is an internal class marked as final that cannot be instantiated without invoking its constructor
-- clone
clone VPN: Error: Trying to clone an uncloneable object of class VPN
-- serialization
serialize VPN: Exception: Serialization of 'VPN' is not allowed
serialize in array: Exception: Serialization of 'VPN' is not allowed
var_export: no error
-- properties
dynamic property: Error: Cannot create dynamic property VPN::$secret
array(0) {
}
array(0) {
}
array(0) {
}
bool(false)
to string: Error: Object of class VPN could not be converted to string
-- still usable
bool(true)
int(8)
