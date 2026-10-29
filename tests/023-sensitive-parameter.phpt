--TEST--
php-vpn: wireguardFromString() marks its argument #[\SensitiveParameter], so traces do not contain the profile
--SKIPIF--
<?php
if (!extension_loaded('vpn')) die('skip vpn extension not loaded');
if (PHP_VERSION_ID < 80200) die('skip #[\SensitiveParameter] needs PHP 8.2+');
?>
--INI--
zend.exception_ignore_args=0
--FILE--
<?php
$marker = 'TOPSECRET-' . bin2hex(random_bytes(8));
$short = 'TOPSECRET';
// Trace strings are cut after 15 characters, so the marker also starts the profile.
$profile = "# $marker\n[Interface]\nPrivateKey = $marker\nAddress = 10.13.13.2/32\n";

echo "-- reflection\n";
$parameter = (new ReflectionMethod('VPN', 'wireguardFromString'))->getParameters()[0];
var_dump($parameter->getName());
var_dump(array_map(fn($a) => $a->getName(), $parameter->getAttributes()));
foreach (['wireguard', 'pool', 'request'] as $method) {
    $first = (new ReflectionMethod('VPN', $method))->getParameters()[0];
    printf("%s::$%s sensitive=%s\n", $method, $first->getName(), var_export(count($first->getAttributes()) > 0, true));
}

echo "-- positive control: arguments do show up in traces of ordinary functions\n";
function visible(string $argument) {
    throw new Exception('control');
}
try {
    visible($marker);
} catch (Exception $e) {
    var_dump(str_contains($e->getTraceAsString(), $short));
    var_dump(str_contains(print_r($e->getTrace(), true), $short));
}

echo "-- a failing wireguardFromString()\n";
try {
    VPN::wireguardFromString($profile);
} catch (VPN\ConfigException $e) {
    var_dump($e->getMessage());
    var_dump(str_contains($e->getMessage(), $short));
    var_dump(str_contains($e->getTraceAsString(), $short));
    var_dump(str_contains(print_r($e->getTrace(), true), $short));
    var_dump(str_contains((string) $e, $short));
    var_dump(str_contains(var_export($e->getTrace(), true), $short));
    $args = $e->getTrace()[0]['args'];
    var_dump(count($args));
    var_dump($args[0] instanceof SensitiveParameterValue);
    var_dump($args[0]->getValue() === $profile);
    var_dump(str_contains($e->getTraceAsString(), 'SensitiveParameterValue'));
}

echo "-- with options and through a wrapper\n";
function load(string $conf, array $options) {
    return VPN::wireguardFromString($conf, $options);
}
try {
    VPN::wireguardFromString($profile, ['timeout' => 5]);
} catch (VPN\ConfigException $e) {
    var_dump(str_contains((string) $e, $short));
}
try {
    load($profile, []);
} catch (VPN\ConfigException $e) {
    // The wrapper's own argument is not marked, but the extension frame must be redacted.
    var_dump($e->getTrace()[0]['function']);
    var_dump($e->getTrace()[0]['args'][0] instanceof SensitiveParameterValue);
}
?>
--EXPECT--
-- reflection
string(6) "config"
array(1) {
  [0]=>
  string(18) "SensitiveParameter"
}
wireguard::$path sensitive=false
pool::$profiles sensitive=false
request::$method sensitive=false
-- positive control: arguments do show up in traces of ordinary functions
bool(true)
bool(true)
-- a failing wireguardFromString()
string(73) "WireGuard profile, line 3: PrivateKey is not a valid base64 WireGuard key"
bool(false)
bool(false)
bool(false)
bool(false)
bool(false)
int(1)
bool(true)
bool(true)
bool(true)
-- with options and through a wrapper
bool(false)
string(19) "wireguardFromString"
bool(true)
