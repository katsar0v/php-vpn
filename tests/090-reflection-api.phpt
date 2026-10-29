--TEST--
php-vpn: public API surface of VPN and VPN\Response (Response objects only come from request())
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
function render_default(ReflectionParameter $parameter): string {
    $value = $parameter->getDefaultValue();
    return $value === [] ? '[]' : var_export($value, true);
}

function signature(ReflectionMethod $method): string {
    $parameters = [];
    foreach ($method->getParameters() as $parameter) {
        $text = $parameter->getType() . ' $' . $parameter->getName();
        if ($parameter->isOptional()) {
            $text .= ' = ' . render_default($parameter);
        }
        $parameters[] = $text;
    }
    $modifiers = implode(' ', Reflection::getModifierNames($method->getModifiers()));
    return sprintf('%s %s(%s): %s', $modifiers, $method->getName(), implode(', ', $parameters), $method->getReturnType());
}

foreach (['VPN', 'VPN\Response'] as $class) {
    echo "-- $class\n";
    $reflection = new ReflectionClass($class);
    foreach ($reflection->getMethods() as $method) {
        if ($method->isConstructor()) {
            printf("constructor: %s, %d parameter(s)\n", implode(' ', Reflection::getModifierNames($method->getModifiers())), $method->getNumberOfParameters());
            continue;
        }
        echo signature($method), "\n";
    }
    printf("properties: %d, constants: %s\n", count($reflection->getProperties()), implode(',', array_keys($reflection->getConstants())) ?: 'none');
    printf("interfaces: %s\n", implode(',', $reflection->getInterfaceNames()) ?: 'none');
    var_dump($reflection->isCloneable(), $reflection->isInstantiable());
}

echo "-- the only way to get a Response is VPN::request()\n";
var_dump((string) (new ReflectionMethod('VPN', 'request'))->getReturnType());
foreach (get_class_methods('VPN') as $method) {
    $type = (string) (new ReflectionMethod('VPN', $method))->getReturnType();
    if ($type === 'VPN\Response') {
        echo "$method returns a Response\n";
    }
}
?>
--EXPECT--
-- VPN
constructor: private, 0 parameter(s)
public static wireguard(string $path, array $options = []): VPN
public static wireguardFromString(string $config, array $options = []): VPN
public static pool(array $profiles, array $options = []): VPN
public request(string $method, string $url, array $options = []): VPN\Response
public info(): array
public close(): void
properties: 0, constants: VERSION
interfaces: none
bool(false)
bool(false)
-- VPN\Response
constructor: private, 0 parameter(s)
public status(): int
public headers(): array
public header(string $name): ?string
public body(): string
public effectiveUrl(): string
public redirectCount(): int
public remoteAddress(): string
properties: 0, constants: none
interfaces: none
bool(false)
bool(false)
-- the only way to get a Response is VPN::request()
string(12) "VPN\Response"
request returns a Response
