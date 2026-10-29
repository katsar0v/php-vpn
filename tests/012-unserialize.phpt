--TEST--
php-vpn: unserialize() never creates a VPN or VPN\Response object
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
// PHP 8.1+ throws "Unserialization of 'X' is not allowed" for classes flagged
// ZEND_ACC_NOT_SERIALIZABLE. PHP 8.0 only has the class-level deny handler,
// which makes unserialize() warn and return false. Either way: no object.
function try_unserialize(string $data, string $class): string {
    set_error_handler(fn() => true);
    try {
        $result = unserialize($data);
    } catch (Exception $e) {
        $expected = "Unserialization of '$class' is not allowed";
        return $e->getMessage() === $expected
            ? 'rejected'
            : 'unexpected ' . get_class($e) . ': ' . $e->getMessage();
    } finally {
        restore_error_handler();
    }
    if ($result === false) {
        return PHP_VERSION_ID < 80100 ? 'rejected' : 'false instead of an exception';
    }
    return 'OBJECT CREATED: ' . get_debug_type($result);
}

$payloads = [
    'VPN'                 => ['O:3:"VPN":0:{}', 'VPN'],
    'VPN\Response'        => ['O:12:"VPN\Response":0:{}', 'VPN\Response'],
    'VPN with properties' => ['O:3:"VPN":1:{s:7:"profile";s:4:"abcd";}', 'VPN'],
    'nested in an array'  => ['a:1:{i:0;O:3:"VPN":0:{}}', 'VPN'],
    'Serializable format' => ['C:3:"VPN":0:{}', 'VPN'],
];
foreach ($payloads as $label => [$data, $class]) {
    printf("%-21s %s\n", $label, try_unserialize($data, $class));
}
?>
--EXPECT--
VPN                   rejected
VPN\Response          rejected
VPN with properties   rejected
nested in an array    rejected
Serializable format   rejected
