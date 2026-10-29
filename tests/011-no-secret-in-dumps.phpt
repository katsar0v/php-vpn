--TEST--
php-vpn: var_dump, print_r, var_export, debug_zval_dump, json_encode and info() never expose key material
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$private = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=';
$preshared = random_bytes(32);
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\nDNS = 10.13.13.1\n"
      . "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n"
      . "PresharedKey = " . base64_encode($preshared) . "\n"
      . "AllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

// Every spelling of the secrets that could plausibly leak.
$secrets = [
    'private (base64)'   => $private,
    'private (prefix)'   => substr($private, 0, 12),
    'private (hex)'      => bin2hex(base64_decode($private)),
    'private (raw)'      => base64_decode($private),
    'preshared (base64)' => base64_encode($preshared),
    'preshared (hex)'    => bin2hex($preshared),
    'preshared (raw)'    => $preshared,
];

function leaks(string $text, array $secrets): array {
    return array_keys(array_filter($secrets, fn($s) => str_contains($text, $s)));
}

$vpn = VPN::wireguardFromString($conf, ['timeout' => 5]);
$pool = VPN::pool([$vpn, VPN::wireguardFromString(str_replace($private, base64_encode(random_bytes(32)), $conf))]);

$outputs = [];
foreach (['single' => $vpn, 'pool' => $pool] as $label => $object) {
    ob_start();
    var_dump($object);
    $outputs["$label var_dump"] = ob_get_clean();
    $outputs["$label print_r"] = print_r($object, true);
    $outputs["$label var_export"] = var_export($object, true);
    ob_start();
    debug_zval_dump($object);
    $outputs["$label debug_zval_dump"] = ob_get_clean();
    $outputs["$label json_encode"] = json_encode($object);
    $outputs["$label array cast"] = print_r((array) $object, true);
    $outputs["$label get_object_vars"] = print_r(get_object_vars($object), true);
    $outputs["$label info"] = print_r($object->info(), true) . serialize($object->info());
    $outputs["$label info json"] = json_encode($object->info());
}
try {
    serialize($vpn);
} catch (Exception $e) {
    $outputs['serialize exception'] = (string) $e;
}
try {
    $vpn->request('GET', 'ftp://example.com/');
} catch (Exception $e) {
    $outputs['request exception'] = (string) $e;
}

foreach ($outputs as $label => $text) {
    $found = leaks($text, $secrets);
    printf("%-28s %s\n", $label, $found ? 'LEAKS ' . implode(', ', $found) : 'clean');
}

echo "-- the object itself has no state to show\n";
var_dump(count((array) $vpn));
?>
--EXPECT--
single var_dump              clean
single print_r               clean
single var_export            clean
single debug_zval_dump       clean
single json_encode           clean
single array cast            clean
single get_object_vars       clean
single info                  clean
single info json             clean
pool var_dump                clean
pool print_r                 clean
pool var_export              clean
pool debug_zval_dump         clean
pool json_encode             clean
pool array cast              clean
pool get_object_vars         clean
pool info                    clean
pool info json               clean
serialize exception          clean
request exception            clean
-- the object itself has no state to show
int(0)
