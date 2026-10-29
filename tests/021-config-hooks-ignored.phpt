--TEST--
php-vpn: wg-quick hooks and kernel-only settings are accepted but never executed
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$marker = sys_get_temp_dir() . '/php-vpn-phpt-021-' . bin2hex(random_bytes(6));
$private = base64_encode(random_bytes(32));
$peer = base64_encode(random_bytes(32));

$hooks = [
    'PreUp'       => "touch $marker.preup",
    'PostUp'      => "touch $marker.postup; iptables -A FORWARD -i %i -j ACCEPT",
    'PreDown'     => "touch $marker.predown",
    'PostDown'    => "touch $marker.postdown",
    'Table'       => 'off',
    'ListenPort'  => '51820',
    'FwMark'      => '0xca6c',
    'SaveConfig'  => 'true',
];

$lines = '';
foreach ($hooks as $key => $value) {
    $lines .= "$key = $value\n";
}
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\n$lines"
      . "[Peer]\nPublicKey = $peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:9\n";

$vpn = VPN::wireguardFromString($conf);
echo get_class($vpn), "\n";
echo $vpn->info()['endpoint'], "\n";

echo "-- case-insensitive keys and sections, comments, CRLF, BOM\n";
$conf = "\xEF\xBB\xBF# comment\r\n[interface]\r\nprivatekey = $private   # trailing comment\r\nADDRESS=10.13.13.2/32\r\n\r\n"
      . "[PEER]\r\n  PublicKey=$peer\r\n\tallowedips = 0.0.0.0/0\r\nENDPOINT = 127.0.0.1:9\r\npersistentkeepalive = off\r\n";
echo VPN::wireguardFromString($conf)->info()['endpoint'], "\n";

echo "-- no hook ran\n";
foreach (['preup', 'postup', 'predown', 'postdown'] as $hook) {
    var_dump(file_exists("$marker.$hook"));
}
?>
--CLEAN--
<?php
foreach (glob(sys_get_temp_dir() . '/php-vpn-phpt-021-*') as $file) {
    @unlink($file);
}
?>
--EXPECT--
VPN
127.0.0.1:9
-- case-insensitive keys and sections, comments, CRLF, BOM
127.0.0.1:9
-- no hook ran
bool(false)
bool(false)
bool(false)
bool(false)
