--TEST--
php-vpn: wireguardFromString() parses a valid profile and info() describes it without secrets
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$private = 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=';
$peer = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=';

function is_list(array $a): bool {
    return $a === array_values($a);
}

function show(array $info): void {
    echo json_encode($info, JSON_UNESCAPED_SLASHES), "\n";
}

echo "-- Surfshark-style profile\n";
$conf = <<<CONF
# Surfshark-style profile
[Interface]
PrivateKey = $private
Address = 10.14.0.2/16
DNS = 162.252.172.57, 149.154.159.92

[Peer]
PublicKey = $peer
AllowedIPs = 0.0.0.0/0
Endpoint = de-fra.prod.surfshark.com:51820
PersistentKeepalive = 25
CONF;
$vpn = VPN::wireguardFromString($conf);
var_dump($vpn instanceof VPN);
$info = $vpn->info();
show($info);
var_dump(array_keys($info));
var_dump($info['mtu']);
var_dump($info['session_age']);
var_dump(is_list($info['addresses']), is_list($info['dns']), is_list($info['allowed_ips']));
var_dump(str_contains(json_encode($info), $private));
var_dump(str_contains(json_encode($info), 'yAnz'));

echo "-- the test vector: public key derived from the private key\n";
var_dump($info['public_key'] === 'HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=');
var_dump($info['peer_public_key'] === $peer);

echo "-- info() is repeatable and unaffected by close()\n";
var_dump($vpn->info() === $info);
var_dump($vpn->close());
var_dump($vpn->info() === $info);

echo "-- dual stack, custom MTU, IPv6 endpoint, preshared key\n";
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32, fd13:13::2/128\nDNS = 10.13.13.1, fd13:13::1\nMTU = 1280\n"
      . "[Peer]\nPublicKey = $peer\nPresharedKey = " . base64_encode(random_bytes(32)) . "\n"
      . "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = [2001:db8::1]:51821\n";
show(VPN::wireguardFromString($conf)->info());

echo "-- host names are lower-cased, search domains in DNS= are ignored\n";
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2\nDNS = 10.13.13.1, lab.example\n"
      . "[Peer]\nPublicKey = $peer\nAllowedIPs = 10.13.13.0/24\nEndpoint = WG.Lab.Example:51820\n";
show(VPN::wireguardFromString($conf)->info());

echo "-- no DNS line is fine\n";
$conf = "[Interface]\nPrivateKey = $private\nAddress = 10.13.13.2/32\n[Peer]\nPublicKey = $peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";
$info = VPN::wireguardFromString($conf)->info();
var_dump($info['dns'], $info['mtu']);

echo "-- profile size limit: 64 KiB\n";
$exact = str_pad($conf, 65536, '#');
var_dump(strlen($exact));
var_dump(VPN::wireguardFromString($exact)->info()['mtu']);
try {
    VPN::wireguardFromString($exact . '#');
} catch (VPN\ConfigException $e) {
    echo $e->getMessage(), "\n";
}

echo "-- MTU bounds\n";
foreach ([576, 1420, 9000] as $mtu) {
    $c = str_replace("Address = 10.13.13.2/32", "Address = 10.13.13.2/32\nMTU = $mtu", $conf);
    var_dump(VPN::wireguardFromString($c)->info()['mtu']);
}
?>
--EXPECT--
-- Surfshark-style profile
bool(true)
{"endpoint":"de-fra.prod.surfshark.com:51820","addresses":["10.14.0.2/16"],"dns":["162.252.172.57","149.154.159.92"],"allowed_ips":["0.0.0.0/0"],"mtu":1420,"public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","peer_public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","session_age":null}
array(8) {
  [0]=>
  string(8) "endpoint"
  [1]=>
  string(9) "addresses"
  [2]=>
  string(3) "dns"
  [3]=>
  string(11) "allowed_ips"
  [4]=>
  string(3) "mtu"
  [5]=>
  string(10) "public_key"
  [6]=>
  string(15) "peer_public_key"
  [7]=>
  string(11) "session_age"
}
int(1420)
NULL
bool(true)
bool(true)
bool(true)
bool(false)
bool(false)
-- the test vector: public key derived from the private key
bool(true)
bool(true)
-- info() is repeatable and unaffected by close()
bool(true)
NULL
bool(true)
-- dual stack, custom MTU, IPv6 endpoint, preshared key
{"endpoint":"[2001:db8::1]:51821","addresses":["10.13.13.2/32","fd13:13::2/128"],"dns":["10.13.13.1","fd13:13::1"],"allowed_ips":["0.0.0.0/0","::/0"],"mtu":1280,"public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","peer_public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","session_age":null}
-- host names are lower-cased, search domains in DNS= are ignored
{"endpoint":"wg.lab.example:51820","addresses":["10.13.13.2/32"],"dns":["10.13.13.1"],"allowed_ips":["10.13.13.0/24"],"mtu":1420,"public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","peer_public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","session_age":null}
-- no DNS line is fine
array(0) {
}
int(1420)
-- profile size limit: 64 KiB
int(65536)
int(1420)
WireGuard profile is larger than 65536 bytes
-- MTU bounds
int(576)
int(1420)
int(9000)
