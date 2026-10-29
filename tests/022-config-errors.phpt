--TEST--
php-vpn: invalid profiles throw ConfigException (code 2) with a line number and never echo key values
--SKIPIF--
<?php if (!extension_loaded('vpn')) die('skip vpn extension not loaded'); ?>
--FILE--
<?php
$private = base64_encode(random_bytes(32));
$peer = base64_encode(random_bytes(32));
$preshared = base64_encode(random_bytes(32));

// Line numbers in the messages refer to this layout:
//   1 [Interface]   2 PrivateKey   3 Address   4 DNS
//   5 [Peer]        6 PublicKey    7 AllowedIPs   8 Endpoint
function profile(array $replace = [], array $remove = [], string $extra = ''): string {
    global $private, $peer;
    $lines = [
        1 => '[Interface]',
        2 => "PrivateKey = $private",
        3 => 'Address = 10.13.13.2/32',
        4 => 'DNS = 10.13.13.1',
        5 => '[Peer]',
        6 => "PublicKey = $peer",
        7 => 'AllowedIPs = 0.0.0.0/0',
        8 => 'Endpoint = 127.0.0.1:9',
    ];
    foreach ($replace as $n => $line) {
        $lines[$n] = $line;
    }
    foreach ($remove as $n) {
        unset($lines[$n]);
    }
    return implode("\n", $lines) . "\n" . $extra;
}

// Secret-looking values that must never be repeated back.
$badKeys = [
    '31 bytes'        => base64_encode(random_bytes(31)),
    'no padding'      => rtrim(base64_encode(random_bytes(32)), '='),
    'not base64'      => 'SECRET!SECRET!SECRET!SECRET!SECRET!SECRET!',
    'truncated real'  => substr($private, 0, 30),
    'hex'             => bin2hex(random_bytes(22)),
    'url-safe alphabet' => 'SECRET_SECRET-SECRET_SECRET-SECRET_SECRE=',
];

$cases = [];
$cases['empty'] = ['', null];
$cases['comments only'] = ["# nothing here\n", null];
$cases['missing PrivateKey'] = [profile([], [2]), null];
$cases['missing Address'] = [profile([], [3]), null];
$cases['missing [Peer]'] = [implode("\n", array_slice(explode("\n", profile()), 0, 4)) . "\n", null];
$cases['missing PublicKey'] = [profile([], [6]), null];
$cases['missing AllowedIPs'] = [profile([], [7]), null];
$cases['missing Endpoint'] = [profile([], [8]), null];

$cases['unknown [Interface] key'] = [profile([4 => "DNS = 10.13.13.1\nJc = 4"]), 5];
$cases['unknown [Peer] key'] = [profile([], [], "Foo = bar\n"), 9];
$cases['unknown section'] = [profile([5 => '[Pier]']), 5];
$cases['two [Peer] sections'] = [profile([], [], "[Peer]\nPublicKey = $peer\n"), 9];
$cases['two [Interface] sections'] = [profile([5 => "[Interface]\n[Peer]"]), 5];
$cases['setting before any section'] = ["Address = 10.0.0.2/32\n" . profile(), 1];
$cases['line without ='] = [profile([3 => 'Address 10.13.13.2/32']), 3];

foreach ($badKeys as $label => $value) {
    $cases["PrivateKey: $label"] = [profile([2 => "PrivateKey = $value"]), 2];
    $cases["PublicKey: $label"] = [profile([6 => "PublicKey = $value"]), 6];
    $cases["PresharedKey: $label"] = [profile([7 => "PresharedKey = $value\nAllowedIPs = 0.0.0.0/0"]), 7];
}

$cases['Address: prefix too long'] = [profile([3 => 'Address = 10.13.13.2/33']), 3];
$cases['Address: not an address'] = [profile([3 => 'Address = nope']), 3];
$cases['Address: bad IPv6 prefix'] = [profile([3 => 'Address = fd00::2/129']), 3];
$cases['AllowedIPs: bad'] = [profile([7 => 'AllowedIPs = 0.0.0.0/0, 300.1.1.1/8']), 7];
$cases['Endpoint: no port'] = [profile([8 => 'Endpoint = 127.0.0.1']), 8];
$cases['Endpoint: port 0'] = [profile([8 => 'Endpoint = 127.0.0.1:0']), 8];
$cases['Endpoint: port too big'] = [profile([8 => 'Endpoint = 127.0.0.1:65536']), 8];
$cases['Endpoint: port text'] = [profile([8 => 'Endpoint = 127.0.0.1:http']), 8];
$cases['Endpoint: bare IPv6'] = [profile([8 => 'Endpoint = 2001:db8::1:51820']), 8];
$cases['Endpoint: bad host name'] = [profile([8 => 'Endpoint = bad_host!:51820']), 8];
$cases['Endpoint: empty'] = [profile([8 => 'Endpoint =']), 8];
$cases['MTU: text'] = [profile([4 => "DNS = 10.13.13.1\nMTU = big"]), 5];
$cases['MTU: too small'] = [profile([4 => "DNS = 10.13.13.1\nMTU = 575"]), 5];
$cases['MTU: too large'] = [profile([4 => "DNS = 10.13.13.1\nMTU = 9001"]), 5];
$cases['MTU: overflow'] = [profile([4 => "DNS = 10.13.13.1\nMTU = 70000"]), 5];
$cases['PersistentKeepalive: text'] = [profile([], [], "PersistentKeepalive = often\n"), 9];

$cases['larger than 64 KiB'] = [profile([], [], '#' . str_repeat('x', 65536) . "\n"), null];
$cases['invalid UTF-8'] = [profile([], [], "# \xFF\xFE\n"), null];

foreach ($cases as $label => [$text, $line]) {
    try {
        VPN::wireguardFromString($text);
        printf("%-34s NO EXCEPTION\n", $label);
        continue;
    } catch (VPN\ConfigException $e) {
        $message = $e->getMessage();
    }
    $problems = [];
    if ($e->getCode() !== 2) {
        $problems[] = 'code ' . $e->getCode();
    }
    if ($line !== null && !str_contains($message, "line $line:")) {
        $problems[] = "no 'line $line'";
    }
    foreach ([$private, $peer, $preshared] + array_values($badKeys) as $secret) {
        if (str_contains($message, $secret) || str_contains($message, substr($secret, 0, 12))) {
            $problems[] = 'echoes a key';
        }
    }
    printf("%-34s %s%s\n", $label, $message, $problems ? '   <<< ' . implode(', ', array_unique($problems)) : '');
}
?>
--EXPECT--
empty                              WireGuard profile: missing [Interface] PrivateKey
comments only                      WireGuard profile: missing [Interface] PrivateKey
missing PrivateKey                 WireGuard profile: missing [Interface] PrivateKey
missing Address                    WireGuard profile: missing [Interface] Address
missing [Peer]                     WireGuard profile: missing [Peer] section
missing PublicKey                  WireGuard profile: missing [Peer] PublicKey
missing AllowedIPs                 WireGuard profile: missing [Peer] AllowedIPs
missing Endpoint                   WireGuard profile: missing [Peer] Endpoint
unknown [Interface] key            WireGuard profile, line 5: unsupported [Interface] key `jc`
unknown [Peer] key                 WireGuard profile, line 9: unsupported [Peer] key `foo`
unknown section                    WireGuard profile, line 5: unknown section
two [Peer] sections                WireGuard profile, line 9: more than one [Peer] section (only single-peer profiles are supported)
two [Interface] sections           WireGuard profile, line 5: more than one [Interface] section
setting before any section         WireGuard profile, line 1: setting outside of a section
line without =                     WireGuard profile, line 3: expected `Key = Value`
PrivateKey: 31 bytes               WireGuard profile, line 2: PrivateKey is not a valid base64 WireGuard key
PublicKey: 31 bytes                WireGuard profile, line 6: PublicKey is not a valid base64 WireGuard key
PresharedKey: 31 bytes             WireGuard profile, line 7: PresharedKey is not a valid base64 WireGuard key
PrivateKey: no padding             WireGuard profile, line 2: PrivateKey is not a valid base64 WireGuard key
PublicKey: no padding              WireGuard profile, line 6: PublicKey is not a valid base64 WireGuard key
PresharedKey: no padding           WireGuard profile, line 7: PresharedKey is not a valid base64 WireGuard key
PrivateKey: not base64             WireGuard profile, line 2: PrivateKey is not a valid base64 WireGuard key
PublicKey: not base64              WireGuard profile, line 6: PublicKey is not a valid base64 WireGuard key
PresharedKey: not base64           WireGuard profile, line 7: PresharedKey is not a valid base64 WireGuard key
PrivateKey: truncated real         WireGuard profile, line 2: PrivateKey is not a valid base64 WireGuard key
PublicKey: truncated real          WireGuard profile, line 6: PublicKey is not a valid base64 WireGuard key
PresharedKey: truncated real       WireGuard profile, line 7: PresharedKey is not a valid base64 WireGuard key
PrivateKey: hex                    WireGuard profile, line 2: PrivateKey is not a valid base64 WireGuard key
PublicKey: hex                     WireGuard profile, line 6: PublicKey is not a valid base64 WireGuard key
PresharedKey: hex                  WireGuard profile, line 7: PresharedKey is not a valid base64 WireGuard key
PrivateKey: url-safe alphabet      WireGuard profile, line 2: PrivateKey is not a valid base64 WireGuard key
PublicKey: url-safe alphabet       WireGuard profile, line 6: PublicKey is not a valid base64 WireGuard key
PresharedKey: url-safe alphabet    WireGuard profile, line 7: PresharedKey is not a valid base64 WireGuard key
Address: prefix too long           WireGuard profile, line 3: invalid Address (expected a.b.c.d/nn or an IPv6 CIDR)
Address: not an address            WireGuard profile, line 3: invalid Address (expected a.b.c.d/nn or an IPv6 CIDR)
Address: bad IPv6 prefix           WireGuard profile, line 3: invalid Address (expected a.b.c.d/nn or an IPv6 CIDR)
AllowedIPs: bad                    WireGuard profile, line 7: invalid AllowedIPs entry (expected CIDRs such as 0.0.0.0/0)
Endpoint: no port                  WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
Endpoint: port 0                   WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
Endpoint: port too big             WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
Endpoint: port text                WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
Endpoint: bare IPv6                WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
Endpoint: bad host name            WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
Endpoint: empty                    WireGuard profile, line 8: Endpoint must be `host:port`, `a.b.c.d:port` or `[ipv6]:port`
MTU: text                          WireGuard profile, line 5: MTU must be a number
MTU: too small                     WireGuard profile, line 5: MTU must be between 576 and 9000
MTU: too large                     WireGuard profile, line 5: MTU must be between 576 and 9000
MTU: overflow                      WireGuard profile, line 5: MTU must be a number
PersistentKeepalive: text          WireGuard profile, line 9: PersistentKeepalive must be a number or `off`
larger than 64 KiB                 WireGuard profile is larger than 65536 bytes
invalid UTF-8                      the WireGuard profile is not valid UTF-8
