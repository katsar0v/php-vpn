<?php
// Helpers for the lab cases: each check prints one "PASS  name" or
// "FAIL  name -- detail" line, which tests/e2e/run.sh counts.

function check(string $name, bool $ok, string $detail = ''): void
{
    echo $ok ? 'PASS' : 'FAIL', "  $name", (!$ok && $detail !== '') ? " -- $detail" : '', "\n";
}

/** Profile from the lab; the lab CA is trusted unless overridden. */
function vpn(string $client = 'client1', array $options = []): VPN
{
    return VPN::wireguard("/etc/php-vpn/$client.conf", $options + ['ca_file' => '/etc/php-vpn/lab-ca.pem']);
}

/** Runs $fn and returns [exception or null, result, seconds]. */
function attempt(callable $fn): array
{
    $t = microtime(true);
    try {
        $r = $fn();
        return [null, $r, microtime(true) - $t];
    } catch (Throwable $e) {
        return [$e, null, microtime(true) - $t];
    }
}

function expect_exception(string $name, callable $fn, string $class, ?float $maxSeconds = null): ?Throwable
{
    [$e, , $s] = attempt($fn);
    $ok = $e instanceof $class && ($maxSeconds === null || $s <= $maxSeconds);
    $got = $e ? get_class($e) . ': ' . $e->getMessage() : 'no exception';
    check($name, $ok, sprintf('%s after %.2f s (expected %s%s)', $got, $s, $class, $maxSeconds ? sprintf(' within %.1f s', $maxSeconds) : ''));
    return $e;
}

function echo_json(VPN $vpn, string $method, string $url, array $options = []): array
{
    $r = $vpn->request($method, $url, $options);
    return json_decode($r->body(), true) ?? [];
}

function header_values(array $echo, string $name): array
{
    $out = [];
    foreach ($echo['headers'] ?? [] as [$n, $v]) {
        if (strcasecmp($n, $name) === 0) {
            $out[] = $v;
        }
    }
    return $out;
}

function rss_kb(): int
{
    return preg_match('/^VmRSS:\s+(\d+)/m', (string) @file_get_contents('/proc/self/status'), $m) ? (int) $m[1] : 0;
}
