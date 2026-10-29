#!/usr/bin/env bash
# Runs tools/live-check.php inside an existing PHP container (e.g. a local
# WordPress container) without changing its image, volumes or project files:
# the extension, the profile and the script are copied to /tmp/php-vpn in the
# container, run as the web server user, and removed afterwards.
#
#   tools/live.sh CONTAINER PROFILE.conf [URL ...]
#   LIVE_USER=www-data (default)
#   LIVE_APACHE=DOCROOT  also run the check once through the container's Apache
#                        (mod_php): adds a conf.d ini + a uniquely named script in
#                        DOCROOT, reloads Apache gracefully, removes both after.
set -Eeuo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="${1:?usage: tools/live.sh CONTAINER PROFILE.conf [URL ...]}"
profile="${2:?usage: tools/live.sh CONTAINER PROFILE.conf [URL ...]}"
shift 2
user="${LIVE_USER:-www-data}"

[[ -r "${profile}" ]] || { echo "live: cannot read ${profile}" >&2; exit 2; }
ver="$(docker exec "${container}" php -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;')"
zts="$(docker exec "${container}" php -r 'echo (int) PHP_ZTS;')"
[[ "${zts}" == 0 ]] || { echo "live: the container's PHP is ZTS; only NTS builds exist" >&2; exit 2; }
so="${root}/dist/php${ver}/php-vpn.so"
[[ -f "${so}" ]] || { echo "live: ${so} missing; run ./dev build ${ver}" >&2; exit 2; }

apache_ini=""
apache_script=""
cleanup() {
    if [[ -n "${apache_ini}" ]]; then
        docker exec "${container}" sh -c "rm -f '${apache_script}' '${apache_ini}' && apache2ctl -k graceful" >/dev/null 2>&1 || true
    fi
    docker exec "${container}" rm -rf /tmp/php-vpn >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker exec "${container}" sh -c "rm -rf /tmp/php-vpn && mkdir -m 0700 /tmp/php-vpn && chown ${user} /tmp/php-vpn"
docker cp -q "${so}" "${container}:/tmp/php-vpn/php-vpn.so"
docker cp -q "${root}/tools/live-check.php" "${container}:/tmp/php-vpn/live-check.php"
# The profile goes in through stdin so it never appears in a command line.
docker exec -i "${container}" sh -c "umask 077 && cat > /tmp/php-vpn/profile.conf && chown ${user} /tmp/php-vpn/profile.conf" <"${profile}"

docker exec -u "${user}" "${container}" \
    php -d extension=/tmp/php-vpn/php-vpn.so \
        -d php_vpn.lock_dir=/tmp/php-vpn \
        /tmp/php-vpn/live-check.php /tmp/php-vpn/profile.conf "$@"

if [[ -n "${LIVE_APACHE:-}" ]]; then
    printf '\n-- through Apache (%s)\n' "$(docker exec "${container}" php -r 'echo PHP_VERSION;')"
    confd="$(docker exec "${container}" php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;')"
    apache_ini="${confd}/zz-php-vpn-live.ini"
    apache_script="${LIVE_APACHE%/}/php-vpn-live-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n').php"
    docker exec "${container}" sh -c "printf 'extension=/tmp/php-vpn/php-vpn.so\nphp_vpn.lock_dir=/tmp/php-vpn\n' > '${apache_ini}' && apache2ctl -k graceful"
    docker exec -i "${container}" sh -c "cat > '${apache_script}'" <<'PHP'
<?php
header('Content-Type: text/plain');
$vpn = VPN::wireguard('/tmp/php-vpn/profile.conf', ['timeout' => 30]);
$via = trim($vpn->request('GET', 'https://api.ipify.org')->body());
$direct = trim((string) @file_get_contents('https://api.ipify.org'));
printf("%s  sapi=%s pid=%d vpn=%s direct=%s\n", ($via !== '' && $via !== $direct) ? 'PASS' : 'FAIL', PHP_SAPI, getmypid(), $via, $direct);
PHP
    sleep 2
    for _ in 1 2; do
        docker exec "${container}" curl -sk --max-time 40 "https://localhost/$(basename "${apache_script}")"
    done
fi
