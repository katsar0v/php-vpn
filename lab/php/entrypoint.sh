#!/bin/bash
# Entry point shared by php-cli / php-fpm / php-apache of the php-vpn lab.
#  1. enable the extension if /opt/php-vpn/php-vpn.so exists
#  2. install the generated WireGuard client confs into /etc/php-vpn with strict perms
#  3. install the lab CA (/etc/php-vpn/lab-ca.pem + system trust store)
#  4. exec the real command
set -Eeuo pipefail
umask 022

SAPI=${LAB_SAPI:-cli}
SO=/opt/php-vpn/php-vpn.so
INI=${PHP_INI_DIR:-/usr/local/etc/php}/conf.d/zz-php-vpn.ini
CONF_DIR=/etc/php-vpn

# --- 1. extension -----------------------------------------------------------
rm -f "$INI"
if [[ -f $SO ]]; then
    {
        echo "extension=$SO"
        echo "php_vpn.allow_private_destinations=0"
        # extra INI lines for a run, e.g. PHP_VPN_EXTRA_INI=$'php_vpn.max_tunnels=2\nphp_vpn.lock_dir=/tmp'
        if [[ -n ${PHP_VPN_EXTRA_INI:-} ]]; then printf '%s\n' "$PHP_VPN_EXTRA_INI"; fi
    } >"$INI"
    echo "lab[$SAPI]: php-vpn extension ENABLED ($SO)"
else
    echo "lab[$SAPI]: NOTICE: $SO not found -> starting WITHOUT the php-vpn extension" >&2
    echo "lab[$SAPI]: (build it into dist/php${PHP_VERSION%.*}/php-vpn.so and run: lab/lab.sh restart)" >&2
fi

# --- 2. client confs ---------------------------------------------------------
mkdir -p "$CONF_DIR"
chmod 0755 "$CONF_DIR"
rm -f "$CONF_DIR"/*.conf
for _ in $(seq 60); do [[ -f /lab/clients/client1.conf ]] && break; sleep 0.5; done
shopt -s nullglob
for f in /lab/clients/*.conf; do
    b=$(basename "$f")
    owner=root; group=www-data; mode=0640
    if [[ $SAPI == fpm ]]; then
        case $b in
            client2.conf) owner=poola; group=poola; mode=0600 ;;
            client3.conf) owner=poolb; group=poolb; mode=0600 ;;
        esac
    fi
    install -o "$owner" -g "$group" -m "$mode" "$f" "$CONF_DIR/$b"
done

# --- 3. lab CA ---------------------------------------------------------------
for _ in $(seq 60); do [[ -f /lab/ca/lab-ca.pem ]] && break; sleep 0.5; done
install -m 0644 /lab/ca/lab-ca.pem "$CONF_DIR/lab-ca.pem"
install -m 0644 /lab/ca/lab-ca.pem /usr/local/share/ca-certificates/php-vpn-lab-ca.crt
update-ca-certificates >/dev/null 2>&1

touch /run/lab-ready
exec "$@"
