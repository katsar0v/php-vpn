#!/bin/bash
# One-shot init: lab CA + server certificates, idempotent (only creates what is missing).
set -Eeuo pipefail
umask 022
STATE=/state
CA=$STATE/ca
mkdir -p "$CA" "$STATE/logs" "$STATE/pcap" "$STATE/wg" "$STATE/clients"
cd "$CA"

if [[ ! -s lab-ca.pem || ! -s lab-ca.key ]]; then
    echo "init: creating lab CA"
    rm -f ./*.pem ./*.key ./*.srl ./*.csr
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout lab-ca.key -out lab-ca.pem -days 3650 -sha256 \
        -subj "/CN=php-vpn lab CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

# leaf <basename> <dns-name>   signed by the lab CA
leaf() {
    local base=$1 name=$2
    [[ -s $base.pem && -s $base.key ]] && return 0
    echo "init: issuing $base (SAN $name)"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$base.key" -out "$base.csr" -subj "/CN=$name" 2>/dev/null
    openssl x509 -req -in "$base.csr" -CA lab-ca.pem -CAkey lab-ca.key -CAcreateserial \
        -out "$base.pem" -days 825 -sha256 -extfile <(cat <<EXT
subjectAltName=DNS:$name
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
) 2>/dev/null
    rm -f "$base.csr"
}

leaf echo.lab.test echo.lab.test
leaf wrong.lab.test wrong.lab.test
leaf secret.vpn.test secret.vpn.test

# self-signed certificate for echo.lab.test (NOT signed by the lab CA)
if [[ ! -s echo.lab.test.selfsigned.pem || ! -s echo.lab.test.selfsigned.key ]]; then
    echo "init: issuing self-signed echo.lab.test"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout echo.lab.test.selfsigned.key -out echo.lab.test.selfsigned.pem \
        -days 825 -sha256 -subj "/CN=echo.lab.test" \
        -addext "subjectAltName=DNS:echo.lab.test" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
fi

chmod 0644 ./*.pem
chmod 0600 ./*.key
[[ -f lab-ca.srl ]] && chmod 0644 lab-ca.srl
# make everything removable/readable by the host user that runs lab.sh
chown -R "${LAB_UID:-0}:${LAB_GID:-0}" "$STATE" 2>/dev/null || true
echo "init: done"
