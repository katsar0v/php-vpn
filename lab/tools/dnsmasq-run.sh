#!/bin/bash
# Run dnsmasq in the foreground and append its (stderr) log to a file, prefixing
# every line with a millisecond ISO-8601 UTC timestamp:
#   2026-10-29T15:50:12.345Z dnsmasq[7]: 12 198.51.100.40/41234 query[A] echo.lab.test from 198.51.100.40
# usage: dnsmasq-run.sh <conf> <logfile>
set -Eeuo pipefail
umask 022
export TZ=UTC
conf=$1
log=$2
mkdir -p "$(dirname "$log")"

stamp() {
    local line sec frac
    while IFS= read -r line; do
        sec=${EPOCHREALTIME%.*}
        frac=${EPOCHREALTIME#*.}
        printf '%(%Y-%m-%dT%H:%M:%S)T.%sZ %s\n' "$sec" "${frac:0:3}" "$line"
    done
}

dnsmasq --conf-file="$conf" 2> >(stamp >>"$log") &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null || true' TERM INT
wait "$pid" || true
trap - TERM INT
wait "$pid" 2>/dev/null || true
