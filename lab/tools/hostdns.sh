#!/bin/bash
set -Eeuo pipefail
exec /lab/dnsmasq-run.sh /lab/hostdns.conf /state/logs/hostdns.log
