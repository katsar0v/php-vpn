# Shared "lab tools" image: wg-server, hostdns, wg-client, sniff and the one-shot
# init (CA/cert generation) all run from this image with different commands.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        bash ca-certificates curl bind9-dnsutils dnsmasq-base iproute2 iptables \
        iputils-ping openssl procps tcpdump wireguard-tools wireguard-go; \
    rm -rf /var/lib/apt/lists/*

COPY tools/ /lab/
RUN chmod 0755 /lab/*.sh
