# One Dockerfile for the three PHP SAPIs of the lab:
#   docker build --build-arg PHP_VERSION=8.4 --build-arg SAPI=cli|fpm|apache -f php/Dockerfile .
ARG PHP_VERSION=8.4
ARG SAPI=cli
FROM php:${PHP_VERSION}-${SAPI}
ARG SAPI

ENV TZ=UTC LAB_SAPI=${SAPI}

# php:8.0 images are Debian 11 (bullseye), which has left the main mirrors: use archive.debian.org
RUN set -eux; \
    . /etc/os-release; \
    if [ "${VERSION_CODENAME:-}" = bullseye ]; then \
        printf '%s\n' \
            'deb http://archive.debian.org/debian bullseye main' \
            'deb http://archive.debian.org/debian-security bullseye-security main' > /etc/apt/sources.list; \
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl iproute2 procps bind9-dnsutils; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 2001 poola; \
    groupadd --system --gid 2002 poolb; \
    useradd --system --uid 2001 --gid poola --no-create-home --shell /usr/sbin/nologin poola; \
    useradd --system --uid 2002 --gid poolb --no-create-home --shell /usr/sbin/nologin poolb; \
    mkdir -p /etc/php-vpn /opt/php-vpn

# pcntl for fork tests in the CLI image
RUN set -eux; if [ "$SAPI" = cli ]; then docker-php-ext-install -j"$(nproc)" pcntl; fi

COPY php/00-lab.ini ${PHP_INI_DIR}/conf.d/00-lab.ini

# php-fpm: two pools (a -> poola:9001, b -> poolb:9002), replacing the stock "www" pool
COPY php/fpm-pools.conf /tmp/fpm-pools.conf
RUN set -eux; \
    if [ "$SAPI" = fpm ]; then \
        rm -f /usr/local/etc/php-fpm.d/*.conf; \
        mv /tmp/fpm-pools.conf /usr/local/etc/php-fpm.d/lab-pools.conf; \
    else rm -f /tmp/fpm-pools.conf; fi

# apache: mod_php + prefork (the official image default), docroot /src/lab/www
COPY php/apache-vhost.conf /tmp/apache-vhost.conf
RUN set -eux; \
    if [ "$SAPI" = apache ]; then \
        mv /tmp/apache-vhost.conf /etc/apache2/sites-available/000-default.conf; \
        apache2ctl -V | grep -i 'MPM' | grep -qi prefork; \
    else rm -f /tmp/apache-vhost.conf; fi

COPY php/entrypoint.sh /usr/local/bin/lab-entrypoint
RUN chmod 0755 /usr/local/bin/lab-entrypoint
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
