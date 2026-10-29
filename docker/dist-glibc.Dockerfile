# syntax=docker/dockerfile:1
#
# Release builder for the glibc builds: AlmaLinux 8 (glibc 2.28, gcc 8.5).
# Everything that ends up in php-vpn.so is compiled and linked here, so the
# shared object needs nothing newer than glibc 2.28 (RHEL/Alma/Rocky 8,
# Debian 10, Ubuntu 18.10 and anything newer).
#
#   --target base   Rust 1.96.0 (rustup, pinned like core/rust-toolchain.toml) +
#                   a C toolchain. Builds the Rust core.
#   --target php    base + PHP built from the official source tarball with a
#                   minimal NTS configure (headers, phpize, php-config and a
#                   small php CLI used to smoke-load the extension).
#
# Driven by ./dev dist; see docker/php-sources.txt for the PHP pins.
ARG ALMA_IMAGE=almalinux:8

FROM ${ALMA_IMAGE} AS base
ARG RUST_VERSION=1.96.0
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    PATH=/opt/cargo/bin:${PATH}
RUN set -eux; \
    dnf -y install \
        autoconf automake binutils bzip2 ca-certificates curl diffutils file findutils \
        gcc gcc-c++ git-core make pkgconf-pkg-config tar xz which; \
    dnf clean all; rm -rf /var/cache/dnf
RUN set -eux; \
    triple="$(uname -m)-unknown-linux-gnu"; \
    cd /tmp; \
    curl -fsSLO "https://static.rust-lang.org/rustup/dist/${triple}/rustup-init"; \
    curl -fsSL "https://static.rust-lang.org/rustup/dist/${triple}/rustup-init.sha256" \
        | awk '{print $1 "  rustup-init"}' | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_VERSION}" -c clippy -c rustfmt; \
    rm rustup-init; \
    chmod -R a+rX /opt/rustup /opt/cargo; \
    cargo --version; rustc --version
# Containers run as an arbitrary uid; keep every cache under /tmp or a volume.
ENV HOME=/tmp

FROM base AS php
ARG PHP_VERSION
ARG PHP_URL
ARG PHP_SHA256
RUN set -eux; \
    test -n "${PHP_VERSION}" -a -n "${PHP_URL}" -a -n "${PHP_SHA256}"; \
    mkdir /usr/src/php; cd /usr/src/php; \
    curl -fsSL -o php.tar.xz "${PHP_URL}"; \
    echo "${PHP_SHA256}  php.tar.xz" | sha256sum -c -; \
    tar -xf php.tar.xz --strip-components=1; \
    rm php.tar.xz; \
    # Minimal NTS build: phpize needs the Zend headers + build system, the CLI is
    # only used to smoke-load the extension. json and spl are always built in.
    ./configure --prefix=/opt/php --disable-all --disable-cgi --disable-phpdbg \
        --without-pear >/dev/null; \
    make -j"$(nproc)" >/dev/null; \
    make install >/dev/null; \
    install -D -m 0644 run-tests.php /opt/php/lib/php/build/run-tests.php; \
    cd /; rm -rf /usr/src/php; \
    /opt/php/bin/php -v | head -1; \
    /opt/php/bin/php-config --extension-dir --php-binary
ENV PATH=/opt/php/bin:${PATH}
