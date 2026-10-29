# syntax=docker/dockerfile:1
#
# Release builder for the musl builds (Alpine, the libc of php:<ver>-cli-alpine).
#
#   --target rust   Alpine + Rust 1.96.0 (rustup, musl host toolchain, pinned like
#                   core/rust-toolchain.toml). Builds the Rust core with
#                   RUSTFLAGS="-C target-feature=-crt-static" (the core is linked
#                   into a dynamically loaded shared object, so the default static
#                   CRT of the musl target must be off) and without --target, so
#                   proc macros and build scripts use the same flags.
#   --target link   the official php:<ver>-cli-alpine image + the phpize toolchain.
#                   The extension is linked against the exact headers and ABI of
#                   the image it is meant to run on.
#
# Driven by ./dev dist.
ARG ALPINE_VERSION=3.23
ARG PHP_IMAGE=php:8.4-cli-alpine

FROM alpine:${ALPINE_VERSION} AS rust
ARG RUST_VERSION=1.96.0
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    PATH=/opt/cargo/bin:${PATH}
RUN apk add --no-cache build-base ca-certificates curl git
RUN set -eux; \
    triple="$(uname -m)-unknown-linux-musl"; \
    cd /tmp; \
    curl -fsSLO "https://static.rust-lang.org/rustup/dist/${triple}/rustup-init"; \
    curl -fsSL "https://static.rust-lang.org/rustup/dist/${triple}/rustup-init.sha256" \
        | awk '{print $1 "  rustup-init"}' | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal \
        --default-host "${triple}" --default-toolchain "${RUST_VERSION}"; \
    rm rustup-init; \
    chmod -R a+rX /opt/rustup /opt/cargo; \
    cargo --version; rustc --version
ENV HOME=/tmp

FROM ${PHP_IMAGE} AS link
RUN apk add --no-cache $PHPIZE_DEPS binutils
ENV HOME=/tmp
