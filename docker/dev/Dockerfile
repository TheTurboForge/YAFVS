# syntax=docker/dockerfile:1.7
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ARG NODE_VERSION=22.22.3

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget gnupg lsb-release git git-lfs xz-utils \
      build-essential cmake ninja-build ccache pkg-config \
      clang clang-tools bear \
      python3 python3-venv python3-pip pipx \
      bison flex perl jq ripgrep fd-find tree \
      libcjson-dev libcrypt-dev libcurl4-gnutls-dev libgcrypt20-dev \
      libglib2.0-dev libgnutls28-dev gnutls-bin libgpgme-dev libhiredis-dev \
      libnet1-dev libpaho-mqtt-dev libpcap-dev libssh-dev libxml2-dev \
      uuid-dev libjson-glib-dev libksba-dev libbsd-dev krb5-multidev \
      libmagic-dev libsnmp-dev gcc-mingw-w64 heimdal-dev libpopt-dev \
      libunistring-dev postgresql-server-dev-all libical-dev xsltproc \
      libmicrohttpd-dev libbrotli-dev redis-tools mosquitto-clients libcap2-bin \
      nmap pnscan python3-impacket && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /opt && \
    ln -s "/opt/node-v${NODE_VERSION}-linux-x64/bin/node" /usr/local/bin/node && \
    ln -s "/opt/node-v${NODE_VERSION}-linux-x64/bin/npm" /usr/local/bin/npm && \
    ln -s "/opt/node-v${NODE_VERSION}-linux-x64/bin/npx" /usr/local/bin/npx && \
    npm install -g npm@11

RUN pipx install uv && pipx install poetry

ENV PATH="/root/.local/bin:${PATH}" \
    CMAKE_GENERATOR=Ninja \
    CCACHE_DIR=/workspace/build/ccache
