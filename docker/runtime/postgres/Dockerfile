# syntax=docker/dockerfile:1.7
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

FROM postgres:16-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    LD_LIBRARY_PATH=/yafvs-prefix/lib:/yafvs-prefix/lib64

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libglib2.0-0t64 \
      libical3t64 && \
    rm -rf /var/lib/apt/lists/*
