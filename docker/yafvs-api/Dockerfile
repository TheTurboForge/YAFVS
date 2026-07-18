# syntax=docker/dockerfile:1.7
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

FROM rust:1.96-bookworm AS build

WORKDIR /src
COPY services/yafvs-api/Cargo.toml services/yafvs-api/Cargo.lock ./
COPY services/yafvs-api/src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /runtime/feeds /runtime/run/ospd \
    && chown -R 1000:1000 /runtime

COPY --from=build /src/target/release/yafvs-api /usr/local/bin/yafvs-api

USER 1000:1000
ENV YAFVS_API_BIND=0.0.0.0:9080
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/yafvs-api"]
