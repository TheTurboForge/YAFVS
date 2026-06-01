<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Runtime Groundwork

This directory documents the development/runtime Docker scaffolding. It is not a
production deployment definition yet.

The default Compose stack starts infrastructure services:

- Postgres, using a TurboVAS development image with pg-gvm runtime dependencies
- Redis for inherited generic runtime surfaces
- Redis for OpenVAS scanner KB state, using a Unix socket only
- Mosquitto
- optional `dev-shell` profile for toolchain/container experiments

The experimental `app` profile adds inherited application services:

- `gvmd`, using the persistent Postgres database and a runtime Unix socket
- `ospd-openvas`, wired to the built OpenVAS scanner binary, scanner Redis Unix socket, and runtime OSP socket path
- `gsad`, exposed on `127.0.0.1:19392` for local HTTPS/API smoke checks

Persistent state is stored outside the repository by default, normally in the
sibling `TurboVAS-runtime` directory. Runtime commands create host-visible
storage for Postgres, Redis, scanner Redis, Mosquitto, feeds, run sockets, logs,
artifacts, certificates, secrets, and service state.

The services bind host ports to `127.0.0.1` only. The scanner Redis service does
not expose a host TCP port. Source, `build/`, and `build/prefix` are bind-mounted
for fast development feedback instead of forcing container rebuilds after small
source changes. App containers also mount the checkout at
`/home/turboforge/Projects/TurboVAS` because the current CMake build baseline
embeds inherited development paths under that location.

## Commands

Use the root `justfile` command surface:

- `just runtime-plan`
- `just up`
- `just runtime-certs-init`
- `just runtime-init`
- `just runtime-manager-init`
- `just runtime-scanner-redis-init`
- `just runtime-status`
- `just runtime-smoke`
- `just runtime-app-up`
- `just runtime-gmp-smoke`
- `just runtime-scanner-register`
- `just runtime-app-smoke`
- `just runtime-app-down`
- `just down`

`runtime-certs-init` uses inherited `gvm-manage-certs` with persistent runtime
certificate directories and does not rotate existing certificates.

`runtime-init` copies `pg-gvm` extension files into the active Postgres container
and creates or verifies the `dba` role, role grant, and `pg-gvm` extension. It
must not delete or recreate existing runtime data.

`runtime-manager-init` runs the `gvmd` database migration, creates or verifies a
local development admin user, stores the generated development password under
the runtime `secrets/` directory, and sets the feed import owner when possible.

`runtime-scanner-redis-init` starts the dedicated scanner Redis service, writes
the ignored development OpenVAS config under `build/prefix/etc/openvas/`, and
verifies that `openvas -s` reports the scanner Redis Unix socket as `db_address`.

`runtime-gmp-smoke` authenticates over the persistent `gvmd` Unix socket with a
small `python-gvm` probe and calls `get_version` without printing secrets.

`runtime-scanner-register` creates or verifies the `OpenVAS Default` scanner
registration against `/runtime/run/ospd/ospd-openvas.sock` on port `0`.

## Current App Runtime Status

The current app profile reaches inherited manager-scanner connectivity:

- `gvmd` starts and creates `/runtime/run/gvmd/gvmd.sock`.
- authenticated GMP `get_version` succeeds over the runtime Unix socket.
- scanner Redis is reachable through `/runtime/run/redis-openvas/redis.sock`.
- `ospd-openvas` starts and creates `/runtime/run/ospd/ospd-openvas.sock`.
- `OpenVAS Default` is registered and verified by `gvmd` against the OSPD socket.
- `gsad` starts in API-only mode and responds on loopback HTTPS.

`runtime-app-smoke` currently reports `warn` because `ospd-openvas` logs inherited
VT loading errors when no feed/plugin cache exists yet. That is expected for this
phase and is intentionally surfaced as a warning instead of hidden.

Full feed population, feed/plugin cache initialization, Notus bring-up, scan
execution, and production packaging are intentionally deferred.
