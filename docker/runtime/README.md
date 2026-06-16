<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Runtime Groundwork

This directory documents the development/runtime Docker scaffolding. It is not a
production deployment definition yet.

The default Compose stack starts infrastructure services:

- Postgres, using a TurboVAS development image with pg-gvm runtime dependencies
- Redis for OpenVAS scanner KB state, using a Unix socket only
- Mosquitto
- optional `dev-shell` profile for toolchain/container experiments

The experimental `app` profile adds inherited application services:

- `gvmd`, using the persistent Postgres database and a runtime Unix socket
- `ospd-openvas`, wired to the built OpenVAS scanner binary, scanner Redis Unix socket, and runtime OSP socket path
- `notus-scanner`, wired to the runtime Notus feed copy and Mosquitto
- `gsad`, exposed on `127.0.0.1:19392` by default for local HTTPS UI/API smoke checks

Persistent state is stored outside the repository by default, normally in the
sibling `TurboVAS-runtime` directory. Runtime commands create host-visible
storage for Postgres, scanner Redis, Mosquitto, feeds, run sockets, logs,
artifacts, certificates, secrets, and service state.

Infrastructure services bind host ports to `127.0.0.1` only. `gsad` also
defaults to loopback, but can be explicitly bound for development by setting
`TURBOVAS_GSAD_HOST` for one address or comma-separated `TURBOVAS_GSAD_HOSTS`
for multiple addresses before startup. The generated GSA `config.js` uses the
browser's current host so each configured URL can talk back to the same `gsad`
endpoint. TurboVAS no longer starts the inherited generic Redis service in the
development runtime. The scanner Redis service does not expose a host TCP port. Source,
`build/`, and `build/prefix` are bind-mounted for fast development feedback
instead of forcing container rebuilds after small source changes. App containers
also mount the checkout at
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
- `just runtime-log-review`
- `just runtime-data-state`
- `just runtime-performance-snapshot`
- `just quality-gate-state`
- `just quality-gate-schedule --status`
- `just runtime-app-up`
- `just runtime-gmp-smoke`
- `just runtime-scanner-register`
- `just runtime-scanner-capability-check`
- `just runtime-scanner-process-check`
- `just runtime-nmap-capability-check`
- `just runtime-feed-keyring-init`
- `just runtime-feed-import-init`
- `just runtime-app-smoke`
- `just runtime-webui-smoke`
- `just runtime-browser-smoke`
- `just runtime-credential-smoke`
- `just runtime-app-down`
- `just down`

`runtime-log-review` writes redacted recent log tails and a JSON finding set
under the runtime artifact tree. `runtime-data-state` reports the current
database version, expected live tables, removed feature-table absence, known
non-database runtime state, DB-owned exports, and a product-data audit that
warns only when product-looking data lacks a gvmd/PostgreSQL source of record.
`runtime-performance-snapshot` captures parsed Docker CPU/memory/I/O/PID
numbers, database size and largest relations, artifact paths, and build-size
facts for future instrumentation work; it writes a latest JSON artifact plus
retained timestamped history and does not optimize or mutate runtime state.
`quality-gate-state` reports retained quality-gate history.
`quality-gate-schedule` manages the development user-level systemd timer on
`turboforge-server`; it does not fall back to cron if user systemd is
unavailable.

The GitHub Actions quality-gate workflow is deliberately source-only. It shares
the same `tools/turbovasctl quality-gate --json` contract, but does not start
Docker runtime services, scans, feed sync/copy commands, or public-release
gates. Runtime-aware continuous checking belongs to the server-side timer.

`runtime-certs-init` uses inherited `gvm-manage-certs` with persistent runtime
certificate directories and does not rotate existing certificates.

`runtime-init` copies `pg-gvm` extension files into the active Postgres container
and creates or verifies the `dba` role, role grant, and `pg-gvm` extension. It
must not delete or recreate existing runtime data.

`runtime-manager-init` runs the `gvmd` database migration, creates or verifies a
local development admin user, stores the local development password under the
runtime `secrets/` directory, aligns it to the `admin` / `admin` development
default, and sets the feed import owner when possible.

`runtime-scanner-redis-init` starts the dedicated scanner Redis service, writes
the ignored development OpenVAS config under `build/prefix/etc/openvas/`, and
verifies that `openvas -s` reports the scanner Redis Unix socket as `db_address`.

`runtime-gmp-smoke` authenticates over the persistent `gvmd` Unix socket with a
small `python-gvm` probe and calls `get_version` without printing secrets.

`runtime-scanner-register` creates or verifies the `OpenVAS Default` scanner
registration against `/runtime/run/ospd/ospd-openvas.sock` on port `0`.

`runtime-scanner-capability-check` verifies that `ospd-openvas` PID 1 runs as
the development UID/GID with effective/permitted/ambient `NET_RAW` and
`NET_ADMIN`, that the scanner service uses a stable non-hex hostname for NASL
packet-capture filters, and that the same service-user path can open an ICMP raw
socket.

`runtime-scanner-process-check` verifies scanner process hygiene and fails when
an idle `ospd-openvas` container has zombie child processes left behind by
OpenVAS, Nmap, or helper subprocesses.

`runtime-nmap-capability-check` verifies that the scanner image can run
representative Nmap raw SYN and OS-detection probes as the development UID/GID
with `NMAP_PRIVILEGED=1` and file capabilities on `/usr/bin/nmap`.

## Current App Runtime Status

The current app profile reaches inherited manager-scanner connectivity:

- `gvmd` starts and creates `/runtime/run/gvmd/gvmd.sock`.
- authenticated GMP `get_version` succeeds over the runtime Unix socket.
- scanner Redis is reachable through `/runtime/run/redis-openvas/redis.sock`.
- `ospd-openvas` starts and creates `/runtime/run/ospd/ospd-openvas.sock`.
- `ospd-openvas` runs as the development UID/GID with only the raw-socket
  capabilities needed for scanner alive detection.
- `notus-scanner` starts against the runtime Notus feed copy.
- `OpenVAS Default` is registered and verified by `gvmd` against the OSPD socket.
- `gsad` serves the staged GSA web UI and responds on the configured HTTPS host binding.

Full feed population, feed import, scan execution, and production packaging
remain guarded development surfaces rather than production deployment behavior.
