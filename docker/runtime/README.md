<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Runtime Groundwork

This directory documents the development/runtime Docker scaffolding. It is not a
production deployment definition yet.

The default Compose stack starts infrastructure services:

- Postgres, using a TurboVAS development image with pg-gvm runtime dependencies
- Redis for OpenVAS scanner KB state, using a Unix socket only
- Mosquitto, with runtime-only credentials and ACLs limited to the retained
  OpenVAS/Notus message flow
- optional `dev-shell` profile for toolchain/container experiments

The experimental `app` profile adds inherited application services:

- `gvmd`, using the persistent Postgres database and a runtime Unix socket
- `ospd-openvas`, wired to the built OpenVAS scanner binary, scanner Redis Unix socket, and runtime OSP socket path
- `notus-scanner`, wired to the active Notus feed generation and Mosquitto
- `gsad`, exposed on `127.0.0.1:19392` by default for local HTTPS UI/API smoke checks
- `turbovas-api`, a Rust proof service for DB-backed typed HTTP/JSON reads;
  internal by default, with an opt-in bearer-auth direct development listener

Persistent state is stored outside the repository by default, normally in the
sibling `TurboVAS-runtime` directory. Runtime commands create host-visible
storage for Postgres, scanner Redis, Mosquitto, feeds, run sockets, logs,
artifacts, certificates, secrets, and service state.

`tools/turbovasctl` creates the ignored runtime-only MQTT passwords before it
starts the broker. A raw `docker compose up` must supply those passwords
explicitly; empty broker credentials intentionally fail startup.

Infrastructure services bind host ports to `127.0.0.1` only. `gsad` also
defaults to loopback, but can be explicitly bound for development by setting
`TURBOVAS_GSAD_HOST` for one address or comma-separated `TURBOVAS_GSAD_HOSTS`
for multiple addresses before startup. The generated GSA `config.js` uses the
browser's current host so each configured URL can talk back to the same `gsad`
endpoint. TurboVAS no longer starts the inherited generic Redis service in the
development runtime. The scanner Redis service does not expose a host TCP port.
The native API sidecar is not published on any host port by default; smoke
checks reach it from inside the Docker network. Direct development access is an
explicit opt-in mode that publishes a separate bearer-auth listener, defaulting
to `127.0.0.1:19080`. Source,
`build/`, and `build/prefix` are bind-mounted for fast development feedback
instead of forcing container rebuilds after small source changes. App
containers also mount the checkout at the absolute path supplied through
`TURBOVAS_REPO_MOUNT_PATH` because the current CMake build baseline embeds its
development checkout path. `tools/turbovasctl` supplies the current repository
root automatically. Direct `docker compose` use must set the variable
explicitly; there is no machine-specific fallback.

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
- `just feed-generation-stage`
- `just feed-generation-state --status-only`
- `just feed-generation-activate -- <generation-id> [--allow-first-activation]`
- `just feed-generation-rollback -- <generation-id>`
- `just runtime-app-smoke`
- `just runtime-native-api-smoke`
- `just runtime-native-api-direct-smoke`
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
`quality-gate-schedule` manages a development user-level systemd timer only
when the operator explicitly sets `TURBOVAS_ENABLE_QUALITY_GATE_SCHEDULE=1`.
It does not assume a hostname or account and does not fall back to cron if user
systemd is unavailable.

The GitHub Actions quality-gate workflow is deliberately source-only. It shares
the same `tools/turbovasctl quality-gate --json` contract, but does not start
Docker runtime services, scans, feed sync/copy commands, or public-release
gates. Runtime-aware continuous checking belongs to the server-side timer.

`feed-generation-stage` builds a sealed generation from all retained Community
Feed cache classes under the private runtime `feed-store/generations` directory.
Its identifier covers the sorted class layout, every file length and SHA-256
digest, and the feed release. Staging rejects unsafe filesystem entries and
source mutation, fsyncs the completed tree, and uses atomic no-replace
installation. It does not create or change the `feed-store/current` pointer and
therefore does not activate content. `feed-generation-state` performs a full
manifest, layout, permission, size, and digest verification of installed
generations and reports orphan staging directories.
`feed-generation-activate` accepts only a verified generation, coordinates the
app services while switching the `feed-store/current` pointer, and verifies the
active runtime after the switch. It first stops scanner-control services and
rechecks the database so no scan can cross the transition boundary. NVT
metadata is rebuilt for every selected generation; a matching publisher
version string is not treated as content identity. A durable owner-only journal
blocks app startup after an interrupted or mismatched transition. The first
activation requires an explicit acknowledgement and may resume only its recorded target.
Later interrupted transitions recover only through `feed-generation-rollback`
to the journaled known-good predecessor. Recovery is service-coordinated and
verified; it reimports prior data but does not claim a transactional database
rollback.
Available Greenbone signatures and exact signed checksum coverage are required
for NASL, Notus, and CERT content. SCAP and GVMD data objects are fully hashed
and generation-bound, but the upstream cache currently supplies no equivalent
signed checksum manifests for those two classes; this residual authenticity
limit is kept explicit.

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
the ignored development OpenVAS config under runtime state, and verifies that
`openvas -s` reports the scanner Redis Unix socket as `db_address`. The
generated config carries the runtime-only OpenVAS MQTT credential and is mounted
only into OSPD; do not copy it into tracked configuration or operator artifacts.

`runtime-gmp-smoke` authenticates over the persistent `gvmd` Unix socket with
a bounded raw compatibility probe and calls `get_version` without printing
secrets or requiring a legacy Python client.

`runtime-native-api-smoke` verifies the internal `turbovas-api` sidecar by
querying `/healthz`, `/api/v1/scope-reports`, and the first scope report's
DB-backed Results, Hosts, CVEs, Error Messages, and Metrics collections from
inside the Docker network. It does not publish a host port and does not use
GMP/XML for the tested read path.

`runtime-native-api-direct-smoke` enables the opt-in direct development listener
for `turbovas-api`, defaulting to `127.0.0.1:19080`, verifies that `/healthz`
is reachable without a token, verifies that `/api/v1/...` rejects missing or
wrong bearer tokens, verifies a valid bearer token, checks request-ID headers
and absent browser CORS access headers, checks bounded direct request-shape
denials, and reruns the internal native API smoke. The helper creates or reuses
the ignored runtime secret `native-api-bearer-token`; it does not make direct
API exposure the default.

`runtime-scope-report-metrics` now uses this internal native API path for scope
report metrics. `runtime-report-metrics` still uses the inherited GMP/XML helper
until a raw-report metrics endpoint lands.

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

- `gvmd` creates separate GMP and native-control sockets. `gsad` receives only
  the GMP socket mount; `turbovas-api` receives only the native-control socket
  mount and a distinct control secret from the browser-proxy secret.
- authenticated GMP `get_version` succeeds over the runtime Unix socket.
- scanner Redis is reachable through `/runtime/run/redis-openvas/redis.sock`.
- `ospd-openvas` starts and creates `/runtime/run/ospd/ospd-openvas.sock`.
- `ospd-openvas` runs as the development UID/GID with only the raw-socket
  capabilities needed for scanner alive detection.
- `notus-scanner` starts against the active Notus feed generation.
- `OpenVAS Default` is registered and verified by `gvmd` against the OSPD socket.
- `gsad` serves the staged GSA web UI and responds on the configured HTTPS host binding.
- `turbovas-api` is available inside the Docker network as the DB-first native
  API proof. Direct API development access is available only through the
  explicit bearer-auth direct mode, which defaults to loopback and is not a
  production exposure model.

Full feed population, feed generation activation or rollback, scan execution,
and production packaging remain guarded development surfaces rather than
production deployment behavior.
