<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Building YAFVS

YAFVS currently has a local required build baseline for:

- C services: `gvm-libs`, `openvas-smb`, `openvas-scanner`, `pg-gvm`, `gvmd`, `gsad`
- Web UI: `gsa`
- Runtime Python components: `greenbone-feed-sync`, `ospd-openvas`, `notus-scanner`

Build output, local install artifacts, Python virtual environments, and component dependency directories are kept under ignored paths. C components install into `build/prefix` when downstream components need their pkg-config metadata and headers.

## Commands

Check dependency readiness:

```sh
just deps
just deps gvmd
just deps gsa
```

Build one supported component:

```sh
just build gvmd
just build gsad
just build pg-gvm
just build gsa
```

Build grouped baselines:

```sh
just build-core-c
just build-c-services
just build-ui
just build-python   # retained runtime Python components
just build-baseline
just quality-gate
just quality-gate-state
just quality-gate-schedule --status
just production-posture-check --json
```

Machine-readable output is available through the command recipes. The recipes
select the active Rust or Python implementation for each command; use the
entrypoints directly only when testing a specific implementation.

```sh
just deps --json
tools/yafvsctl build-baseline --json
tools/yafvsctl quality-gate-state --json
tools/yafvsctl production-posture-check --json
just rust-migration-state --json
tools/yafvsctl runtime-native-api-smoke --json
```

## Quality Gates

`just quality-gate` and `tools/yafvsctl quality-gate --json` are the local
source-quality contract. They run the routine license report, doctor checks,
Python unit tests, Python compile checks, Docker Compose config validation,
Rust CLI and native API formatting/tests when present, GSA type-checking, and
the fast GSA web test suite.

`.github/workflows/quality-gate.yml` runs that same source-only contract in
GitHub Actions on pushes to `main`, pull requests, and manual dispatch. Hosted
CI intentionally does not start app runtime services, start scans, mutate feeds,
or run the stricter public-release license gate. Runtime-aware continuous
checking remains on the development server through the `quality-gate-schedule`
systemd timer and retained runtime artifacts.

`just production-posture-check --json` is a separate non-destructive checklist.
It is expected to fail or warn while YAFVS is still using development
credentials, development TLS material, and a development-only Docker runtime.

## Retained C Hardening

The current required C compile check is `just build-c-services`. Existing
components apply some hardening, but coverage varies by component and build
type; this command alone does not prove final binary protections.

The planned hardened, sanitizer, analysis, and ELF-verification profiles are
defined in `docs/C_HARDENING.md`. Do not treat those profiles as available
until their command surfaces and machine-readable evidence have landed.

## Notes

The server baseline uses the Ubuntu `libcurl4-gnutls-dev` package because the scanner build expects the GnuTLS curl variant. The C service documentation build also expects `xmltoman` and `xmlmantohtml`; `just deps gvmd`, `just deps gsad`, and `just deps openvas-smb` check those tools explicitly so missing manpage-generation dependencies show up before a build.

The scanner build currently passes `-isystem /usr/include/mit-krb5` through
`yafvsctl` because Ubuntu's `mit-krb5-gssapi` pkg-config metadata exposes the
GSSAPI header path there. This keeps the Phase 2 baseline reproducible without
modifying imported source code.

The web UI baseline uses Node.js 22 with npm 11 from an official Node.js binary installation on the development server. The NodeSource apt repository was not used for the final install because its dry-run transaction would have removed unrelated distro Node tooling.

The Python baseline uses `uv` with per-component virtual environments under `build/venvs`.

## Runtime Groundwork

The current Docker runtime baseline starts infrastructure services and an
experimental inherited application profile:

```sh
just runtime-plan
just up
just runtime-certs-init
just runtime-init
just runtime-manager-init
just runtime-scanner-redis-init
just runtime-gmp-smoke
just runtime-scanner-register
just runtime-scanner-capability-check
just runtime-feed-keyring-init
TARGET_CIDR='replace-with-an-authorized-cidr'
just runtime-full-test-scan-preflight --target-cidr "$TARGET_CIDR"
just runtime-full-test-scan-start --target-cidr "$TARGET_CIDR" --confirm-authorized-target "$TARGET_CIDR"
just runtime-full-test-scan-status --target-cidr "$TARGET_CIDR"
just feed-state
just feed-cache-sync
just feed-generation-stage
just feed-generation-state --status-only
just feed-generation-activate -- <generation-id> [--allow-first-activation]
just feed-generation-rollback -- <generation-id>
just runtime-status
just runtime-smoke
just runtime-log-review # service-specific high-signal runtime log review
just runtime-data-state      # includes DB-owned export classification and product-data audit
just runtime-performance-snapshot # numeric Docker/DB/report-workflow/static-asset baseline, thresholdless
just quality-gate-state
just quality-gate-schedule --status
just runtime-app-up
just runtime-app-smoke
just runtime-webui-smoke
just runtime-browser-smoke
just runtime-browser-regression
just runtime-credential-smoke
just runtime-app-down
just down
```

Runtime state is host-visible and persistent under the sibling
`TurboVAS-runtime` directory by default when commands are run through
`tools/yafvsctl`. `runtime-certs-init`, `runtime-init`,
`runtime-manager-init`, scanner Redis/config initialization, and scanner
registration are designed to be idempotent and must not delete or recreate
unrelated runtime data. Feed generation activation and rollback are separate
guarded operations and must be treated as service-coordinated changes.

The current app profile can start `gvmd`, `ospd-openvas`, `notus-scanner`, and
`gsad` for service-health checks. `ospd-openvas` starts through a root
entrypoint that immediately drops to the development UID/GID with only
`NET_RAW`/`NET_ADMIN` ambient capabilities so Boreas/OpenVAS can open raw
sockets without a privileged container or host networking.
`runtime-scanner-capability-check` verifies that runtime state before scans.
Feed downloads use a persistent local Community Feed cache under
`TurboVAS-runtime/feed-cache/`. `feed-generation-stage` seals that cache into a
content-addressed generation, and retained app services consume only the
verified `TurboVAS-runtime/feed-store/current` generation through
`/runtime/feeds`. OSPD and Notus share a persistent feed signature keyring under
`TurboVAS-runtime/state/feed-gnupg`.
`feed-generation-activate` verifies the selected generation, coordinates the
app services around the pointer switch, and verifies the resulting runtime
state. It fails closed unless the database proves that no scan task is active.
A durable owner-only journal distinguishes a completed import from an
interrupted transition, and app startup refuses any selector/journal mismatch.
The first activation requires an explicit acknowledgement. If a
verified activation needs to be undone, `feed-generation-rollback` performs
service-coordinated, verified compensating recovery to a prior generation; it
accepts only the journaled known-good predecessor and does not claim a
transactional database rollback. Full-test scan commands require an explicit
canonical `--target-cidr`, retain the `Full and fast` scan config and `All IANA
assigned TCP and UDP` port list, and reject targets larger than 256 addresses.
Starting a scan also requires `--confirm-authorized-target` with the exact same
CIDR. YAFVS does not ship a real network target or infer authorization.

`build-ui` stages the GSA production bundle under
`build/prefix/share/gvm/gsad/web` and writes a development `config.js` for the
active browser endpoint. `gsad` defaults to loopback host binding; for a single
development address set `TURBOVAS_GSAD_HOST` before `runtime-app-up`, or for
multiple explicit development addresses set comma-separated
`TURBOVAS_GSAD_HOSTS`. Run `runtime-webui-smoke` with the same environment to
verify every configured URL. The local development admin credentials are
`admin` / `admin`; do not treat those defaults as production credentials.
