<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS

TurboVAS is an OpenVAS-derived monorepo for vulnerability scanner operators. It is intentionally organized around the components required to run TurboVAS as one coherent scanner system.

This repository is currently in an early private development phase. The initial source snapshot preserves upstream component boundaries and provenance so future changes can be made with clear licensing and attribution context.

## Relationship To Greenbone

TurboVAS is an independent OpenVAS-derived project. It is not affiliated with, sponsored by, or endorsed by Greenbone AG. Greenbone remains the upstream source for the imported Greenbone/OpenVAS components listed in `UPSTREAMS.md`; organizations looking for official Greenbone/OpenVAS vulnerability-management products, support, or services should contact Greenbone directly at https://www.greenbone.net/.

## Components

Imported upstream components live under `components/`.

See `UPSTREAMS.md` for source provenance and imported commit IDs. See `LICENSE_AUDIT.md` for the initial license and provenance audit notes.

## User Manual

See `docs/USER_MANUAL.md` for the current operator manual, including setup
orientation, security boundaries, scope-based reporting, and major intentional
changes from inherited OpenVAS behavior.
See `docs/CHANGES_FROM_UPSTREAM.md` for a concise public-safe overview of
intentional divergences from upstream behavior.

## Operating Model

TurboVAS is an opinionated scanner for vulnerability management operators. It is
designed around a specific operating model rather than arbitrary local process
customization. See `docs/VULNERABILITY_MANAGEMENT_PRACTICE.md`.

TurboVAS also intentionally separates technical scan targets from reporting
scopes. See `docs/SCOPE_BASED_REPORTING.md`.

For the first prescriptive reporting loop, see `docs/REPORTING_MODEL.md`.
For production posture and public-release gating, see
`docs/PRODUCTION_POSTURE.md` and `docs/PUBLIC_RELEASE_READINESS.md`.
For minimum validation expectations by change class, see
`docs/VALIDATION_STANDARDS.md`.

For current implementation flow maps and data-placement rules, see
`docs/ARCHITECTURE_FLOWS.md` and `docs/DATABASE_GRAVITY.md`.
For the native HTTP/JSON API direction and GMP/XML retirement map, see
`docs/API_CONTRACT.md`, `docs/NATIVE_API_PROOF_PLAN.md`,
`docs/GMP_XML_STRANGLER.md`, and `api/openapi/turbovas-v1.yaml`.

## Development Commands

TurboVAS provides a small root command surface for repository health checks:

- `just status`: show repository branch, HEAD, upstream, and worktree state.
- `just inventory`: list the expected monorepo components.
- `just native-tooling-state`: inventory inherited GMP, `python-gvm`, and `gvm-tools` dependency surfaces for native API retirement.
- `just rust-migration-state`: inspect Rust/C migration tools and the first non-production C-to-Rust dry-run candidate.
- `just doctor`: run structural and environment readiness checks.
- `just branding-state`: inventory visible TurboVAS/upstream identity and branding residue.
- `just quality-gate`: run the local source quality gate.
- `just quality-gate-state`: show the latest quality-gate result and retained history.
- `just quality-gate-schedule`: install, inspect, or disable the server-side development quality-gate timer.
- `just license-report`: check preserved license and provenance files.
- `just license-public-release-gate`: fail until public-release license review items are closed.
- `just production-posture-check`: run the non-destructive production posture checklist.
- `just deps [component]`: check build dependency readiness.
- `just configure <component>`: configure a CMake component into `build/<component>/`.
- `just build <component>`: build a supported component with local artifacts under ignored paths.
- `just build-core-c`: build the initial core C chain.
- `just build-c-services`: build the current C service baseline.
- `just build-ui`: install and build the web UI.
- `just build-python`: build/import-check Python components.
- `just build-baseline`: run the inherited-stack build baseline.
- `just runtime-plan`: show the persistent Docker runtime layout and deferred surfaces.
- `just up`: start the current Docker infrastructure services.
- `just down`: stop the current Docker infrastructure services.
- `just logs [service]`: show recent Docker runtime logs.
- `just runtime-init`: idempotently initialize PostgreSQL runtime prerequisites.
- `just runtime-certs-init`: create or verify persistent development certificates.
- `just runtime-manager-init`: migrate/initialize `gvmd` development database state and admin user.
- `just runtime-scanner-redis-init`: initialize scanner Redis and generated OpenVAS runtime configuration.
- `just runtime-gmp-smoke`: run an authenticated GMP smoke check.
- `just runtime-scanner-register`: create or verify the OpenVAS scanner registration.
- `just runtime-scanner-capability-check`: verify non-root OpenVAS raw-socket capabilities.
- `just runtime-scanner-process-check`: verify scanner process hygiene, including zombie child processes.
- `just runtime-nmap-capability-check`: verify non-root Nmap raw scan capability for `Full and fast`.
- `just runtime-feed-keyring-init`: initialize the shared feed signature GnuPG keyring.
- `just runtime-feed-import-init`: import the runtime feed copy into gvmd/OpenVAS state.
- `just runtime-full-test-scan-preflight`: verify readiness for the fixed authorized `192.168.178.0/24` full test scan.
- `just runtime-full-test-scan-start --confirm-authorized-lan`: start the fixed authorized full test scan.
- `just runtime-full-test-scan-status`: report the fixed full test scan task status.
- `just runtime-report-summary`: summarize the latest completed raw full-test scan report.
- `just runtime-report-export`: export parsed raw full-test scan report results as JSON, defaulting to the latest completed full-test report.
- `just runtime-report-metrics`: read CVSS Load and authenticated coverage metrics for a raw report.
- `just runtime-scope-smoke`: verify scope reporting without starting scans.
- `just runtime-scope-report-summary`: summarize the latest `Organization` scope report.
- `just runtime-scope-report-metrics`: read CVSS Load and authenticated coverage metrics for a scope report.
- `just feed-state`: show persistent feed cache and runtime-copy state.
- `just feed-cache-sync`: start a full Community Feed cache sync in `tmux`.
- `just feed-copy-to-runtime`: copy cached feed data into the runtime feed tree.
- `just runtime-status`: show Docker runtime status.
- `just runtime-smoke`: run infrastructure smoke checks.
- `just runtime-log-review`: review recent full-stack runtime logs for high-signal regressions.
- `just runtime-data-state`: inspect database-centered runtime data state, DB-owned exports, and known non-DB runtime artifacts.
- `just runtime-performance-snapshot`: capture a lightweight numeric runtime performance baseline.
- `just runtime-redis-state`: inspect scanner Redis dependency/runtime boundaries and verify generic Redis remains absent.
- `just runtime-app-up`: start experimental inherited application services.
- `just runtime-app-smoke`: run experimental application service smoke checks.
- `just runtime-native-api-smoke`: verify the internal DB-backed TurboVAS native API sidecar.
- `just runtime-webui-smoke`: verify the staged GSA web UI over `gsad`.
- `just runtime-browser-smoke`: verify raw-report and scope-report workflows through a headless browser.
- `just runtime-credential-smoke`: verify credential creation through a headless browser.
- `just runtime-app-down`: stop experimental inherited application services.
- `just gvmd-smoke`: run a narrow experimental manager profile smoke.

The commands delegate to `tools/turbovasctl`. The root `justfile` forwards
additional command arguments consistently, so JSON output can be requested via
either surface, for example:

```sh
just doctor --json
tools/turbovasctl doctor --json
```

`tools/forkctl` remains as a temporary compatibility wrapper during the command
rename.

GitHub Actions also runs the source-only quality gate in
`.github/workflows/quality-gate.yml` on pushes to `main`, pull requests, and
manual dispatch. That hosted gate uses the same
`tools/turbovasctl quality-gate --json` contract as local development, but it
does not start runtime services, run scans, sync/copy feeds, or perform public
release gating. The server-side systemd timer remains the runtime-capable daily
development gate.

See `BUILDING.md` for the current build baseline and `docker/runtime/README.md` for the current runtime groundwork.
