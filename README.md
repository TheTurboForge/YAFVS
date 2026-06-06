<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS

TurboVAS is an OpenVAS-derived monorepo for vulnerability scanner operators. It is intentionally organized around the components required to run OpenVAS Scan / TurboVAS as one coherent scanner system.

This repository is currently in an early private development phase. The initial source snapshot preserves upstream component boundaries and provenance so future changes can be made with clear licensing and attribution context.

## Relationship To Greenbone

TurboVAS is an independent OpenVAS-derived project. It is not affiliated with, sponsored by, or endorsed by Greenbone AG. Greenbone remains the upstream source for the imported Greenbone/OpenVAS components listed in `UPSTREAMS.md`; organizations looking for official Greenbone/OpenVAS vulnerability-management products, support, or services should contact Greenbone directly at https://www.greenbone.net/.

## Components

Imported upstream components live under `components/`.

See `UPSTREAMS.md` for source provenance and imported commit IDs. See `LICENSE_AUDIT.md` for the initial license and provenance audit notes.

## Operating Model

TurboVAS is an opinionated scanner for vulnerability management operators. It is
designed around a specific operating model rather than arbitrary local process
customization. See `docs/VULNERABILITY_MANAGEMENT_PRACTICE.md`.

TurboVAS also intentionally separates technical scan targets from reporting
scopes. See `docs/SCOPE_BASED_REPORTING.md`.

## Development Commands

TurboVAS provides a small root command surface for repository health checks:

- `just status`: show repository branch, HEAD, upstream, and worktree state.
- `just inventory`: list the expected monorepo components.
- `just doctor`: run structural and environment readiness checks.
- `just license-report`: check preserved license and provenance files.
- `just license-public-release-gate`: fail until public-release license review items are closed.
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
- `just runtime-feed-keyring-init`: initialize the shared feed signature GnuPG keyring.
- `just runtime-feed-import-init`: import the runtime feed copy into gvmd/OpenVAS state.
- `just runtime-full-test-scan-preflight`: verify readiness for the fixed authorized `192.168.178.0/24` full test scan.
- `just runtime-full-test-scan-start --confirm-authorized-lan`: start the fixed authorized full test scan.
- `just runtime-full-test-scan-status`: report the fixed full test scan task status.
- `just runtime-report-summary`: summarize the latest raw full-test scan report.
- `just runtime-report-export`: export parsed raw full-test scan report results as JSON.
- `just runtime-scope-smoke`: verify scope reporting without starting scans.
- `just runtime-scope-report-summary`: summarize the latest `Organization` scope report.
- `just feed-state`: show persistent feed cache and runtime-copy state.
- `just feed-cache-sync`: start a full Community Feed cache sync in `tmux`.
- `just feed-copy-to-runtime`: copy cached feed data into the runtime feed tree.
- `just runtime-status`: show Docker runtime status.
- `just runtime-smoke`: run infrastructure smoke checks.
- `just runtime-app-up`: start experimental inherited application services.
- `just runtime-app-smoke`: run experimental application service smoke checks.
- `just runtime-webui-smoke`: verify the staged GSA web UI over `gsad`.
- `just runtime-app-down`: stop experimental inherited application services.
- `just gvmd-smoke`: run a narrow experimental manager profile smoke.

The commands delegate to `tools/turbovasctl`, which also supports JSON output for
automation, for example:

```sh
tools/turbovasctl doctor --json
```

`tools/forkctl` remains as a temporary compatibility wrapper during the command
rename.

See `BUILDING.md` for the current build baseline and `docker/runtime/README.md` for the current runtime groundwork.
