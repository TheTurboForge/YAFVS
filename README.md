<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS

TurboVAS is an OpenVAS-derived monorepo for vulnerability scanner operators. It is intentionally organized around the components required to run TurboVAS as one coherent scanner system.

TurboVAS uses an operator-only console model. A TurboVAS login is for trusted
scanner operators who may administer the scanner; remediation stakeholders
should receive findings through reports, exports, notifications, or future
delivery integrations rather than through broad in-product accounts. This is an
intentional product/security boundary, not an attempt to model every
organization's internal workflow as roles inside the scanner console.

This repository is currently in an early development phase. The initial source snapshot preserves upstream component boundaries and provenance so future changes can be made with clear licensing and attribution context. Public source visibility, if enabled, is for source transparency only and is not a binary release, container release, hosted service, production deployment, feed mirror, or feed redistribution.

## Relationship To Greenbone

TurboVAS is an independent OpenVAS-derived project. It is not affiliated with, sponsored by, or endorsed by Greenbone AG. Greenbone remains the upstream source for the imported Greenbone/OpenVAS components listed in `UPSTREAMS.md`; organizations looking for official Greenbone/OpenVAS vulnerability-management products, support, or services should contact Greenbone directly at https://www.greenbone.net/.

TurboVAS supports the Greenbone Community Feed only. It does not support
Greenbone Enterprise Feed subscription keys or Enterprise Feed synchronization.
Organizations that need Greenbone Enterprise Feed access, official Greenbone
products, or vendor support should contact Greenbone directly.

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

## Memory Safety Direction

TurboVAS is incrementally reducing reliance on memory-unsafe implementation.
New security-sensitive backend functionality is Rust-first. Existing C is not
being mechanically rewritten wholesale: unnecessary components are removed,
exposed and high-consequence boundaries are prioritized, and retained C is
hardened and tested until a validated replacement is appropriate.

See `docs/MEMORY_SAFETY.md` for the rationale, migration policy, limitations,
and validation expectations. See `docs/C_HARDENING.md` for the concrete public
commitments governing C that remains.

For current implementation flow maps and data-placement rules, see
`docs/ARCHITECTURE_FLOWS.md` and `docs/DATABASE_GRAVITY.md`.
For the native HTTP/JSON API direction and GMP/XML retirement map, see
`docs/API_CONTRACT.md`, `docs/NATIVE_API_PROOF_PLAN.md`,
`docs/GMP_XML_STRANGLER.md`, and `api/openapi/turbovas-v1.yaml`.

## Contributions And Security Reports

Public source visibility is intended for transparency at this stage. TurboVAS
is not currently seeking external contributions and does not provide a support
promise. See `CONTRIBUTING.md` and `SECURITY.md` before opening issues or pull
requests, and do not submit secrets, scan results, customer data, private
configuration, or other sensitive material.

## Development Commands

TurboVAS provides a small root command surface for repository health checks. See
`docs/VALIDATION_STANDARDS.md` for which gate answers which source, runtime,
browser, direct API, production-posture, or release-readiness question.

- `just status`: show repository branch, HEAD, upstream, and worktree state.
- `just inventory`: list the expected monorepo components.
- `just native-tooling-state --status-only --json`: inventory inherited GMP, `python-gvm`, and `gvm-tools` dependency surfaces for native API retirement with chat-safe status/non-pass output. Use `--summary` for compact count/contract detail, and reserve `--compact` for review work that needs removal-candidate paths.
- `just rust-migration-state`: inspect Rust/C migration tools and the first non-production C-to-Rust dry-run candidate.
- `just doctor`: run structural and environment readiness checks.
- `just branding-state`: inventory visible TurboVAS/upstream identity and branding residue, including public image assets and SVG icon files.
- `just quality-gate`: run the local source quality gate.
- `just quality-gate-state`: show the latest quality-gate result and retained history.
- `just quality-gate-schedule`: install, inspect, or disable the server-side development quality-gate timer.
- `just license-report`: check preserved license and provenance files.
- `just license-public-release-gate --mode source-public`: check source-public license/provenance readiness while keeping stricter binary, container, hosted-service, and feed-redistribution modes blocked until separately reviewed.
- `just production-posture-check`: run the non-destructive production posture checklist.
- `just deps [component]`: check build dependency readiness.
- `just configure <component>`: configure a CMake component into `build/<component>/`.
- `just build <component>`: build a supported component with local artifacts under ignored paths.
- `just build-core-c`: build the initial core C chain.
- `just build-c-services`: build the current C service baseline.
- `just c-hardening-check --status-only --json`: inspect current final C ELF artifacts and report missing, unsupported, inapplicable, or unknown hardening evidence without changing build flags.
- `just build-ui`: install and build the web UI.
- `just build-python`: build/import-check all Python components, including inherited compatibility clients.
- `just build-baseline`: run the current required build baseline without `python-gvm` or `gvm-tools`.
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
- `just runtime-full-test-scan-preflight`: verify readiness for the fixed authorized `192.168.178.0/24` full test scan.
- `just runtime-full-test-scan-start --confirm-authorized-lan`: start the fixed authorized full test scan.
- `just runtime-full-test-scan-status`: report the fixed full test scan task status.
- `just runtime-report-summary`: summarize the latest completed raw full-test scan report.
- `just runtime-report-export`: export parsed raw full-test scan report results as JSON, defaulting to the latest completed full-test report.
- `just runtime-report-metrics`: read CVSS Load and authenticated coverage metrics for a raw report.
- `just runtime-scope-smoke`: verify scope reporting without starting scans.
- `just runtime-scope-report-summary`: summarize the latest `Organization` scope report.
- `just runtime-scope-report-metrics`: read CVSS Load and authenticated coverage metrics for a scope report through the internal native API.
- `just feed-state`: show persistent feed cache and active-generation state.
- `just feed-cache-sync`: start a full Community Feed cache sync in `tmux`.
- `just feed-generation-stage`: create and verify a sealed, content-addressed feed generation without activating it.
- `just feed-generation-state --status-only --json`: verify staged feed generations and report orphan or tampered state.
- `just runtime-app-build`: explicitly build application images without changing feed state or starting services.
- `just feed-generation-activate -- <generation-id> [--allow-first-activation]`: activate a verified generation through the service-coordinated, guarded activation path.
- `just feed-generation-rollback -- <generation-id>`: perform verified compensating recovery only to the journaled known-good predecessor; this is not a transactional database rollback.
- `just runtime-status`: show Docker runtime status.
- `just runtime-smoke`: run infrastructure smoke checks.
- `just runtime-log-review`: review recent full-stack runtime logs for high-signal regressions.
- `just runtime-data-state`: inspect database-centered runtime data state, DB-owned exports, and known non-DB runtime artifacts.
- `just runtime-performance-snapshot`: capture a lightweight numeric runtime performance baseline.
- `just runtime-redis-state`: inspect scanner Redis dependency/runtime boundaries and verify generic Redis remains absent.
- `just runtime-app-up`: start experimental inherited application services.
- `just runtime-app-smoke`: run experimental application service smoke checks.
- `just runtime-native-api-smoke`: verify the internal DB-backed TurboVAS native API sidecar.
- `just runtime-native-api-direct-smoke`: verify opt-in bearer-auth direct native API development access.
- `just runtime-webui-smoke`: verify the staged GSA web UI over `gsad`.
- `just runtime-browser-smoke`: verify raw-report and scope-report workflows through a headless browser.
- `just runtime-browser-regression`: run deeper browser route, link, and pagination regression checks.
- `just runtime-credential-smoke`: verify credential creation through a headless browser.

Because the development services consume read-only bind mounts from `build/`,
runtime-affecting component builds and `runtime-app-build` refuse to run while
application services are active. Run `runtime-app-down`, build and prepare the
deployment, then use `runtime-app-up`. `runtime-app-build` prepares images but
does not deploy them. Use
`runtime-app-up` to deploy the prepared images explicitly on an installation
that already has an active feed generation. First activation may deploy the
prepared receipt after its import succeeds. Feed activation and rollback never
build or pull application images. They journal both the exact prepared image
IDs, a digest of the bind-mounted executable/static artifacts, and a digest of
the rendered application execution contract. They fail closed if any part of
that deployment identity changes or cannot be recreated. `build-ui` only
builds the web assets; `runtime-app-build` stages them for deployment.
- `just runtime-app-down`: stop experimental inherited application services.
- `just gvmd-smoke`: run a narrow experimental manager profile smoke.

The commands delegate to `tools/turbovasctl`. The root `justfile` forwards
additional command arguments consistently, so JSON output can be requested via
either surface, for example:

```sh
just doctor --status-only --json
tools/turbovasctl doctor --status-only --json
```

GitHub Actions also runs the source-only quality gate in
`.github/workflows/quality-gate.yml` on pushes to `main`, pull requests, and
manual dispatch. That hosted gate uses the same
`tools/turbovasctl quality-gate --json` contract as local development, but it
does not start runtime services, run scans, sync/copy feeds, or perform public
release gating. The server-side systemd timer remains the runtime-capable daily
development gate.

See `BUILDING.md` for the current build baseline and `docker/runtime/README.md` for the current runtime groundwork.
