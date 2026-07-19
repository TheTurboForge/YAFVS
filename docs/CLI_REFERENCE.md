<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# YAFVS CLI Reference

The root `justfile` is the normal command surface. It delegates deterministic
implementation work to `tools/yafvsctl` and forwards additional arguments:

```sh
just doctor --status-only --json
tools/yafvsctl doctor --status-only --json
```

Use `just --list` for the current recipe inventory and
`tools/yafvsctl --help` or a subcommand's `--help` for exact arguments.
Machine-readable results use a common `status`, `summary`, `findings`,
`artifacts`, and `metadata` envelope. `warn` is non-zero in meaning but does
not use a failure exit code; `fail` exits non-zero.

## Repository And Tooling

- `just status`: show repository branch, HEAD, upstream, and worktree state.
- `just inventory`: list the ten expected imported components.
- `just doctor`: inspect repository structure, tools, Python version, and
  known deferred surfaces.
- `just path-coupling-state`: inspect tracked checkout/runtime path coupling.
- `just native-tooling-state`: inventory remaining GMP, `python-gvm`, and
  `gvm-tools` compatibility surfaces.
- `just branding-state`: inventory public product identity and inherited
  branding residue.
- `just security-policy-check`: validate the security-sensitive path policy.
- `just rust-migration-state`: inspect C-to-Rust tooling and the current proof
  candidate.

The incremental Rust command spine currently implements 47 parity-tested
subcommands. Python remains canonical only for commands not listed in this
mechanically checked block while the normal `just` recipes continue to provide
a stable front door:

```sh
just yafvsctl-rust status --json
just yafvsctl-rust inventory --json
just yafvsctl-rust-test
```

<!-- rust-cli-commands:start -->
```text
status
inventory
branding-state
path-coupling-state
runtime-redis-state
runtime-identity-migrate
runtime-db-introspect
c-hardening-check
quality-gate-state
feed-state
feed-generation-state
feed-generation-stage
feed-generation-activate
feed-generation-rollback
rust-migration-state
native-api-cargo-audit
gsa-npm-audit
native-api-semgrep-audit
osv-lockfile-audit
security-policy-check
runtime-plan
down
runtime-app-down
feed-copy-to-runtime
deps
runtime-feed-import-init
runtime-performance-snapshot
runtime-certbund-report
runtime-log-review
runtime-scanner-capability-check
runtime-scanner-process-check
runtime-nmap-capability-check
runtime-data-state
runtime-gmp-smoke
runtime-credential-smoke
runtime-rbac-smoke
runtime-webui-smoke
runtime-full-test-scan-preflight
runtime-full-test-scan-start
runtime-full-test-scan-status
logs
license-report
doctor
quality-gate-schedule
runtime-native-api-direct-token
runtime-native-api-direct-bootstrap
production-posture-check
```
<!-- rust-cli-commands:end -->

Parity includes each command's existing mutation boundary. In particular,
`feed-copy-to-runtime` and `runtime-feed-import-init` retain their guarded
refusals; quality-gate schedule changes still require explicit host opt-in; and
direct-token rotation remains an explicit `--rotate` action.

## Build Commands

- `just deps [component]`: report dependency readiness globally or for one
  component.
- `just configure <component>`: configure a supported CMake component under
  `build/<component>/`.
- `just build <component>`: build one supported component.
- `just build-core-c`: build the initial core C chain.
- `just build-c-services`: build the C service baseline.
- `just build-ui`: install/build GSA web assets.
- `just build-python`: build and import-check retained Python runtime
  components.
- `just build-baseline`: run the required combined build baseline.
- `just c-hardening-check --status-only --json`: inspect hardening evidence on
  the current final C artifacts without changing build flags.

Runtime-affecting builds refuse to replace bind-mounted artifacts while
application services are active. Stop them with `just runtime-app-down`, build,
then prepare and deploy the new application identity explicitly.

## Assurance And Release Checks

- `just quality-gate`: run the source-quality contract: license, doctor,
  native-contract, Python, Compose, Rust, and fast GSA checks.
- `just quality-gate-state`: read retained local gate history.
- `just quality-gate-schedule --status`: inspect the user-systemd timer.
- `YAFVS_ENABLE_QUALITY_GATE_SCHEDULE=1 just quality-gate-schedule --install`:
  explicitly opt this host into timer installation. YAFVS assumes no
  hostname or user and never falls back to cron.
- `just closeout-readiness`: summarize closeout evidence.
- `just license-precommit`: run the fast modified-file provenance check.
- `just license-report`: run the routine engineering license/provenance gate.
- `just license-public-release-gate --mode source-public`: check source-public
  readiness. Binary, container, hosted, and feed-redistribution modes have
  separate stricter gates.
- `just secret-precommit`: scan the current change surface for secrets.
- `just production-posture-check`: run the non-destructive development versus
  production posture checklist.
- `just osv-lockfile-audit`: scan tracked dependency lockfiles.
- `just native-api-cargo-audit`: audit the native API Rust dependency graph.
- `just native-api-semgrep-audit`: run the focused native API static rules.
- `just gsa-npm-audit`: inspect GSA npm dependencies.
- `just gsa-vitest [filter]`: run focused GSA tests.

A passing source gate does not authorize packaging, deployment, hosting, or
feed redistribution.

## Native API Commands

Read/contract surfaces:

- `just native-api-request`: perform a guarded `/api/v1` request.
- `just native-api-client-contract`: inspect the native API client contract.
- `just native-api-migration-matrix`: show migration ownership and maturity.
- `just native-api-replacement-dashboard`: summarize remaining compatibility
  owners.
- `just native-api-rust-test [filters]`: run native API Rust tests.
- `just native-verify-scanners`: verify scanner inventory through the native
  API.
- `just native-export-report-csv`, `native-export-report-pdf`, and
  `native-export-report-bundle`: export one explicit report.

Guarded write/control surfaces include:

```text
native-start-task
native-stop-task
native-start-tasks-from-csv
native-stop-tasks-from-csv
native-stop-all-tasks
native-update-task-target
native-targets-from-host-list
native-targets-from-csv
native-targets-from-xml
native-tasks-from-csv
native-tags-from-csv
native-credentials-from-csv
native-alerts-from-csv
native-bulk-modify-schedules
native-delete-overrides-by-filter
native-empty-trash
native-nvt-diagnostic-scan
native-scan-new-system
native-scan-with-delivery
```

Use each subcommand's help before a write. Preview/dry-run and explicit
write-control acknowledgements are part of the command contract; do not bypass
them with direct database or protocol mutations.

## Runtime Foundation

- `just runtime-plan`: render the persistent runtime layout and current
  deferred surfaces.
- `just up` / `just down`: start or stop infrastructure services.
- `just logs [service]`: show recent Compose logs.
- `just runtime-certs-init`: create or verify development certificates.
- `just runtime-init`: initialize PostgreSQL prerequisites.
- `just runtime-manager-init`: migrate/initialize manager state and the
  development operator.
- `just runtime-scanner-redis-init`: initialize scanner Redis/config state.
- `just runtime-gmp-smoke`: run the retained authenticated GMP smoke.
- `just runtime-scanner-register`: create or verify scanner registration.
- `just runtime-scanner-capability-check`: verify OpenVAS raw-socket
  capabilities.
- `just runtime-scanner-process-check`: check scanner process hygiene.
- `just runtime-nmap-capability-check`: verify Nmap capabilities.
- `just runtime-feed-keyring-init`: initialize the feed-signature keyring.
- `just runtime-status`: show current runtime status.
- `just runtime-smoke`: run infrastructure smoke checks.
- `just runtime-log-review`: write a redacted high-signal log review.
- `just runtime-data-state`: inspect DB-centered product/runtime data.
- `just runtime-db-introspect`: inspect bounded database structure.
- `just runtime-performance-snapshot`: record thresholdless runtime metrics.
- `just runtime-redis-state`: inspect scanner Redis boundaries.
- `just yafvsctl-rust runtime-identity-migrate`: plan the guarded, atomic
  one-time rename of a sibling `TurboVAS-runtime` directory to
  `YAFVS-runtime`; add `--apply` only after all Docker containers have been
  removed and a pre-migration `runtime-data-state` artifact has been retained.

`tools/yafvsctl` supplies the current absolute checkout path to Compose.
Direct `docker compose` use must set `YAFVS_REPO_MOUNT_PATH` explicitly.
Runtime state defaults to the sibling `YAFVS-runtime` directory and can be
relocated with `YAFVS_RUNTIME_DIR`.

## Feed Generation And Deployment

- `just feed-state`: inspect cache/runtime feed state.
- `just feed-cache-sync`: start a full Community Feed cache sync.
- `just feed-generation-stage`: create and verify an immutable generation
  without activation.
- `just feed-generation-state --status-only --json`: reverify staged and
  active generations.
- `just runtime-app-build`: prepare application images and the deployment
  identity without deploying.
- `just feed-generation-activate -- <generation-id>
  [--allow-first-activation]`: perform guarded service-coordinated activation.
- `just feed-generation-activate -- <active-generation-id>
  --repair-attestation`: reimport the active generation to repair its database
  attestation.
- `just feed-generation-rollback -- <generation-id>`: compensate only to the
  journaled known-good predecessor.

Feed operations use local Community Feed content. Source availability does not
authorize mirroring, bundling, packaging, or redistributing feed content.

## Application And Browser Runtime

- `just runtime-app-up`: deploy the prepared application identity.
- `just runtime-app-down`: stop application services.
- `just runtime-app-smoke`: run application service checks.
- `just runtime-native-api-smoke`: test the internal native API.
- `just runtime-native-api-rebuild`: rebuild/redeploy the native API under the
  guarded receipt contract.
- `just runtime-webui-smoke`: test the staged GSA UI through `gsad`.
- `just runtime-browser-smoke`: test representative report/scope workflows.
- `just runtime-browser-regression`: run deeper route/link/pagination checks.
- `just runtime-credential-smoke`: test credential creation in a browser.
- `just gvmd-smoke`: run the narrow experimental manager profile.

Direct native API development access is opt-in:

- `just runtime-native-api-direct-token`: create/read the local development
  bearer token.
- `just runtime-native-api-direct-bootstrap`: prepare the direct listener.
- `just runtime-native-api-direct-smoke`: verify read-only direct access.
- `just runtime-native-api-direct-write-smoke`: verify the guarded write path.

See [Production Posture](PRODUCTION_POSTURE.md); direct development access is
not a production exposure model.

## Explicit Full-Test Scans

YAFVS ships no scan target and does not infer authorization. Supply one
canonical CIDR containing at most 256 addresses:

```sh
TARGET_CIDR='replace-with-an-authorized-cidr'
just runtime-full-test-scan-preflight --target-cidr "$TARGET_CIDR"
just runtime-full-test-scan-start \
  --target-cidr "$TARGET_CIDR" \
  --confirm-authorized-target "$TARGET_CIDR"
just runtime-full-test-scan-status --target-cidr "$TARGET_CIDR"
```

The start command revalidates the target and exact target-bound confirmation
before runtime checks or side effects. Preflight and status never start a scan.

## Reports And Scopes

- `just runtime-report-summary [--report-id ID]`: summarize a completed raw
  report.
- `just runtime-report-export [--report-id ID]`: export parsed raw results.
- `just runtime-report-metrics [--report-id ID]`: read native report metrics.
- `just runtime-certbund-report`: create a native CERT-Bund report.
- `just runtime-scope-smoke`: verify scope reporting without starting scans.
- `just runtime-scope-report-summary`: summarize the latest Organization scope
  report.
- `just runtime-scope-report-metrics`: read native scope-report metrics.
- `just runtime-rbac-smoke`: characterize the retained operator-account
  compatibility boundary.

When a report ID is omitted, raw-report commands select the newest completed
YAFVS full-test report. Scope reports analyze existing completed evidence;
they do not trigger scans.
