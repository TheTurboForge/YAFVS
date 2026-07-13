<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Minimum Validation Standards

Validation should scale with the change class. These are minimums, not a ceiling.

## Always Consider

- `git diff --check`
- `just license-report --json`
- relevant unit tests
- relevant type/compile checks
- whether `docs/USER_MANUAL.md` changed behavior needs an update

## Docs-Only

- `git diff --check`
- `just license-report --json` when public-facing docs, provenance, release,
  feed, dependency, or license language changes
- link/path sanity for edited docs

## GSA UI

- `cd components/gsa && npm run type-check`
- focused Vitest files through `just gsa-vitest -- <path-or-filter>`
- `cd components/gsa && npm run test:web-fast` when route/component surface is
  non-trivial
- Playwright/browser smoke for operator-visible workflow changes where feasible
- `just build-ui` before closeout for meaningful UI changes

## GMP/API/Backend

- focused parser/command tests or C/Python unit tests
- `just build-c-services` for gvmd/gsad/gvm-libs/openvas C changes
- `just c-hardening-check --status-only --json` after C builds to inspect the
  declared final ELF artifacts without changing build policy
- `just build-python` for python-gvm/gvm-tools/runtime Python changes
- runtime smoke only when the change affects runtime command behavior
- for retained C hardening direction and planned profiles, see
  `docs/C_HARDENING.md`; do not claim `just build-c-services` alone proves
  final binary hardening

## Database Or Migration

- migration/version verification
- new-schema and existing-state behavior where feasible
- runtime manager init when safe and non-destructive in the current context
- checks proving removed tables/columns or new tables/columns match the plan

## Runtime, Scanner, Or Feed

- `docker compose -f compose/dev.yaml --profile app config --quiet`
- `just runtime-status --json`
- `just runtime-smoke --json`
- targeted capability/log/feed checks for the touched subsystem
- no scan/feed mutation unless explicitly in scope

## Public Release Or Packaging

- `just license-public-release-gate`
- secret scan/public artifact review
- feed terms review
- release-owner review of license/provenance/public wording

## Aggregated Gates

- `just quality-gate --json` is the local source-quality gate.
- The GitHub Actions source gate should stay aligned with `quality-gate`.
- The server-side daily quality gate is the runtime-capable continuous gate.

## Gate Purpose Matrix

No single gate proves every release or runtime claim. Use the narrowest gate
that answers the current question, then add broader gates when the change spans
surfaces.

| Gate | Proves | Does Not Prove |
| --- | --- | --- |
| `git diff --check` | Patch formatting has no trailing whitespace or conflict markers. | Build, runtime, behavior, or license safety. |
| `just doctor --status-only --json` | Repository structure, required documents, tool availability, Python tooling version, and known deferred surfaces are visible with compact status/non-pass output. | Component builds, runtime behavior, browser workflows, or production readiness. |
| `just native-tooling-state --status-only --json` | Native API inventory, browser-proxy, direct-read, and OpenAPI contract alignment with chat-safe status/non-pass output. Use `--summary` only when compact count details are needed. | Runtime data parity, browser behavior, or production readiness. |
| `just native-api-client-contract --status-only --json` | OpenAPI server/auth/error/direct-read metadata is ready for generated-client use with compact status/non-pass output. Use full `--json` only when investigating a contract mismatch. | Endpoint response correctness or direct listener availability. |
| `just runtime-native-api-smoke --json` | Internal native API sidecar can answer representative live runtime reads. | Browser workflows, direct scriptable access, or production posture. |
| `just runtime-native-api-direct-smoke --json` | Opt-in direct bearer-auth development listener rejects bad access and serves allowlisted reads. | Production TLS, host-binding safety, or write/control authorization. |
| `just runtime-native-api-direct-write-smoke --status-only --json` | Guarded direct write-control can enable, run zero-residue approved write probes, and restore write-control state, including credential name/comment metadata patch coverage with sentinel secret-row preservation and target name/comment metadata patch coverage with adjacent host/port-list/alive-test/reverse-DNS/credential-link checksum preservation. Schedule positive probes may warn when the runtime lacks suitable records. Report-config probes are intentionally absent because retained report formats are nonconfigurable; future export options will be typed. | Production write authorization, scanner/feed/credential-secret/account control, destructive writes, target host/credential/control writes, or every possible retained write path. |
| `just runtime-browser-smoke --json` | Key operator workflows render through GSA/browser against the dev runtime. | Deep route regression, generated-client contracts, or release readiness. |
| `just runtime-browser-regression --json` | Deeper browser route/link/pagination regressions for selected workflows. | Backend-only invariants or production posture. |
| `just production-posture-check --status-only --json` | Known production blockers and exposure hazards are visible with compact status/non-pass output. Use full `--json` only when investigating pass-detail context. | That the deployment is production-ready while failures or warnings remain. |
| `just license-report --json` | Daily engineering license/provenance guardrails are clean. | Binary/container/hosted/feed redistribution readiness. |
| `just secret-precommit` | Staged source changes pass a redacted gitleaks secret scan before commit. | Full repository history, runtime artifact, feed cache, or public-release secret review. |
| `just license-public-release-gate --mode source-public` | Source-public license/provenance posture for the selected mode. | Broader release modes unless their stricter mode gates pass. |
| `just quality-gate --json` | Broad local source-quality and selected runtime-aware project gates. | Exhaustive browser regression, production readiness, or public release readiness by itself. |
