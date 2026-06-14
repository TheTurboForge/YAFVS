<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
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
- focused web tests for changed components/routes
- `cd components/gsa && npm run test:web-fast` when route/component surface is
  non-trivial
- Playwright/browser smoke for operator-visible workflow changes where feasible
- `just build-ui` before closeout for meaningful UI changes

## GMP/API/Backend

- focused parser/command tests or C/Python unit tests
- `just build-c-services` for gvmd/gsad/gvm-libs/openvas C changes
- `just build-python` for python-gvm/gvm-tools/runtime Python changes
- runtime smoke only when the change affects runtime command behavior

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
