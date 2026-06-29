<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API Write And Control Contract

TurboVAS native API replacement is not limited to reads. Retained write and
control workflows may move to native HTTP/JSON when the slice is explicit,
bounded, and validated.

Every non-GET native operation, request-body operation, or side-effecting
operation must declare these OpenAPI fields before implementation:

- `x-turbovas-exposure`: `internal-only` by default, or `direct-write` only
  after the direct-access auth/exposure posture is deliberately approved for
  that path.
- `x-turbovas-maturity`: `preview-write`, `live-write`, `preview-control`, or
  `live-control`.
- `x-turbovas-replaces`: the inherited product workflow or `none` while the
  contract is still a scaffold.
- `x-turbovas-inherited-still-owns`: the legacy behavior that still owns any
  unreplaced part of the workflow.
- `x-turbovas-safety-contract`: currently `write-control-v1`.
- `x-turbovas-side-effect`: one of `metadata-write`, `scanner-control`,
  `feed-control`, `credential-secret-control`, `account-auth-control`,
  `destructive-mutation`, `report-generation`, or `export-generation`.

For each write/control slice, characterize inherited behavior first, then define
authorization, validation and rejection paths, idempotency or rollback semantics,
audit logging, secret redaction, OpenAPI request/response shape, and focused
tests. The rule is not to avoid these paths; the rule is not to half-ass them.

Current checks:

- `just native-api-client-contract --status-only --json`
- `just native-tooling-state --status-only --json`

