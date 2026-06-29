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
- `x-turbovas-operator-identity`: how the write/control operation maps the
  request to an operator principal: `proxied-session-operator`,
  `direct-token-operator`, `service-admin-dev-only`, or
  `not-applicable-preview`.
- `x-turbovas-owner-semantics`: how persistent owner fields or gvmd-style
  current-user semantics are handled: `request-operator-owner`,
  `preserve-existing-owner`, `single-admin-owner`, `no-owner-state`, or
  `not-applicable-preview`.
- `x-turbovas-safety-contract`: currently `write-control-v1`.
- `x-turbovas-side-effect`: one of `metadata-write`, `scanner-control`,
  `feed-control`, `credential-secret-control`, `account-auth-control`,
  `destructive-mutation`, `report-generation`, or `export-generation`.

For each write/control slice, characterize inherited behavior first, then define
authorization, validation and rejection paths, idempotency or rollback semantics,
audit logging, secret redaction, OpenAPI request/response shape, and focused
tests. The rule is not to avoid these paths; the rule is not to half-ass them.

## First Candidate: Scope Metadata And Membership

The preferred first live-write candidate is scope metadata and membership, not
report generation or scanner control. Scope create/modify/delete and target or
host membership edits are metadata writes over gvmd/PostgreSQL state and do not
start scans, touch credentials, mutate feeds, or generate reports by themselves.

Before any scope write route is implemented, the contract must state:

- operator identity and owner semantics for created and modified scopes;
- whether the global scope is immutable, partially editable, or excluded;
- membership invariants for targets, hosts, empty scopes, and duplicate links;
- delete behavior, including any scope-report references that block deletion;
- idempotency and rejection semantics for repeated add/remove operations;
- audit fields that do not include credentials, tokens, or private network
  details.

`generate_scope_report` remains a separate report-generation workflow. It must
not be folded into the first scope metadata-write slice.

## Second Candidate: Tag Metadata Only

The next approved direct write-control slice is tag metadata create/update only:

- `POST /api/v1/tags` creates tag metadata for a supported resource type without
  assigning resources.
- `PATCH /api/v1/tags/{tag_id}` updates only name, comment, value, and active
  state.
- Resource assignment filters, add/set/remove actions, resource-type patching,
  clone/copy, export, delete, and trash behavior remain inherited until those
  semantics receive a separate contract.

This slice is intentionally not full inherited `create_tag`/`modify_tag` parity;
it is a bounded metadata write surface that does not touch `tag_resources`.

### First-Slice Scope Write Semantics

The first live scope write slice should expose only metadata and membership
mutations for non-global, non-predefined scopes:

- `POST /api/v1/scopes` creates a normal user scope.
- `PATCH /api/v1/scopes/{scope_id}` modifies mutable metadata and, when
  provided, replaces target and host membership.
- `DELETE /api/v1/scopes/{scope_id}` deletes only scopes with no generated
  scope-report history.

Inherited behavior anchors:

- `components/gvmd/src/manage_sql_scopes.c:create_scope` validates name,
  protection requirement, target UUIDs, host UUIDs, sets owner from the current
  user, inserts `predefined=0` and `is_global=0`, then replaces target and host
  membership.
- `modify_scope` updates metadata and replaces target or host membership only
  for non-global scopes; inherited GMP also blocks renaming predefined scopes.
- `delete_scope` deletes non-predefined scope membership and the scope row.
- `generate_scope_report` starts a transaction, creates `scope_reports` and
  `scope_report_sources`, and recomputes counts and metrics. It is report
  generation, not a metadata write.

Request shape:

- Create body: `name` is required and non-empty; `comment` is optional;
  `protection_requirement` is optional and defaults to `normal`; `target_ids`
  and `host_ids` are optional arrays and default to empty lists.
- Patch body: `name`, `comment`, and `protection_requirement` are optional;
  absent `target_ids` or `host_ids` preserve existing membership; present arrays
  fully replace that membership, including an empty array clearing it.
- Delete has no request body.
- IDs are UUID strings. Duplicate IDs in a membership array are rejected rather
  than silently collapsed.

Validation and state rules:

- Native live writes require an authenticated operator. OpenAPI metadata must
  use `x-turbovas-operator-identity: proxied-session-operator` for the browser
  bridge or `direct-token-operator` for direct API access. `service-admin-dev-only`
  is allowed only for preview/scaffold operations, not live scope writes.
- Ownership for create is `request-operator-owner`; patch and delete preserve
  the existing owner. The write implementation must not create anonymous,
  fallback, or global-admin-owned scopes accidentally.
- The first slice rejects global or predefined scope mutation with a state
  conflict. Special global-scope editing can be designed later if it proves
  useful.
- Target and host UUIDs must exist and must be visible to the authenticated
  operator under the active authorization model. Missing or unauthorized
  references are rejected before membership changes are committed.
- Create, patch, and delete run in a single transaction. Failed validation must
  leave scope metadata and membership unchanged.
- Delete rejects scopes that have generated scope reports so historical scope
  evidence is not silently orphaned or destroyed. Scope-report deletion remains
  a separate design.

Response and audit posture:

- Create returns `201` with the resulting `ScopeItem` JSON and a `Location`
  header. Patch returns `200` with the resulting `ScopeItem`. Delete returns
  `204`.
- Repeating the same patch body after success is idempotent. Repeating delete
  after success returns `404`.
- Audit/log fields may include operation, route template, request ID, operator
  principal ID, scope UUID, membership counts, and result class. Logs must not
  include bearer tokens, session cookies, credentials, or private network
  details.
- Expected error classes are `400` for malformed bodies or invalid enum/UUID
  arrays, `401`/`403` for missing or unauthorized operators, `404` for missing
  scopes or references when non-disclosure is required, `409` for global,
  predefined, duplicate-membership, or scope-report-history conflicts, and `500`
  only for unexpected persistence failures.

Current checks:

- `just native-api-client-contract --status-only --json`
- `just native-tooling-state --status-only --json`

