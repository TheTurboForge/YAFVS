<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# YAFVS Architecture Flows

YAFVS is an OpenVAS-derived scanner system with intentionally divergent
operator workflows. This document maps the practical flows that matter for
changes, debugging, and future architecture work. It is a routing document, not
a complete internal design reference.

## GMP Request Flow

Browser operator action:

```text
GSA React page -> GSA GMP command/model -> gsad HTTPS endpoint -> gvmd GMP parser/handler -> PostgreSQL
```

Use this path for UI workflows, route bugs, command payload changes, and user
visible state. A feature is not really removed or added until the GSA command,
GSAD proxy/validation, gvmd GMP command, database behavior, protocol clients,
tests, and public docs agree.

## Native API Direction

YAFVS is moving toward typed HTTP/JSON product APIs for DB-backed reads,
writes, and bounded control operations:

```text
runtime helper -> yafvs-api /api/v1 JSON contract -> YAFVS product query layer -> gvmd/PostgreSQL
browser/GSA -> gsad same-origin /api/v1 proxy -> yafvs-api -> gvmd/PostgreSQL
operator script -> opt-in bearer-auth direct /api/v1 listener -> yafvs-api -> gvmd/PostgreSQL
```

The first native API work is contract-first. It must not become a REST wrapper
around GMP/XML. GMP remains compatibility and high-consequence control plumbing
until each product workflow has a proven native replacement with tests and
browser/runtime coverage. See `docs/API_CONTRACT.md`,
`docs/GMP_XML_STRANGLER.md`, and `api/openapi/yafvs-v1.yaml`.

Browser-facing native operations use the authenticated same-origin `gsad` proxy
while GSA migrates from GMP/XML. Direct scriptable API work uses a separate
opt-in bearer-authenticated development listener: classified reads are
allowlisted, while reviewed writes additionally require verified operator
identity and explicit write-control. Admission limits, request bounds,
correlation, and outcome audit logging are present; production TLS, non-loopback
deployment, per-operator rate policy, and production authorization remain
separate hardening work. `docs/NATIVE_API_OPERATION_REGISTRY.md`, generated from
OpenAPI operation profiles, is the exact current surface and migration map.

## Scan Flow

Technical evidence collection:

```text
target + task -> gvmd task state -> OSPD socket -> openvas-scanner/Notus -> gvmd report/results -> PostgreSQL
```

Targets and tasks are technical evidence-collection inputs. Raw reports remain
the authoritative evidence for what the scanner did. Scan start is guarded by
runtime preflight and capability checks; YAFVS must not start arbitrary scans
without an explicit authorized scope.

## Feed Flow

Local feed handling:

```text
canonical feed cache -> verified immutable generation -> journaled activation -> OSPD/Notus/OpenVAS/gvmd import -> database/scanner state
```

The canonical cache under the sibling runtime directory is source material and
must not be mutated by daemons. Runtime services consume only the verified
`feed-store/current` generation after its durable activation journal records a
completed import. Interrupted transitions block app startup until explicit
recovery. Feed signature verification stays enabled, and
feed content remains local/untracked unless a separate feed-term review approves
packaging or redistribution.

## Scope Report Flow

Operator reporting:

```text
scope metadata + target membership + host membership -> newest completed raw source reports -> scope report snapshot -> gvmd/PostgreSQL-backed scope-report collections -> report-like scope report views
```

Scope reports do not start scans. They aggregate existing completed raw reports
for scope targets while preserving source-report provenance. Raw `/reports`
remain available as technical evidence; scope reports are reached through
`/scopes` and `/scopes/reports`. The scope-report list is filtered, sorted, and
paged through gvmd/PostgreSQL; result reading uses the standard result query
path with a hidden scope-report constraint, and the Hosts, Ports, CVEs, and
Error Messages tabs now use native DB-backed collections instead of browser-side
source-report stitching.

## Auth And Operator Model

YAFVS uses an operator-account model:

```text
authenticated account -> full scanner operator rights -> per-user identity, attribution, and preferences
```

There is no product-level distinction between admin and super admin because the
console intentionally serves one trusted scanner-operator team. Individual
accounts provide identity, attribution, preferences, revocation, and auditing;
operators share resource visibility and authority so they can continue one
another's work and cover for one another during leave or other absences. Owner
metadata does not partition resources between teammates.

People who should not administer the scanner should receive findings through
reports, exports, notifications, ticket integrations, or future delivery
workflows rather than console accounts. Distinct administrative trust domains
require independently operated stacks: tenant isolation belongs at the
database, runtime, secret, scanner, network, backup, and failure-domain
boundaries, not in row or UI permissions inside one application. Login, network
exposure, TLS, deployment controls, auditability, and credential handling remain
required. Development credentials are `admin` / `admin`; they are not
production guidance.

## Deletion, Retention, And Provenance Flow

Raw reports are evidence and can be referenced by generated scope reports:

```text
task retention -> preserve scope-report source reports -> raw report evidence links -> scope report snapshot integrity
```

Automatic raw-report retention may delete old unreferenced raw reports, but it
must not delete raw reports that a scope report references. Trashcan remains for
retained resources where backend support exists. Removed inherited product
surfaces must be removed through the stack rather than hidden in the Web UI.

## Diagnostic Flow

Routine foundation commands keep the runtime inspectable:

```text
quality-gate -> retained quality artifacts
runtime-log-review -> service-specific redacted log artifacts
runtime-data-state -> DB/table/runtime-state classification + product-data audit
runtime-performance-snapshot -> parsed Docker/DB/report-workflow/scanner-Redis/static-asset baselines
```

Diagnostics should create artifacts outside git under `YAFVS-runtime`, not
new product state. `db_owned_export` artifacts are generated from gvmd/PostgreSQL
and should not become hidden sources of truth. Product-relevant durable data
discovered in diagnostics should be evaluated for migration into
gvmd/PostgreSQL.
