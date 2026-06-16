<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Database Gravity

TurboVAS reporting and analytics depend on deterministic, queryable state.
Product-critical data should move toward gvmd/PostgreSQL unless there is a clear
reason to keep it as runtime state, cache, log, or artifact.

## Rule Of Thumb

Put data in gvmd/PostgreSQL when it is part of the product contract:

- operator-managed objects such as targets, tasks, credentials, schedules,
  filters, scopes, and scope membership;
- raw reports, results, hosts, ports, applications, operating systems, CVEs,
  TLS certificates, and vulnerability evidence;
- generated scope reports and their source-report provenance;
- scope-report list and result-reading collections that operators filter, sort,
  page, and drill into;
- snapshot metrics that must remain stable after generation;
- future inventory/evidence/applicability records that operators query,
  compare, export, or audit.

Keep data outside PostgreSQL when it is not product state:

- feed content and feed caches, because feed terms and scanner expectations are
  separate from manager-owned product records;
- runtime logs, because they are operational diagnostics;
- generated command artifacts, because they preserve execution evidence for
  humans and automation but should not become hidden product truth;
- temporary sockets, pids, certificates, local secrets, and service state;
- build outputs, staged static UI bundles, and local virtual environments.

## Current Classifications

`runtime-data-state --json` classifies known runtime paths as:

- `system_of_record`: gvmd/PostgreSQL state;
- `db_owned_export`: report, scope-report, and metric artifacts generated from
  gvmd/PostgreSQL state;
- `diagnostic_artifact`: browser, credential, log-review, quality-gate,
  full-test-scan, performance, and runtime-log artifacts that explain command or
  service behavior but are not product truth;
- `feed_content`: canonical feed cache and runtime feed copy;
- `temporary_runtime_state`: service state such as keyrings, sockets, and
  runtime-local files.

The command also checks current core tables, scope tables, metric snapshot
tables, row counts where available, and absence of removed inherited feature
tables. Its `product_data_audit` section warns only when a product-looking
export exists without the expected gvmd/PostgreSQL source tables; diagnostic
artifacts and feed/runtime state do not produce product-data warnings by
themselves.

## Design Guidance

When adding a workflow, ask these questions before choosing storage:

1. Does an operator need to filter, sort, compare, export, audit, or link to it?
2. Would losing the data change a report, metric, finding, or decision later?
3. Does the data need schema migration, retention, deletion protection, or
   provenance?
4. Is the data merely evidence that a command ran, a runtime log, or a cache
   that can be regenerated?

If the answer to the first three questions is yes, the data probably belongs in
gvmd/PostgreSQL. If the answer is mostly the fourth question, keep it outside
the database and make the classification explicit.

## Near-Term Use

Use `runtime-data-state --json` before major reporting, metrics, scope, or
inventory work to identify product data that is still outside the database.
Do not move data merely for tidiness; move it when the product needs durable
query semantics, provenance, retention, or shared API access.

`runtime-performance-snapshot --json` complements this with thresholdless
baseline facts: parsed Docker CPU/memory/I/O/PID counters, database size and
largest relations, known row counts, report-workflow counts and largest-report
indicators, and static asset size summaries. Those facts are instrumentation,
not policy; optimization decisions need a later hot-path analysis.

The first scope-report data-gravity move is in place: `/scopes/reports` obtains
its list through filtered, sorted, paged gvmd/PostgreSQL queries, and scope
report result reading uses the standard result-query path constrained by the
scope-report snapshot. Browser-side code may still present lazy evidence tabs,
but product report-reading collections should continue moving toward manager
queries rather than client-side source-report stitching.

The native `/api/v1` contract in `docs/API_CONTRACT.md` builds on the same
rule: product reads should expose typed DB-owned state instead of forwarding
GMP/XML payloads. Contract-first API work must keep raw reports inspectable as
evidence and must not create a second hidden truth store for report data.
