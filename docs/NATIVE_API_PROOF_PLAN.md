<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API First Proof Plan

TurboVAS will prove the native HTTP/JSON direction with one narrow read-only
workflow before implementing broader endpoint coverage. The first proof should
be scope-report Hosts, not scanner control, feed state, credentials, or account
management.

## First Proof Candidate

Endpoint contract:

```text
GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts
```

Why this is the best first proof:

- it is read-only and does not start scans or mutate feed/scanner state;
- it exercises core TurboVAS product semantics: scope membership, source-report
  provenance, evidence host coverage, missing hosts, and candidate hosts;
- it should be backed by gvmd/PostgreSQL state already present in
  `scope_reports`, `scope_report_sources`, `scope_hosts`, `report_hosts`, and
  host/result tables;
- it can first prove DB-backed report reading inside the Docker app profile,
  then replace browser-side source-report stitching for one lazy tab without
  moving the entire UI at once.

## Query Characterization Targets

Inspect and reuse the existing manager-side scope-report logic before writing
new SQL:

- `components/gvmd/src/manage_sql_scopes.c` for scope reports, source report
  selection, count maintenance, candidate hosts, and scope-host filtering;
- `components/gvmd/src/manage_sql_report_hosts.*` for inherited raw report-host
  collection behavior;
- `components/gvmd/src/manage_sql.c` around the `_and_scope_report_id` result
  constraint, because it is the current proof that scope-report reads can be
  implemented as database-constrained product collections.

The implementation should prefer shared query helpers over duplicating a second
host-count definition. If a new helper is needed, it should live beside the
existing scope-report/report-host query code and be covered by fixture tests.

## Minimum Parity Checks

The first endpoint is not complete until it proves:

- pagination, sorting, and filtering are server-backed;
- custom scopes include only member hosts in official counts;
- `Organization` includes all known evidence hosts;
- candidate hosts are visible as candidates but do not become custom-scope
  members implicitly;
- every row can point back to source raw report evidence;
- results match the existing scope-report detail tab for the same snapshot;
- the internal `runtime-native-api-smoke` can load the endpoint without GMP/XML.

Browser smoke through the native client remains the next proof step after the
internal sidecar and database query contract are stable.

## Not In The First Proof

Do not implement writes, scan start/stop, credential handling, feed operations,
or account administration through `/api/v1` in this proof. Those paths remain
high-consequence inherited control paths until separately designed and reviewed.

## Next Proofs

After scope-report Hosts works, the next candidates are:

1. scope-report CVEs, using the same source-report and scope-host filtering;
2. raw and scope-report metrics, replacing `python-gvm` runtime helper reads;
3. scope-report Results through a typed JSON client, once report-row parity is
   stable enough to avoid duplicating inherited report behavior.
