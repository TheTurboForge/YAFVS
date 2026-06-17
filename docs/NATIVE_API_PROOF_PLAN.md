<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API First Proof Plan

TurboVAS proves the native HTTP/JSON direction with narrow read-only workflows
before implementing broader endpoint coverage. The first proof started with
scope-report Hosts and now also covers scope-report Results, CVEs, Error
Messages, persisted scope-report Metrics, and raw report Metrics. Scanner
control, feed state, credentials, writes, and account management remain out of
scope for this proof.

## First Proof Candidate

Initial endpoint contract:

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

Implementation commit `c59140a` proved the internal sidecar for scope-report
list and Hosts. Later B-117/B-125 slices added scope-report Results, CVEs,
Error Messages, persisted scope-report Metrics, and raw report Metrics with the
same internal-only, PostgreSQL-backed pattern. Browser proof work now routes
raw-report and scope-report Metrics plus scope-report Results, Hosts, CVEs, and
Error Messages through the authenticated same-origin `gsad` proxy defined in
`docs/NATIVE_API_AUTH_BOUNDARY.md`.

## Not In The First Proof

Do not implement writes, scan start/stop, credential handling, feed operations,
or account administration through `/api/v1` in this proof. Those paths remain
high-consequence inherited control paths until separately designed and reviewed.

## Next Proofs

After scope-report Results/Hosts/CVEs/Error Messages/Metrics and raw report Metrics work, the next candidates are:

1. dedicated native contracts for the remaining source-backed scope-report tabs:
   Ports, Applications, Operating Systems, and TLS Certificates.
2. raw report list/detail or scope metadata reads, only if they directly unlock
   helper or browser migration away from GMP/XML.

## Remaining Evidence Contract Candidates

The OpenAPI baseline now names the four remaining scope-report detail
collections before implementation:

- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/ports`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/applications`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/operating-systems`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/tls-certificates`

These are not live endpoint promises yet. Each implementation slice should
first prove the DB query against `scope_report_sources` and the relevant raw
report tables, then add sidecar routing, `gsad` same-origin allowlisting, typed
GSA client code, browser-smoke coverage, and docs updates. If a row shape is
too weak or too dependent on inherited report XML assumptions, stop at the
contract and record the gap instead of papering it over in the UI.
