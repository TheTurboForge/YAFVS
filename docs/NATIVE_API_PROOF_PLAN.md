<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API First Proof Plan

TurboVAS proves the native HTTP/JSON direction with narrow read-only workflows
before implementing broader endpoint coverage. The first proof started with
scope-report Hosts and now also covers all scope-report evidence tabs,
persisted scope-report Metrics, raw report Metrics, raw report list/detail,
raw report result and host rows, and scope list/detail
reads. Scanner
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
list and Hosts. Later B-117/B-125 slices added scope-report Results, Ports,
CVEs, Error Messages, Applications, Operating Systems, TLS Certificates,
persisted scope-report Metrics, raw report Metrics, and raw report list/detail
reads plus raw report result/host rows with the same internal-only,
PostgreSQL-backed pattern. Browser proof work now routes the raw `/reports`
list, raw-report Results, raw-report Hosts, raw-report Ports, raw-report CVEs,
raw-report Error Messages, raw-report and scope-report Metrics, plus scope
list/detail and every scope-report evidence tab through the authenticated
same-origin `gsad` proxy defined in `docs/NATIVE_API_AUTH_BOUNDARY.md`.
`runtime-report-summary --json` and `runtime-report-export --json` use the
native raw report detail/result-row endpoints; the remaining heavy raw report
detail tabs stay inherited follow-ups.

## Not In The First Proof

Do not implement writes, scan start/stop, credential handling, feed operations,
or account administration through `/api/v1` in this proof. Those paths remain
high-consequence inherited control paths until separately designed and reviewed.

## Next Proofs

After scope-report Results/Hosts/Ports/Applications/Operating Systems/CVEs/TLS
Certificates/Error Messages/Metrics, raw report Metrics, raw report
list/detail/result/host/port/CVE/error rows, raw report Results/Hosts/Ports/CVEs/Error
Messages browser reads, and scope metadata reads, the next candidates are the
remaining native raw report tab collections or helper/tooling replacements,
only if they directly unlock migration away from GMP/XML.

## Completed Evidence Contracts

The OpenAPI baseline names these scope-report detail collection contracts, and
they are now live internal and browser-proxied endpoints:

- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/applications`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/operating-systems`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/tls-certificates`
- `GET /api/v1/reports/{report_id}/applications`
- `GET /api/v1/reports/{report_id}/operating-systems`
- `GET /api/v1/reports/{report_id}/tls-certificates`

Together with Results, Hosts, Ports, CVEs, Error Messages, and Metrics, these
endpoints complete native browser coverage for current scope-report evidence
tabs and the high-value raw report evidence tabs. Further native API expansion
should now decide the Closed CVEs path, then move toward remaining helper/tooling
replacements and, later, carefully designed write/control paths that remove
required GMP/XML, `python-gvm`, or `gvm-tools` dependence.
