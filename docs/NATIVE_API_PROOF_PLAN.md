<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API First Proof Plan

TurboVAS proves the native HTTP/JSON direction with narrow read-only workflows
before implementing broader endpoint coverage. The first proof started with
scope-report Hosts and now also covers all scope-report evidence tabs,
persisted scope-report Metrics, raw report Metrics, raw report list/detail,
raw report evidence rows, scope list/detail, target list reads, task list reads,
target/task read-summary reads, and scanner metadata list reads. Scanner
control, feed state, credential secrets, writes, and account management remain out of
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
reads plus raw report evidence rows, scope list/detail, and target/task
read-summary endpoints with the same internal-only, PostgreSQL-backed pattern.
Browser proof work now routes the raw `/reports` list, raw-report Results,
raw-report Hosts, raw-report Ports, raw-report CVEs, raw-report Error Messages,
raw-report and scope-report Metrics, plus scope list/detail, target/task list
reads, top-level asset/security-info lists including Hosts, TLS Certificates,
Operating Systems, Scanners, Scan Configs, Filters, Tags, Overrides, and Report Configs, and every scope-report evidence tab through the authenticated same-origin
`gsad` proxy defined in `docs/NATIVE_API_AUTH_BOUNDARY.md`.
Operating System detail Information fields now read native metadata through the
authenticated `gsad` proxy while inherited GMP context still owns retained
actions and User Tags.
Host detail Information fields now read native metadata through the authenticated
`gsad` proxy while inherited GMP context still owns writes, export, target
creation, delete identifier, User Tags, and GMP-only `details=1` behavior. The
native metadata uses `hosts.uuid`, bounded safe identifier/source metadata, host
OS associations, and latest whitelisted host details.
TLS Certificate detail Information fields now read native metadata through the
authenticated `gsad` proxy while inherited GMP context still owns certificate
download bytes, User Tags, export, delete, and retained actions. The native
detail remains read-only metadata/source provenance and intentionally excludes
stored certificate bytes and file-transfer semantics.
`runtime-report-summary --json` and `runtime-report-export --json` use the
native raw report detail/result-row endpoints; the remaining heavy raw report
detail tabs stay inherited follow-ups.

Internal read-only scripting can use `tools/turbovasctl native-api-request
--json --path '/api/v1/...'` or `just native-api-request --json --path
'/api/v1/...'` for DB-backed report, scope, target, task, scan-config
metadata, host asset metadata, tag metadata, override metadata, and report-config reads. This
removes the need for covered inherited read-only GMP scripts while keeping
write/control operations on inherited paths until a separate native write design
exists.

## Not In The First Proof

Do not implement writes, scan start/stop, credential handling, feed operations,
or account administration through `/api/v1` in this proof. Those paths remain
high-consequence inherited control paths until separately designed and reviewed.

## Next Proofs

After scope-report and raw-report evidence reads, scope metadata reads, and
target/task read-summary endpoints, `/targets` list reads now use typed JSON
with safe credential-reference parity, and `/tasks` list reads use typed JSON
with report-count, trend, scanner-type, and last-report parity. The next
candidates are target/task detail migration and helper/tooling replacements
that directly unlock migration away from GMP/XML.

## Completed Evidence Contracts

The OpenAPI baseline names these scope-report detail collection contracts, and
they are now live internal endpoints. Browser-proxied coverage is noted below
where it exists:

- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/applications`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/operating-systems`
- `GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/tls-certificates`
- `GET /api/v1/reports/{report_id}/applications`
- `GET /api/v1/reports/{report_id}/operating-systems`
- `GET /api/v1/reports/{report_id}/tls-certificates`
- `GET /api/v1/cves`
- `GET /api/v1/cves/{cve_id}`
- `GET /api/v1/cpes`
- `GET /api/v1/cpes/{cpe_id}`
- `GET /api/v1/operating-systems`
- `GET /api/v1/operating-systems/{os_id}` metadata only
- `GET /api/v1/tls-certificates`
- `GET /api/v1/tls-certificates/{certificate_id}` metadata/source detail only
- `GET /api/v1/targets`
- `GET /api/v1/targets/{target_id}`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/{task_id}`
- `GET /api/v1/scanners`
- `GET /api/v1/scan-configs`
- `GET /api/v1/scan-configs/{scan_config_id}` metadata only
- `GET /api/v1/filters`
- `GET /api/v1/filters/{filter_id}`
- `GET /api/v1/tags`
- `GET /api/v1/tags/{tag_id}`
- `GET /api/v1/overrides`
- `GET /api/v1/overrides/{override_id}`
- `GET /api/v1/port-lists`
- `GET /api/v1/port-lists/{port_list_id}`
- `GET /api/v1/schedules`
- `GET /api/v1/schedules/{schedule_id}`
- `GET /api/v1/report-formats`
- `GET /api/v1/report-formats/{report_format_id}`
- `GET /api/v1/nvts`
- `GET /api/v1/nvts/{nvt_id}` catalog metadata only
- `GET /api/v1/cert-bund-advisories`
- `GET /api/v1/cert-bund-advisories/{advisory_id}` catalog metadata only
- `GET /api/v1/dfn-cert-advisories`
- `GET /api/v1/dfn-cert-advisories/{advisory_id}` catalog metadata only

Together with Results, Hosts, Ports, CVEs, Error Messages, Metrics, and the
Security Information CVE/CPE/CERT advisory catalogs, these
endpoints complete native browser coverage for current scope-report evidence
tabs and the high-value raw report evidence tabs. Target list reads are also
browser-proxied through the authenticated `gsad` same-origin boundary, including
credential metadata that the inherited UI already displayed. Task list reads are
also browser-proxied with the read-only table metadata required by the current
operator view. Scanner metadata list reads are browser-proxied, but scanner
details and scanner writes remain inherited. Target-detail and task-detail reads
remain internal native endpoints until their browser parity gaps are closed.
Port-list list/detail reads are browser-proxied, including port ranges and target
backlinks; port-list writes and import/export actions remain inherited. Override
list/detail metadata reads are browser-proxied, including NVT identity, active
state, task/result links, and severity override values; override create, modify,
clone, export, delete, trashcan mutation, and result-specific expansion remain
inherited. Tag list/detail metadata reads are browser-proxied, including
resource type/count, active state, and value; tag assigned-resource expansion is
browser-proxied only for read-only strict-whitelist id/type/name references;
tag create, modify, clone, enable/disable, export, delete, unsupported resource
types, and writes remain inherited. Scan-config list reads are browser-proxied,
and scan-config metadata
detail exists for internal automation; rich detail tabs, scanner/NVT
preferences, selector/family expansion, import/export, and writes remain
inherited. Schedule
list/detail reads are browser-proxied with iCalendar recurrence data and task
backlinks; schedule writes, clone, export, and delete actions remain inherited.
CERT-Bund and DFN-CERT list reads are browser-proxied, while their detail
metadata endpoints remain internal automation/catalog probes because rich GSA
detail/export behavior still depends on XML-only feed fields that PostgreSQL
does not store.
Further native API expansion should now move toward remaining helper/tooling
replacements and, later, carefully designed write/control paths that remove
required GMP/XML, `python-gvm`, or `gvm-tools` dependence.
