<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API First Proof Plan

YAFVS proves the native HTTP/JSON direction with narrow read-only workflows
before implementing broader endpoint coverage. The first proof started with
scope-report Hosts and now also covers all scope-report evidence tabs,
persisted scope-report Metrics, raw report Metrics, raw report list/detail,
raw report evidence rows, scope list/detail, target list reads, task list reads,
target/task read-summary reads, scanner metadata list/detail Information reads,
and the guarded task-start/task-stop control slices. Scanner execution/result
ingestion, feed state, credential secrets, resume, other task control, and account
management remain inherited or out of scope for this proof.

## First Proof Candidate

Initial endpoint contract:

```text
GET /api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts
```

Why this is the best first proof:

- it is read-only and does not start scans or mutate feed/scanner state;
- it exercises core YAFVS product semantics: scope membership, source-report
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
read-summary endpoints with the same PostgreSQL-backed pattern. The sidecar
remains internal by default and now has an opt-in bearer-auth direct development
listener for read-only scriptable proof work.
Browser proof work now routes the raw `/reports` list, raw-report Results,
raw-report Hosts, raw-report Ports, raw-report CVEs, raw-report Error Messages,
raw-report and scope-report Metrics, plus scope list/detail, target/task list
reads, top-level result detail metadata/explanatory fields, top-level
asset/security-info lists including Hosts, TLS Certificates, Operating Systems,
Scanners, Scan Configs, Filters, Tags, and Overrides, NVT
detail Information fields, and every scope-report evidence tab through the authenticated same-origin
`gsad` proxy defined in `docs/NATIVE_API_AUTH_BOUNDARY.md`.
NVT detail Information fields now read native catalog metadata through the
authenticated `gsad` proxy while inherited GMP context still owns preferences,
User Tags, override creation/list context, export, selector/config expansion,
feed-control, scanner-control, and write semantics.
Operating System detail Information fields now read native metadata through the
authenticated `gsad` proxy while inherited GMP context still owns retained
actions and tag writes/actions. Active OS User Tags are included in the native
detail payload.
Host detail Information fields now read native metadata through the authenticated
`gsad` proxy while direct host metadata export reuses the same read-only detail
JSON for scriptable operator reads. Inherited GMP context still owns writes, XML export, target
creation, delete identifier, tag writes/actions, and GMP-only `details=1`
behavior. The native metadata uses `hosts.uuid`, bounded safe identifier/source
metadata, host OS associations, latest whitelisted host details, and active host
User Tags.
TLS Certificate detail Information fields, active User Tags, validity/trust
status, and source provenance now read native metadata through the authenticated
`gsad` proxy while inherited GMP context still owns certificate download bytes,
legacy export, delete, tag writes/actions, and retained actions. Direct TLS
certificate metadata export reuses the same read-only detail JSON. The native detail
remains read-only metadata/source provenance and intentionally excludes stored
certificate bytes and file-transfer semantics.
Scanner detail now reads native metadata, active User Tags, and non-hidden task
backlinks through the authenticated `gsad` proxy for safe socket/builtin
page-load reads. Native write-control now owns create, metadata/configuration
edit, clone, trash, restore, hard-delete, and bounded local verification.
Inherited compatibility remains for remote TLS/relay verification, legacy file
export/download formats, credential/certificate download context, and deeper
scanner-control behavior.
Scan Config detail Information fields, active User Tags, and shallow non-hidden
task backlinks now read native metadata through the authenticated `gsad` proxy
while inherited GMP context still owns scanner/NVT preferences, selector/family
expansion, scanner reference context, import/export, edit/delete actions, and
writes.
`runtime-report-summary --json` and `runtime-report-export --json` use the
native raw report detail/result-row endpoints; the remaining heavy raw report
detail tabs stay inherited follow-ups.

Read-only scripting can use `just native-api-request --json --path
'/api/v1/...'` from
inside the development runtime boundary. Opt-in direct development access uses
`just native-api-request --direct --json --path '/api/v1/...'`
after `just runtime-native-api-direct-smoke --json` has created the bearer-auth
listener and ignored runtime secret. These paths cover DB-backed report, scope,
target, task, scan-config metadata, host asset metadata, tag metadata, override
metadata, and related native reads. Report-config resources were intentionally
removed because retained report formats are nonconfigurable; future export
options will use explicit typed contracts. This removes the need for covered
inherited read-only GMP scripts while keeping uncovered operations on their
existing paths until native semantics are implemented and proven.
Direct probes may add `--request-id 'operator-check-1'`; the value is sent as
`X-Request-Id` and must use the bounded safe request-ID character set.
Direct host/port env overrides are intentionally single-value settings:
`YAFVS_API_DIRECT_HOST` accepts a host name, IPv4 address, or bracketed IPv6
address; `YAFVS_API_DIRECT_PORT` accepts one TCP port; and
`YAFVS_API_DIRECT_BIND` accepts `host:port` or `[ipv6]:port`. The helper
rejects URLs, host lists, whitespace, and invalid ports before executing direct
requests.
Direct scriptable access is narrower than the internal listener: endpoints must
be explicitly classified for direct use. Non-destructive preview reads such as
the scope-report retention plan are scriptable and browser-proxied when marked
direct, but retention mutations remain closed. Direct write-control is limited
to explicitly registered routes behind verified operator identity and
`YAFVS_API_DIRECT_WRITE_CONTROL`.
The OpenAPI contract marks direct scriptable reads with the
`x-yafvs-direct: true` operation extension, and `native-tooling-state`
reports whether those markers align with the implementation inventory.

## Guarded Control Exceptions

Task start and stop are reviewed native scanner-control slices. Start creates
the report and gvmd `scan_queue` request transactionally. Stop sends one strict,
bounded shared-secret/operator/task command over a private gvmd Unix socket,
keeps status and queue state unchanged when scanner absence cannot be verified,
rejects stale report handlers, and serializes task finalization with stop. This
keeps ACL, scanner protocol, queue, report, and state ownership in gvmd. Both are
available through direct write-control and the authenticated browser proxy;
operator tooling requires explicit write-control consent. Resume, credential
handling, feed operations, and account administration remain separate proofs.

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
- `GET /api/v1/operating-systems/{os_id}/export` metadata JSON only
- `GET /api/v1/tls-certificates`
- `GET /api/v1/tls-certificates/{certificate_id}` metadata/source detail only
- `GET /api/v1/tls-certificates/{certificate_id}/export` metadata JSON only
- `GET /api/v1/targets`
- `GET /api/v1/targets/{target_id}`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/{task_id}`
- `GET /api/v1/tasks/{task_id}/export` metadata JSON only
- `GET /api/v1/scanners`
- `GET /api/v1/scanners/{scanner_id}` metadata, active User Tags, and task backlinks only
- `GET /api/v1/scanners/{scanner_id}/export` metadata JSON only
- `GET /api/v1/scan-configs`
- `GET /api/v1/scan-configs/{scan_config_id}` metadata, active User Tags, and shallow task backlinks only
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
- `GET /api/v1/report-formats/{report_format_id}/export` metadata JSON only
- `GET /api/v1/nvts`
- `GET /api/v1/nvts/{nvt_id}` catalog metadata only
- `GET /api/v1/cert-bund-advisories`
- `GET /api/v1/cert-bund-advisories/{advisory_id}` catalog metadata only
- `GET /api/v1/dfn-cert-advisories`
- `GET /api/v1/dfn-cert-advisories/{advisory_id}` catalog metadata only

Together with Results, Hosts, Ports, CVEs, Error Messages, Metrics, and the
Security Information CVE/CPE/CERT advisory catalogs, these
endpoints complete native browser coverage for current scope-report evidence
tabs and the high-value raw report evidence tabs. Target list/detail reads are
also browser-proxied through the authenticated `gsad` same-origin boundary,
including credential metadata that the inherited UI already displayed. Task
list/detail reads are also browser-proxied with the read-only metadata required
by the current operator view. Direct task metadata export reuses the task detail
JSON for scriptable operator reads. Task clone uses gvmd's authoritative copy
transaction through the private authenticated control socket and returns the
committed native task detail without directly starting a scan. The source
schedule and next-run state are retained, so a copied schedule can start the
clone later when due. Task hard-delete, resume,
task file export, credential secret material, and remaining scanner-control
semantics remain inherited. Scanner metadata list
and safe socket/builtin detail page-load reads are browser-proxied, including
active User Tags and non-hidden task backlinks. Direct scanner metadata export
reuses the same redacted detail JSON for scriptable operator reads. Remote
scanner certificate context, verify/file export/download,
credential/certificate download context, and scanner writes remain inherited.
Port-list list/detail reads are browser-proxied, including port ranges and target
backlinks. Port-list typed create, metadata/range update, clone, trash, restore,
hard-delete, and exported-XML import with explicit TCP/UDP ranges are native
write-control paths; browser bulk download uses native JSON metadata exports;
implicit default-range XML imports and legacy bulk XML export fallback remain
inherited. Override
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
backlinks; metadata patch, clone, trash, restore, hard-delete, and JSON metadata
export are native, while schedule create, calendar edit, and task next-time
recalculation remain inherited.
CERT-Bund and DFN-CERT list reads are browser-proxied, while their detail
metadata endpoints remain internal automation/catalog probes because rich GSA
detail/export behavior still depends on XML-only feed fields that PostgreSQL
does not store. Trashcan Contents reads can use
`/api/v1/trashcan/summary` for counts-only native JSON, but row-level
Trashcan data and restore/delete/empty mutations remain inherited because
credential/target/scanner trash tables contain secret-adjacent payloads.
The legacy Python client/tooling dependency is removed. Further native API
expansion should target the remaining explicit GSA/gsad/gvmd owner tails and
production direct-access hardening without weakening scanner-control or secret
boundaries.
