<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# YAFVS HTTP/JSON API Contract

YAFVS is adding typed HTTP/JSON product APIs under `/api/v1` for DB-backed
operator workflows. Native reads, writes, and bounded control operations are
live through the Rust sidecar, the authenticated `gsad` browser proxy, and an opt-in direct
bearer-token development listener. `python-gvm` and `gvm-tools` are removed;
remaining inherited GSA, `gsad`, `gvmd`, and GMP/XML paths are explicit
workflow-owner tails rather than required automation clients.

The goal is not to wrap GMP/XML in REST. New YAFVS product operations should be
sourced from gvmd/PostgreSQL-owned state and should keep GMP/XML contained as a
compatibility and control protocol while native APIs replace product workflow
needs over time.

## Current Boundary

The API began with report-focused reads and now includes reviewed native writes
and bounded control operations. The authoritative inventory is not a prose list:
each OpenAPI operation selects a reusable `x-yafvs-operation-profiles` entry and
records its exposure, maturity, replacement, and residual inherited owner. The
generated `docs/NATIVE_API_OPERATION_REGISTRY.md` expands those profiles into
the current method/path, surface, principal, authentication, team-authority,
write-gate, schema, request-limit, destructive, confirmation, idempotency,
audit, and migration matrix. The Quality Gate validates all operation metadata
and rejects generated-document drift.

The registry currently covers these representative workflow families:

- raw report list, detail, result rows, hosts, ports, applications, operating
  systems, CVEs, TLS certificates, error messages, and metrics;
- scope list and scope detail;
- target list and target detail summary reads;
- task list and task detail summary reads;
- top-level asset/security metadata lists for results, vulnerabilities, CVE,
  CPE, and NVT catalog entries, operating systems, hosts, TLS certificates,
  and scanner metadata; browser-proxied detail Information metadata is
  available for NVTs, operating systems, hosts, TLS certificates, scanners, and
  scan configs.
- saved filter list and detail reads, including filter term metadata and alert
  backlinks, inside authenticated operator access only.
- redacted alert list and detail metadata reads, including safe task id/name
  backlinks; method delivery values and event/condition payload data remain
  absent from the native contract.
- read-only runtime feed inventory metadata and sync-status reads from
  `/api/v1/feeds` backed by fixed allowlisted runtime feed metadata and lock
  files; no feed sync/import/update, mirroring, bundling, redistribution, or
  scanner control.
- tag list and detail metadata reads, including resource type/count and value,
  plus tag-dialog resource-name lookups for supported types including alert, credential, report, and result,
  inside authenticated operator access only.
- scan-config list and browser-proxied metadata-detail reads, including
  family/NVT counts, growth flags, predefined/deprecated state, active User
  Tags, and shallow task backlinks, inside authenticated operator access only.
- Security Information CERT-Bund and DFN-CERT advisory list reads plus
  internal catalog-detail metadata reads from imported PostgreSQL state.
- Security Information NVT list and browser-proxied catalog-detail metadata
  reads from imported PostgreSQL state.
- override list and detail metadata reads, including NVT identity, active state,
  task/result links, and severity override values, inside authenticated operator
  access only.
- port-list list and detail reads, including port ranges and target backlinks,
- schedule list and detail reads, including iCalendar recurrence data and task
  backlinks,
  inside authenticated operator access only.
- scope-report list, detail, results, hosts, ports, applications, operating
  systems, CVEs, TLS certificates, error messages, and metrics.
- guarded task start through `POST /api/v1/tasks/{task_id}/start`, which
  transactionally creates the report and gvmd `scan_queue` request; scanner
  execution and result ingestion remain gvmd-owned. The superseded browser-facing
  gsad `start_task` GMP action is not available; GSA retains lowercase
  `start_task` only as capability vocabulary. The operator-facing
  `native-start-tasks-from-csv` helper composes paginated native task reads
  with this endpoint and replaces the inherited CSV start script without
  adding a bulk mutation endpoint.
- guarded task create through `POST /api/v1/tasks` accepts required
  target/config/scanner references plus an optional operator-owned schedule
  and up to five operator-owned alerts. `native-tasks-from-csv` snapshots and
  exactly resolves all referenced collections before writing, replacing the
  inherited CSV creator without GMP/XML. Optional host ordering is stored as a
  bounded task preference and forwarded through both scanner transports.
- guarded task stop through `POST /api/v1/tasks/{task_id}/stop`. The HTTP
  service sends one bounded, shared-secret-authenticated operator command over
  a private Unix socket. gvmd keeps ACL, scanner stop/delete, queue,
  task/report state, timestamps, and partial-result ownership. It rejects
  stale report handlers and changes queue/status state only after scanner
  absence is verified. A scanner-verification failure is `502`; an
  asynchronous-only inherited stop is `409`, never false success. No GMP/XML
  or DB fallback exists. This retires only gsad's browser-facing `stop_task`
  action; public GMP `STOP_TASK` remains available for external compatibility.
- authoritative task clone through `POST /api/v1/tasks/{task_id}/clone`. The
  HTTP service sends one bounded, shared-secret-authenticated operator command
  over the private gvmd control socket. gvmd preserves its ACL checks,
  transaction, generated name, task preferences and defaults, alert links,
  schedule state, and New-task state. The endpoint does not directly start a
  scan, but a copied schedule that becomes due can start the cloned task later.
  The endpoint returns the committed native task detail.
- strict New-task target replacement through
  `POST /api/v1/tasks/{task_id}/replace-target`. The endpoint requires an
  operator-owned live scan task with no reports, atomically clones the retained
  target configuration with the requested host/exclusion lists, rebinds only
  that task, and trashes the source target only when no other live task or
  scope references it. It never starts a scan.

Task start, stop, clone, and strict target replacement are guarded native
direct-write/browser-proxied controls and operator tooling requires explicit
write-control consent. Other scanner, credential, import, account, and
authentication operations have also migrated in reviewed slices. The operation
registry—not a resource-family generalization—states exactly which operations
are native and which inherited owner tails remain. Secret material is never
implied by a metadata route and must be explicitly contracted.

The browser integration remains same-origin and proxied through `gsad` while GSA
reads migrate. Direct scriptable access is now a first-class development path:
the direct listener is opt-in, bearer-token protected, limited to classified v1
reads plus explicitly gated write-control routes, and bound explicitly by the
runtime helper. Production exposure still needs the separate TLS/bootstrap/
host-binding posture tracked outside this development API.

## Common Contract Rules

- Base path: `/api/v1`.
- Registry: `api/openapi/yafvs-v1.yaml` is the authored machine-readable
  operation registry; `docs/NATIVE_API_OPERATION_REGISTRY.md` is generated.
  Independent Rust direct-listener and C browser-proxy positive allowlists stay
  fail closed. Contract/route assertions detect disagreement; metadata never
  silently registers a broader security surface.
- Authentication: same-origin operator session through the existing `gsad` web
  boundary for browser reads, or bearer token through the opt-in direct native
  API listener. The development helper uses a read-only runtime token file by
  default instead of passing generated bearer tokens through the container
  environment. See `docs/NATIVE_API_AUTH_BOUNDARY.md`.
- Direct operator identity: `YAFVS_API_OPERATOR_UUID` and
  `YAFVS_API_OPERATOR_NAME` are optional for read-only direct access and
  required for direct write-control. A configured operator UUID is verified
  against `users` at startup and anchors owner-bearing writes.
- Direct write-control enablement: `YAFVS_API_DIRECT_WRITE_CONTROL` is a
  strict-boolean enablement flag. Truthy values require
  `YAFVS_API_OPERATOR_UUID` and register only explicitly approved direct
  write-control routes.
- Direct v1 method boundary: the opt-in direct listener accepts classified
  `GET` requests under `/api/v1` by default. With direct write-control enabled
  and operator identity verified, it additionally accepts only explicit
  contract-listed `POST`, `PATCH`, and `DELETE` write/control routes. Current
  families cover scope metadata/membership, tag metadata/resources/clone/
  restore/trash, filter metadata/clone/restore/trash, port-list metadata/clone/
  restore/trash, scan-config
  metadata/clone/restore/trash, schedule metadata/clone/restore/trash, target
  metadata/create/clone/restore/trash, selected alert metadata, credential
  name/comment metadata and restore, scanner metadata, task metadata and
  restore, guarded task start and stop, and strict New-task target replacement. Other valid-token
  non-GET requests return JSON `405 method_not_allowed`. The enforced route set
  is the `APPROVED_NATIVE_WRITE_ROUTE_CONTRACTS` list in
  `services/yafvs-api/src/direct_api_contract_tests.rs` plus OpenAPI
  `x-yafvs-exposure: direct-write` metadata.
- Direct v1 browser boundary: direct responses do not emit browser CORS access
  headers. Browser product reads and browser-relevant write routes continue
  through the authenticated same-origin `gsad` proxy. That proxy uses exact
  allowlists and now includes the existing browser-safe `POST`, `PATCH`, and
  no-body `DELETE` write routes for scopes, tags, filters, port lists, report
  configs, scan configs, schedules, and targets; task start, stop, and strict
  target replacement are browser-proxied through exact UUID action allowlists.
  Resume and other task
  control writes remain inherited until separately designed.
- Direct v1 request-shape boundary: bearer-authenticated direct `GET` and
  `DELETE` requests reject request bodies, direct write-control `POST`/`PATCH`
  bodies are size-bounded, direct non-GET requests reject query strings, and
  transfer-encoded bodies plus oversized query strings are rejected with JSON
  `413 request_too_large`. Malformed
  `Content-Length` is rejected as malformed HTTP before middleware in the live
  stack, currently with HTTP 400. This first bound is listener-level hardening;
  endpoint-specific cost limits and full rate limits remain separate
  B-130/B-134 work.
- Direct v1 pressure guard: authenticated direct `GET` requests also pass
  through a fixed in-flight request cap. When the cap is reached, the listener
  returns JSON `429 too_many_requests` with `X-Request-Id`. This is a coarse
  development pressure guard, not per-operator or per-IP production rate
  limiting.
- Direct v1 endpoint boundary: bearer-authenticated direct access exposes only
  explicitly allowlisted scriptable read endpoints. Unclassified `/api/v1`
  routes and internal-only native previews such as the scope-report retention
  plan preview return JSON `404 not_found` on the direct listener even though
  they remain available to internal runtime validation.
- Direct v1 contract metadata: scriptable direct-read operations carry
  `x-yafvs-direct: true` in `api/openapi/yafvs-v1.yaml`. The
  `native-tooling-state` command compares those markers with the implementation
  inventory and reports drift as `native-tooling.direct-api-contract`.
- Exposure and migration contract metadata: boundary seed operations carry
  `x-yafvs-exposure: direct-read` or `internal-only`, plus compact enforced
  migration metadata: `x-yafvs-maturity` (`live-read` or `preview-read`),
  `x-yafvs-replaces` (`feed-status-read`, `tag-resource-name-read`,
  `tag-active-resource-assignment-write`, `nvt-catalog-detail-read`, or `none`), and
  `x-yafvs-inherited-still-owns` (`feed-sync-import-control`,
  `tag-security-info-filter-actions-clone-export-trash`, `nvt-rich-detail`, or
  `retention-mutations`).
  `native-tooling-state` reports missing, invalid, or mismatched seed metadata
  as `native-tooling.openapi-contract` drift. Extend this enforced seed before
  adding broader free-form migration metadata.
- Response body: JSON objects only; no XML payloads in native product APIs.
- IDs: UUID strings matching the underlying gvmd resource identifiers.
- Timestamps: RFC 3339 UTC strings.
- Pagination: `page`, `page_size`, `total`, `sort`, and `filter` fields are
  explicit in collection responses.
- Request correlation: the direct bearer listener returns `X-Request-Id` on
  responses. Clients may send a bounded safe `X-Request-Id`; invalid or missing
  values are replaced with a generated ID. The header is correlation metadata,
  not identity or authorization.
- Errors: return an object with `error.code`, `error.message`, and optional
  `error.details`; do not leak secrets or raw stack traces.
- Provenance: report-like rows include raw evidence links or source report IDs
  where drill-down depends on inherited raw evidence.

## Contract Source

The seed OpenAPI document lives at `api/openapi/yafvs-v1.yaml`. It is the
source of truth for the first native API shape until a live implementation
lands. Future endpoint work must update the OpenAPI contract and the GMP/XML
strangler map in the same slice.

Read-only automation can use `just native-api-request --json --path
'/api/v1/...'` for the internal development path, or add `--direct` to call the
opt-in direct bearer listener. This replaces covered read-only GMP scripts for
report, scope, target, task, scan-config metadata, override metadata, tag
metadata and tag-dialog resource-name lookups, runtime feed inventory metadata
(`/api/v1/feeds`), native CERT-Bund report generation through
`runtime-certbund-report`, and selected asset listing/detail workflows.
Direct probes may add `--request-id 'operator-check-1'` to send a bounded safe
`X-Request-Id` correlation value.
Raw `curl` and generated clients use the same contract: send
`Authorization: Bearer <token>`, `Accept: application/json`, and optionally a
bounded `X-Request-Id`; expect JSON bodies for API responses and no browser CORS
access headers from the direct listener. Development `curl` examples should read
the token from the ignored runtime secret into shell memory and unset it after
the probe rather than printing or persisting the token.
Use `just native-api-client-contract --status-only --json` before relying on
generated-client output; it checks the OpenAPI version, servers, cookie/bearer
auth schemes, operation IDs, shared Error responses, and direct-read markers
without dumping the full endpoint inventory. Use full `--json` only when
investigating a contract mismatch.
The direct helper validates direct listener env shape locally before access:
`YAFVS_API_DIRECT_HOST` is a single host name, IPv4 address, or bracketed
IPv6 address, `YAFVS_API_DIRECT_PORT` is a decimal TCP port, and
`YAFVS_API_DIRECT_BIND` is `host:port` or `[ipv6]:port`. URLs, paths,
comma-separated hosts, whitespace, and out-of-range ports are rejected before a
direct request is sent.
If `YAFVS_API_OPERATOR_NAME` is set, `YAFVS_API_OPERATOR_UUID` must also
be set; malformed operator UUID/name values are rejected before a direct request
is sent.

The first runtime implementation proof is scoped in
`docs/NATIVE_API_PROOF_PLAN.md`. It started with an internal Rust sidecar and now
adds opt-in direct read access for the same safe GET contracts. Current coverage
includes raw report list/detail/result rows/result metadata/hosts/ports/applications/operating
systems/CVEs/TLS certificates/errors, scope list/detail, target list/detail,
task list/detail, scanner metadata list/detail Information, saved filter
list/detail, override list/detail metadata, tag list/detail metadata, operating-system asset
list/detail metadata, host asset list/detail metadata, scan-config metadata
list/detail, port-list list/detail, schedule list/detail, report-format list/detail,
Security Information CVE catalog list/detail, Security Information CPE catalog
list/detail, Security Information
CERT-Bund and DFN-CERT advisory catalog list/detail metadata, scope-report list,
Results, Hosts, Ports, Applications,
Operating Systems, CVEs, TLS Certificates, Error Messages, scope-report Metrics,
and raw report Metrics because those read
paths validate DB-backed evidence, scope membership, provenance, and report
reading without changing scanner control behavior. Browser-facing proof now
covers the raw `/reports` list, `/scopes` list/detail reads, raw report Results,
raw report Hosts, raw report Ports, raw report Applications, raw report
Operating Systems, raw report CVEs, raw report TLS Certificates, raw report Error Messages,
report Metrics, and all current
scope-report evidence tabs:
GSA calls same-origin `/api/v1/...` paths, and `gsad` authenticates and
allowlists those reads and selected write routes before proxying to the internal
sidecar. Browser-proxied DELETE routes are no-body only and share the same
operator-session-to-internal-proxy-secret boundary as POST/PATCH browser writes.
`runtime-report-summary --json` now also uses the native raw report
detail/result-row endpoints instead of `python-gvm`.
`runtime-native-api-smoke --json` and browser smoke cover the live runtime
endpoints.

Native target rows include target identity, host and exclude-host membership,
alive-test labels, reverse-DNS flags, port-list reference, task references, and
timestamps. They include safe credential metadata already visible in the
inherited UI, such as credential UUID/name/type and SSH port, but never expose
credential secret values. Direct write-control may patch target name/comment
metadata only and validates that adjacent hosts, exclude hosts, port-list,
alive-test, reverse-DNS, simultaneous-IP, and credential-link state are not part
of that slice. Native credential reads expose redacted metadata, and direct
write-control may patch credential name/comment metadata only; credential secret
material, store selectors, type/allow-insecure settings, scanner/target links,
export/download, create/clone/restore/delete, and secret-bearing writes remain
inherited.

Native task rows include task identity, status/progress, target/config/scanner
and schedule references, report counts, current/latest report references,
maximum severity, and timestamps. Task create, metadata patch, strict New-task
target replacement, and safe live-to-trash moves are native. Task create validates and transactionally links
an optional operator-owned schedule and up to five operator-owned alerts.
Target replacement preserves retained target settings, credential links, and
tags, refuses tasks with reports, and never starts a scan. Resume, file
export, config/scanner mutation, and other scanner-control actions
remain inherited. The guarded
`POST /api/v1/tasks/{task_id}/start` is available
through direct native access and the authenticated browser proxy; it
transactionally creates the report and gvmd `scan_queue` request, while gvmd
remains the scanner execution and result-ingestion owner. The gsad `start_task`
GMP action is retired. Alert execution uses the private authenticated gvmd Unix
control command, and scheduled starts use that same private authenticated gvmd
Unix control client. Authenticated gvmd `START_TASK` handling and gvm-libs
start-task clients remain retained for external compatibility. Direct scriptable
`GET /api/v1/tasks/{task_id}/export` returns
the same read-only task detail JSON for metadata export; it does not replace
legacy task file export or lifecycle control.

GSA task deletion uses authenticated `DELETE /api/v1/tasks/{task_id}` to move
an eligible live task to trash. `DELETE /api/v1/tasks/{task_id}/trash` is the
separate trash-only permanent-delete contract. Both retain native owner,
status/in-use, reference, transaction, tag, and result-evidence guards. The
obsolete browser-facing gsad `delete_task` GMP adapter is absent; raw gvmd GMP
`DELETE_TASK`, including `ultimate` semantics, and gvm-libs delete-task clients
remain external compatibility surfaces.

Native scanner metadata rows include scanner identity, host/socket, port,
inherited scanner type, safe credential references, relay metadata, and
timestamps. Scanner detail adds active User Tags and non-hidden task backlinks
for safe socket/builtin page-load reads. Native write-control owns scanner
create, metadata patch, full configuration replacement including validated relay
configuration, clone, live-to-trash, restore, hard-delete, and bounded local
verification. POST omission creates no relay; because replacement is full,
omitting, nulling, or blanking relay_host clears an existing relay. Clone copies
the retained scanner configuration and active tag links but intentionally
initializes relay configuration empty; trash and restore preserve relay fields
losslessly. Live non-hidden task references block trash, and trash-side task
references block hard-delete. Inherited paths remain only for
credential/certificate download context, legacy file export/download formats,
and deeper scanner-control behavior. The browser-side, GMP/XML, and gvmd CLI
scanner read/export, create/copy/modify/delete, and duplicate manual verification
commands are removed. Native bounded local verification owns the retained
manual workflow; configured remote, TLS, and relay scan dispatch remains
separate. Direct scriptable
`GET /api/v1/scanners/{scanner_id}/export` returns the same redacted scanner
detail JSON for metadata export; it does not replace legacy scanner file export
or scanner-control behavior. Native scanner reads do not expose credential
secret values or credential certificate metadata. Detail/export responses may
include the scanner's configured public CA certificate; list responses omit it.

Native operating-system asset rows include the `oss.uuid` identity, CPE/name,
title, latest/highest/average host severity, current best-OS host count, all
associated host count, and timestamps from gvmd/PostgreSQL asset tables. The
detail endpoint returns the same bounded metadata plus active User Tags for one
OS asset by UUID. Tag assignment uses the separate native tag contract; delete,
legacy XML export, and other OS asset writes remain inherited until native write
semantics are designed.
Direct scriptable `GET /api/v1/operating-systems/{os_id}/export` returns the
same native detail JSON for metadata export; it does not replace legacy OS
asset export/delete behavior.

Native host asset detail rows use the `hosts.uuid` identity and return the
existing host asset summary plus bounded safe metadata from `host_identifiers`,
`host_oss`/`oss`, and latest whitelisted `host_details` names only:
`best_os_cpe`, `best_os_txt`, and `traceroute`. The detail endpoint validates
and canonicalizes UUID path IDs before parameterized PostgreSQL queries. It also
returns active User Tags attached directly to the host. Native write-control
can create manual IP hosts, patch host comments, and hard-delete operator-owned
hosts. Tag assignment uses the separate native tag contract. The detail surface
intentionally excludes delete-identifier behavior, XML export, target creation from host,
credential/privacy-sensitive identifiers, raw `report_host_details` expansion,
report/result/port/application history, GMP-only `details=1` semantics, and
all other writes.
Direct scriptable `GET /api/v1/hosts/{host_id}/export` returns the same native
detail JSON for metadata export; it does not replace legacy host XML export or
target-creation workflows.

Native TLS certificate asset rows include the `tls_certificates.uuid` identity,
subject and issuer distinguished names, serial and fingerprints, activation,
expiration, last-seen/source counts, in-use state, and timestamps from
gvmd/PostgreSQL asset tables. The detail endpoint returns the same bounded
metadata plus active User Tags, inherited-style validity/trust status, and
source provenance rows with source UUIDs, timestamps, TLS version metadata,
locations, resolved host asset IDs when available, and origins. It intentionally
excludes stored certificate bytes, export/delete behavior, and other asset
writes until native write and file-transfer semantics are designed. Tag
assignment uses the separate native tag contract.
Direct scriptable `GET /api/v1/tls-certificates/{certificate_id}/export`
returns the same native detail JSON for metadata export; it does not replace
legacy certificate byte export/download or delete behavior.

Native saved filter rows include filter identity, type, term, timestamps, and
alert backlink references. Filter terms can reveal operator search logic,
resource naming, and workflow shape, so these endpoints stay inside the
authenticated operator boundary and are not catalog/public data.

Native tag rows include tag identity, owner, comment, resource type, inherited
resource count, active state, value, permissions, and timestamps. Tag metadata
is operator labeling data, so these endpoints stay inside the authenticated
operator boundary. Native assigned-resource expansion is limited to read-only
strict-whitelist references for the current tag detail Assigned Items tab.
Tag metadata export and the supported create, modify, clone, enable/disable,
trash, restore, hard-delete, and explicit or typed-filter assignment lifecycles
are native. The raw gvmd/GMP tag create, copy-on-create, modify, delete, and
generic restore paths are retired. Unsupported resource types and unbounded raw
filter expressions are rejected rather than delegated to the legacy manager.

Native scan-config rows include config identity, owner, comment, family/NVT
counts, growth flags, predefined/deprecated state, in-use state, and
timestamps. Detail payloads add active User Tags and shallow non-hidden task
backlinks. Scanner/NVT preferences, selector/family expansion, import/export,
and config writes remain inherited until native resource/write semantics are
designed. The GSA list reads native metadata; preference-heavy detail tabs
remain inherited for now.

Native override rows include override identity, owner, NVT identity/name, text,
host/port constraints, original and replacement severity values, active/end-time
state, shallow task/result links, permissions, and timestamps. Override metadata
is operator policy data, so these endpoints stay inside the authenticated
operator boundary. Native write-control owns create, metadata patch, clone,
live-to-trash delete, restore, and trash-only hard delete. Those transactions
preserve the established owner attribution, relocate associated tag-resource
rows, and clear the affected report override-count caches so later reads rebuild
them from source evidence. Metadata export is native JSON. The GSA capability
surface, gsad dispatch, gvmd parser/schema, and gvmd SQL layer no longer expose
the duplicate legacy create/copy/modify/delete commands. Override evaluation,
result-specific expansion, trash-empty accounting, user cleanup, and retained
legacy read/export plumbing remain inherited while their callers are retired.

Native port-list rows include port-list identity, comment, port counts, concrete
port ranges, target backlink references, predefined/deprecated flags, and
timestamps. Port lists are operator scanner configuration, so these endpoints
stay inside the authenticated operator boundary. Native write-control supports
typed create, metadata patch, complete range-set replacement, clone, trash,
restore, and trash-only hard delete; GSA range-add and non-empty range-delete
actions use the native range-set replacement path. Native import accepts one
exported port-list XML payload with an explicit UUID and TCP/UDP ranges,
preserves the imported UUID, suffixes duplicate names, and creates the port list
for the authenticated operator. Browser bulk download uses native JSON metadata
exports when available. Implicit default-range XML imports, legacy bulk XML
export fallback, and empty-range-delete semantics remain inherited.

Native schedule rows include schedule identity, comments, iCalendar recurrence
data, timezone, task backlink references, and timestamps. Schedules are operator
automation metadata, so these endpoints stay inside the authenticated operator
boundary. Create, modify, clone, export, and delete actions remain inherited
until native write semantics are designed.

Native Trashcan summary, redacted row inventory, confirmation-bound emptying,
ten complete typed resource lifecycles, and native task restore
are available through `/api/v1/trashcan` and resource-specific restore routes.
The native inventory intentionally excludes credential secrets, target
hosts, scanner connection fields, scan-config preferences, alert method data,
`results_trash`, and child trash tables. Alert, filter, override, port list,
credential, scan config, scanner, schedule, tag, and target restore and permanent delete
are native-only and fail closed if the native API is unavailable. Alert restore
transactionally restores its metadata, condition/event/method rows, task links,
and tag links but returns only redacted metadata. Alert hard-delete removes only
the trash-side alert family and is blocked while a trash task references it.
Task restore also moves preserved result evidence and task/report/result tag
locations back to live state, remaps result-tag row identities through stable
result UUIDs after reinsertion, invalidates report counts for safe recalculation,
and rejects any non-live task dependency. Retired inherited row-level permission
mutations are not reintroduced. Credential restore copies opaque secret rows
inside PostgreSQL without loading or returning them, restores trash-side
target/scanner references and tag locations, preserves `allow_insecure`, and
returns only redacted credential metadata. Credential hard-delete blocks trash
target/scanner/alert-delivery references and deletes opaque secret rows without
selecting, returning, or logging their values. All supported browser restore
operations are therefore native; the generic GSA/gsad GMP restore bridge is removed.
The raw gvmd/GMP `RESTORE` parser, public command/schema surface, and duplicate
resource-specific SQL implementations are removed as well. Individual
report-format restore and permanent delete are deliberately unavailable: gvmd
has no retained command handler, and restoring a row could reintroduce a
retired custom executable report format. Confirmed owner-scoped Trashcan
emptying remains the cleanup path for legacy report-format rows and directories. Separately
classified raw GMP behavior remains outside this browser contract.

Native report-format rows include report-format identity, summary/description,
extension/content type, trust state, active/predefined/configurable/deprecated
flags, alert backlinks, parameters, and timestamps. Report formats
are scanner output configuration, so these endpoints stay inside the
authenticated operator boundary. Direct scriptable
`GET /api/v1/report-formats/{report_format_id}/export` returns the same native
detail JSON for metadata export. YAFVS deliberately retires custom
executable report-format import, editing, verification, cloning, and deletion
instead of reproducing those plugin semantics in the native API. Report output
uses retained trusted built-in/feed formats or dedicated typed native export
contracts.

Native Security Information CVE catalog rows include the CVE identifier,
description, CVSS vector, severity, vulnerable product strings, optional EPSS
metadata when present, and published/modified timestamps from SCAP-owned
PostgreSQL state. This catalog is intentionally distinct from `/vulnerabilities`
and report/scope-report CVE tabs: `/cves` is reference intelligence, while the
report paths are observed evidence from completed scans.

Native CVE detail also includes EPSS score/percentile, generic URL/tag
references from `scap.cve_references`, CERT-Bund/DFN-CERT advisory references,
NVT references, and SCAP configuration nodes when those are available from
PostgreSQL. EPSS provenance is not exposed because the current
`scap.epss_scores` schema stores only CVE, score, and percentile;
source/revision/import provenance would need a separate SCAP/feed-schema
design.

Native Security Information CPE catalog rows include the CPE URI, title,
deprecation status, severity, CVE reference count, and reported CVE references
where available from SCAP-owned PostgreSQL state. This catalog is intentionally
distinct from observed host, application, operating-system, and report evidence:
`/cpes` is reference intelligence, while report paths are observed evidence from
completed scans. GSA CPE metadata export reuses the same browser-proxied native
detail JSON; raw/rich SCAP feed export remains inherited.

Native Security Information NVT catalog rows use `nvts.oid` as the identifier
and include the NVT name, family, severity, QoD, solution metadata, tags, CVE,
CERT, and other reference IDs, optional EPSS metadata, and timestamps from NVT
feed metadata imported into PostgreSQL. The browser-proxied detail endpoint
adds only text fields directly stored on `nvts`, such as comment, summary,
insight, affected, impact, and detection. It intentionally excludes NVT
preferences, scan-config selector expansion, export, feed-control,
scanner-control, and write semantics.

Native Security Information CERT-Bund and DFN-CERT advisory catalog rows include
the advisory identifier, title, summary, severity, CVE reference count, CVE
list, and timestamps from CERT feed metadata imported into PostgreSQL. The
internal detail endpoints intentionally do not reconstruct XML-only rich feed
fields such as CERT-Bund revision history, platform, risk/source URL, rich
description blocks, DFN advisory links, or additional feed links; the retained
GSA detail/export paths continue to use inherited feed XML where those fields
matter.

Native raw and scope-report result projections include host, optional hostname,
port, NVT OID/name/family, severity, QoD, creation time, source report ID,
raw evidence link, and a bounded description excerpt. These fields are enough
for summary views and report-export artifacts without asking GSA or runtime
helpers to stitch raw XML report payloads together client-side.
`GET /api/v1/results/{result_id}` returns the same basic metadata for one raw
result row plus result description and NVT explanatory fields for the existing
Information view. The GSA result detail page tries this native detail first and
falls back to inherited GMP when the native read fails. The native detail does
not replace inherited result export/action behavior or still-unmigrated rich
detail surfaces. Result-tag mutation uses the separate native tag assignment
contract; it does not fall back to raw GMP. Effective override display and
override create/mutation workflows use the native override contract.
`runtime-report-export --json` and the raw report Results tab now read native
raw-report detail/result-row endpoints, then write or render their familiar
JSON/table views. The
artifact is an export of PostgreSQL-owned report data, not a separate source of
truth.

Operator CSV export composes the direct report-detail and paginated result
projection through `native-export-report-csv`. The helper writes a deterministic
YAFVS result-view schema atomically and is not a hidden GMP/report-format
bridge.

`GET /api/v1/reports/{report_id}/raw-results` is the lossless retained-result
evidence contract. It returns every `results` row for the exact report, including
severity `-3` scanner errors and rows without host identity, while preserving
nullable source values. `native-export-report-bundle` composes that canonical
collection with report detail, metrics, and the existing typed projections into
a versioned private atomic ZIP. Its manifest records per-member hashes, counts,
roles, and the explicit rule that legacy XML byte/schema parity is not claimed.
JSON is canonical machine evidence; CSV files are human spreadsheet views.

Native raw report host rows include host, optional hostname, best OS details,
port/application counts, authenticated-scan state, scan timestamps, result and
vulnerability counts, severity buckets, maximum severity, and source report ID.
The raw report Hosts tab uses this endpoint through the same authenticated
browser proxy.

Native raw report port rows include port, protocol, affected host count,
result count, vulnerability count, maximum severity, and source report ID
provenance. The raw report Ports tab uses this endpoint through the same
authenticated browser proxy.

Native raw report CVE rows include CVE ID, affected system count, result count,
maximum severity, and source report provenance. Native raw report Error Message
rows include creation time, host when known, port, NVT OID, description, and
source report ID. Hostless scanner error messages are retained. The raw report CVEs and Error Messages tabs use
these endpoints through the same authenticated browser proxy.

Raw report `vulnerability_count` mirrors inherited raw-report summary semantics:
it counts distinct NVTs on non-error result rows, including log-level rows. CVSS
Load metric payloads have their own `vulnerability_count` semantics and count
positive-severity vulnerability metric rows only.

## Non-Goals For V1

- Do not expose arbitrary GMP command forwarding through `/api/v1`.
- Do not invent a second source of truth for report results.
- Do not start scans, sync/import/update/download feeds, or mutate scanner
  state through this first read API.
- Do not expose direct native API access without bearer authentication and an
  explicit host binding.
- Do not confuse the `gsad` same-origin proxy with the final scriptable API
  boundary; it remains a migration bridge for browser reads.
- Do not reintroduce the removed `python-gvm` or `gvm-tools` dependency;
  use the native API or a bounded YAFVS-owned helper.
- Do not recreate inherited read-only list wrappers after a native
  metadata endpoint covers the retained safe contract; for Alerts, the native
  list/detail contract is redacted metadata only, not method/event/condition
  payload data.
