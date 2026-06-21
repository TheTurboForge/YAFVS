<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS HTTP/JSON API Contract

TurboVAS is adding typed HTTP/JSON product APIs under `/api/v1` for DB-backed
operator workflows. Several read-only endpoints are already live through the
Rust sidecar, the authenticated `gsad` browser proxy, and an opt-in direct
bearer-token development listener. The inherited GSA, `gsad`, `gvmd`, GMP/XML,
`python-gvm`, and `gvm-tools` paths remain temporary compatibility and control
plumbing during the strangler migration.

The goal is not to wrap GMP/XML in REST. New TurboVAS product reads should be
sourced from gvmd/PostgreSQL-owned state and should keep GMP/XML contained as a
compatibility and control protocol while native APIs replace product workflow
needs over time.

## Initial Boundary

The first API phase is read-only and report-focused:

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
- tag list and detail metadata reads, including resource type/count and value,
  inside authenticated operator access only.
- scan-config list and browser-proxied metadata-detail reads, including
  family/NVT counts, growth flags and predefined/deprecated state, inside
  authenticated operator access only.
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

Scanner control, target/task writes, credential management, feed import,
account management, and other high-consequence operations stay on the inherited
path until separate native replacements are designed and proven. Native target
and scanner reads intentionally do not expose credential secret material.

The browser integration remains same-origin and proxied through `gsad` while GSA
reads migrate. Direct scriptable access is now a first-class development path:
the direct listener is opt-in, bearer-token protected, read-only for v1, and
bound explicitly by the runtime helper. Production exposure still needs the
separate TLS/bootstrap/host-binding posture tracked outside this v1 read API.

## Common Contract Rules

- Base path: `/api/v1`.
- Authentication: same-origin operator session through the existing `gsad` web
  boundary for browser reads, or bearer token through the opt-in direct native
  API listener. See `docs/NATIVE_API_AUTH_BOUNDARY.md`.
- Response body: JSON objects only; no XML payloads in native product APIs.
- IDs: UUID strings matching the underlying gvmd resource identifiers.
- Timestamps: RFC 3339 UTC strings.
- Pagination: `page`, `page_size`, `total`, `sort`, and `filter` fields are
  explicit in collection responses.
- Errors: return an object with `error.code`, `error.message`, and optional
  `error.details`; do not leak secrets or raw stack traces.
- Provenance: report-like rows include raw evidence links or source report IDs
  where drill-down depends on inherited raw evidence.

## Contract Source

The seed OpenAPI document lives at `api/openapi/turbovas-v1.yaml`. It is the
source of truth for the first native API shape until a live implementation
lands. Future endpoint work must update the OpenAPI contract and the GMP/XML
strangler map in the same slice.

Read-only automation can use `tools/turbovasctl native-api-request --json --path
'/api/v1/...'` for the internal development path, or add `--direct` to call the
opt-in direct bearer listener. This replaces covered read-only GMP scripts for
report, scope, target, task, scan-config metadata, override metadata, tag
metadata, and selected asset listing/detail workflows.

The first runtime implementation proof is scoped in
`docs/NATIVE_API_PROOF_PLAN.md`. It started with an internal Rust sidecar and now
adds opt-in direct read access for the same safe GET contracts. Current coverage
includes raw report list/detail/result rows/result metadata/hosts/ports/applications/operating
systems/CVEs/TLS certificates/errors, scope list/detail, target list/detail,
task list/detail, scanner metadata list/detail Information, saved filter list/detail, override
list/detail metadata, tag list/detail metadata, operating-system asset
list/detail metadata, host asset list/detail metadata, scan-config metadata
list/detail, port-list list/detail, schedule list/detail, report-config
list/detail, report-format list/detail, Security Information CVE catalog
list/detail, Security Information CPE catalog list/detail, Security Information
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
allowlists those reads before proxying to the internal sidecar.
`runtime-report-summary --json` now also uses the native raw report
detail/result-row endpoints instead of `python-gvm`.
`runtime-native-api-smoke --json` and browser smoke cover the live runtime
endpoints.

Native target rows include target identity, host and exclude-host membership,
alive-test labels, reverse-DNS flags, port-list reference, task references, and
timestamps. They include safe credential metadata already visible in the
inherited UI, such as credential UUID/name/type and SSH port, but never expose
credential secret values.

Native task rows include task identity, status/progress, target/config/scanner
and schedule references, report counts, current/latest report references,
maximum severity, and timestamps. Task creation, modification, deletion,
start/stop, and other scanner-control actions remain on the inherited path.

Native scanner metadata rows include scanner identity, host/socket, port,
inherited scanner type, safe credential references, relay metadata, and
timestamps. Scanner detail Information overlays this read-only metadata in GSA
while inherited GMP context keeps User Tags, CA/certificate data, credential
download context, verify/export/download/delete/clone/edit actions, and scanner
control behavior. Native scanner reads do not expose credential secret values or
scanner CA material.

Native operating-system asset rows include the `oss.uuid` identity, CPE/name,
title, latest/highest/average host severity, current best-OS host count, all
associated host count, and timestamps from gvmd/PostgreSQL asset tables. The
detail endpoint returns the same bounded metadata for one OS asset by UUID;
delete, export, and other asset writes remain inherited until native write
semantics are designed.

Native host asset detail rows use the `hosts.uuid` identity and return the
existing host asset summary plus bounded safe metadata from `host_identifiers`,
`host_oss`/`oss`, and latest whitelisted `host_details` names only:
`best_os_cpe`, `best_os_txt`, and `traceroute`. The detail endpoint validates
and canonicalizes UUID path IDs before parameterized PostgreSQL queries. It
intentionally excludes host create/save/delete, delete-identifier behavior, XML
export, target creation from host, User Tags, credential/privacy-sensitive
identifiers, raw `report_host_details` expansion, report/result/port/application
history, GMP-only `details=1` semantics, and all writes.

Native TLS certificate asset rows include the `tls_certificates.uuid` identity,
subject and issuer distinguished names, serial and fingerprints, activation,
expiration, last-seen/source counts, in-use state, and timestamps from
gvmd/PostgreSQL asset tables. The detail endpoint returns the same bounded
metadata plus source provenance rows with source UUIDs, timestamps, TLS version
metadata, locations, and origins. It intentionally excludes stored certificate
bytes, export/delete behavior, and other asset writes until native write and
file-transfer semantics are designed.

Native saved filter rows include filter identity, type, term, timestamps, and
alert backlink references. Filter terms can reveal operator search logic,
resource naming, and workflow shape, so these endpoints stay inside the
authenticated operator boundary and are not catalog/public data.

Native tag rows include tag identity, owner, comment, resource type, inherited
resource count, active state, value, permissions, and timestamps. Tag metadata
is operator labeling data, so these endpoints stay inside the authenticated
operator boundary. Native assigned-resource expansion is limited to read-only
strict-whitelist references for the current tag detail Assigned Items tab. Tag
create, modify, clone, enable/disable, export, delete, unsupported resource
types, and tag write semantics remain inherited until native write semantics
are designed.

Native scan-config rows include config identity, owner, comment, family/NVT
counts, growth flags, predefined/deprecated state, in-use state, and
timestamps. Scanner/NVT preferences, selector/family expansion, task backlink
identity, import/export, and config writes remain inherited until native
resource/write semantics are designed. The GSA list reads native metadata;
rich detail tabs remain inherited for now.

Native override rows include override identity, owner, NVT identity/name, text,
host/port constraints, original and replacement severity values, active/end-time
state, shallow task/result links, permissions, and timestamps. Override metadata
is operator policy data, so these endpoints stay inside the authenticated
operator boundary. Create, modify, clone, export, delete, trashcan mutation, and
result-specific override expansion remain inherited until native write/control
semantics are designed.

Native port-list rows include port-list identity, comment, port counts, concrete
port ranges, target backlink references, predefined/deprecated flags, and
timestamps. Port lists are operator scanner configuration, so these endpoints
stay inside the authenticated operator boundary. Create, modify, import, export,
and delete actions remain inherited until native write semantics are designed.

Native schedule rows include schedule identity, comments, iCalendar recurrence
data, timezone, task backlink references, and timestamps. Schedules are operator
automation metadata, so these endpoints stay inside the authenticated operator
boundary. Create, modify, clone, export, and delete actions remain inherited
until native write semantics are designed.

Native report-config rows include report-config identity, owner, report-format
reference, alert backlinks, resolved parameter metadata, writable/in-use/orphan
flags, and timestamps. Report configs are scanner output configuration, so these
endpoints stay inside the authenticated operator boundary. Create, modify,
clone, export, and delete actions remain inherited until native write semantics
are designed.

Native Trashcan summary reads are counts-only at
`/api/v1/trashcan/summary`. The endpoint returns all supported Trashcan
resource types with `resource_type`, `title`, and `count`, plus an aggregate
`total`. It intentionally excludes row-level Trashcan payloads, identifiers,
names, comments, credential data, target hosts, scanner fields, scan-config
preferences, alert method data, `results_trash`, and child trash tables.
Row-level Trashcan resource reads and restore/delete/empty mutations remain
inherited because credential/target/scanner trash data is secret-adjacent.

Native report-format rows include report-format identity, summary/description,
extension/content type, trust state, active/predefined/configurable/deprecated
flags, alert/report-config backlinks, parameters, and timestamps. Report formats
are scanner output configuration, so these endpoints stay inside the
authenticated operator boundary. Import/export/verification, edits, and deletion
remain inherited until native write semantics are designed.

Native Security Information CVE catalog rows include the CVE identifier,
description, CVSS vector, severity, vulnerable product strings, optional EPSS
metadata when present, and published/modified timestamps from SCAP-owned
PostgreSQL state. This catalog is intentionally distinct from `/vulnerabilities`
and report/scope-report CVE tabs: `/cves` is reference intelligence, while the
report paths are observed evidence from completed scans.

Native Security Information CPE catalog rows include the CPE URI, title,
deprecation status, severity, CVE reference count, and reported CVE references
where available from SCAP-owned PostgreSQL state. This catalog is intentionally
distinct from observed host, application, operating-system, and report evidence:
`/cpes` is reference intelligence, while report paths are observed evidence from
completed scans.

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

Native raw and scope-report result rows include host, optional hostname,
port, NVT OID/name/family, severity, QoD, creation time, source report ID,
raw evidence link, and a bounded description excerpt. These fields are enough
for summary views and report-export artifacts without asking GSA or runtime
helpers to stitch raw XML report payloads together client-side.
`GET /api/v1/results/{result_id}` returns the same basic metadata for one raw
result row so the GSA result detail page can overlay native read-only metadata
after loading the inherited GMP detail context. The native detail intentionally
does not replace inherited overrides, tags, EPSS/CVE context, export, actions,
create-override, or rich NVT/result detail surfaces.
`runtime-report-export --json` and the raw report Results tab now read native
raw-report detail/result-row endpoints, then write or render their familiar
JSON/table views. The
artifact is an export of PostgreSQL-owned report data, not a separate source of
truth.

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
rows include creation time, host, port, NVT OID, description, source report ID,
and raw result evidence links. The raw report CVEs and Error Messages tabs use
these endpoints through the same authenticated browser proxy.

Raw report `vulnerability_count` mirrors inherited raw-report summary semantics:
it counts distinct NVTs on non-error result rows, including log-level rows. CVSS
Load metric payloads have their own `vulnerability_count` semantics and count
positive-severity vulnerability metric rows only.

## Non-Goals For V1

- Do not expose arbitrary GMP command forwarding through `/api/v1`.
- Do not invent a second source of truth for report results.
- Do not start scans, sync feeds, or mutate scanner state through this first
  read API.
- Do not expose direct native API access without bearer authentication and an
  explicit host binding.
- Do not confuse the `gsad` same-origin proxy with the final scriptable API
  boundary; it remains a migration bridge for browser reads.
- Do not keep `python-gvm` or `gvm-tools` as permanent TurboVAS product
  dependencies once native replacements exist.
- Do not retain inherited read-only `gvm-tools` list wrappers after a native
  metadata endpoint covers the retained safe contract; for Alerts, the retained
  contract is redacted metadata only, not method/event/condition payload data.
