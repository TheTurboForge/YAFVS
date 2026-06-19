<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# GMP/XML Strangler Map

TurboVAS inherits GMP/XML as the main manager protocol. GMP remains useful for
compatibility and high-consequence scanner control, but it should no longer be
the default shape for new TurboVAS product data flow. Native HTTP/JSON product
APIs should replace inherited client/tooling paths workflow by workflow.

Explicit end-state: TurboVAS should remove the need for `python-gvm` and
`gvm-tools` entirely from required product, runtime-helper, test, and operator
tooling paths. They may remain temporarily as compatibility bridges while
replacement APIs land.

The end-state also includes scriptable access to TurboVAS through typed
HTTP/JSON and OpenAPI clients. The current authenticated same-origin `gsad`
proxy is a browser migration bridge, not the final API boundary and not a new
reason to keep `gsad` in every automation path. Direct scriptable API exposure
must be designed separately with authentication, TLS, host binding, audit, and
write-safety controls.

The first live proof is the Docker-internal Rust `turbovas-api` sidecar for
raw report reads, scope-report collections, target/task reads, scanner metadata,
and report metrics, currently raw report list/detail/result rows/hosts,
target/task internal reads, the browser-backed target and task lists, top-level
Results, Vulnerabilities, Operating Systems, Hosts, TLS Certificates, and
Scanners lists, scope-report list, Results, Hosts, Ports, Applications,
Operating Systems, CVEs, TLS Certificates, Error Messages, scope-report Metrics,
and raw report Metrics. It queries PostgreSQL
directly and is intentionally not
exposed on a host port. Browser migration now covers the raw `/reports` list,
the `/targets` list, the `/tasks` list, raw-report Results/Hosts, raw-report
and scope-report Metrics, plus all current scope-report evidence tabs through
the authenticated same-origin `gsad` proxy defined in
`docs/NATIVE_API_AUTH_BOUNDARY.md`.

## Workflow Retirement Classes

| Class | Meaning | Current candidates |
| --- | --- | --- |
| Ready for native API proof | Low-risk read workflows with DB-owned state and existing validation. | Raw report reads, scope metadata reads, and remaining helper/tooling replacement paths. |
| Later after product semantics | Workflows needing stronger operator-model decisions first. | Exposure-duration views, owner/patchability/support status, non-operator delivery, BYO inventory. |
| High-consequence control path | Keep inherited control path until a separate design proves safety. | Scan start/stop, credentials, account/auth, feed import, scanner registration, runtime feed state. |
| Compatibility-only | Retain only until no required TurboVAS workflow depends on it. | `python-gvm` request helpers, `gvm-tools` GMP scripts, direct XML report helper paths. |

## Initial Map

| Workflow | Current path | Native target | Retirement criterion |
| --- | --- | --- | --- |
| Raw result/report list/detail/evidence tabs | GSA GMP commands -> gsad -> gvmd XML -> PostgreSQL | `/api/v1/results`, `/api/v1/reports`, `/api/v1/reports/{report_id}`, `/api/v1/reports/{report_id}/results`, `/hosts`, `/ports`, `/applications`, `/operating-systems`, `/cves`, `/tls-certificates`, and `/errors` | `/results` and `/reports` now read their lists through typed JSON. Raw detail summary plus raw report Results, Hosts, Ports, Applications, Operating Systems, CVEs, TLS Certificates, and Error Messages tab reads use native JSON through the authenticated `gsad` proxy. Closed CVEs remain a product decision: migrate as-is, fold into CVEs, or remove/retire. |
| Raw report metrics | `runtime-report-metrics` and the GSA Metrics tab now use the native API; the inherited `get_report_metrics` GMP command remains available during transition | `/api/v1/reports/{report_id}/metrics` | Runtime and browser smoke continue to prove the native path while GMP compatibility remains intact. |
| Scope list/detail | GMP scope commands and GSA scope pages | `/api/v1/scopes` and `/api/v1/scopes/{scope_id}` | Scope metadata and membership reads move to typed JSON; writes remain inherited until designed. |
| Scope-report list/detail | GMP scope-report commands and GSA scope-report pages | `/api/v1/scope-reports` and canonical scoped detail path | GSA list/detail reads use server-backed JSON collections and browser smoke remains green. |
| Target reads | GSA/GMP target commands -> gsad -> gvmd XML -> PostgreSQL | `/api/v1/targets` and `/api/v1/targets/{target_id}` | `/targets` now reads its list through typed JSON, including safe credential references already visible in the UI; target detail and all target writes remain inherited until separately migrated. Secret credential material is never exposed. |
| Task reads | GSA/GMP task commands -> gsad -> gvmd XML -> PostgreSQL | `/api/v1/tasks` and `/api/v1/tasks/{task_id}` | `/tasks` now reads its list through typed JSON, including task status, progress, trend, scanner type, references, report counts, latest report metadata, severity, and timestamps. Task detail and task writes/start/stop remain inherited until separately migrated. |
| Scanner metadata reads | GSA/GMP scanner list commands -> gsad -> gvmd XML -> PostgreSQL | `/api/v1/scanners` | `/scanners` now reads its list through typed JSON, exposing only scanner metadata and safe credential references. Scanner details and all scanner-control actions remain inherited until separately designed. |
| Scope-report Results | GSA Results tab now uses typed native JSON through the authenticated `gsad` proxy; the inherited gvmd source-report-constrained GMP collection remains available during transition | `/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results` | Browser smoke proves the native Results tab and raw evidence links while GMP compatibility remains intact. |
| Scope-report metrics | `runtime-scope-report-metrics` and the GSA Metrics tab now use the native API; the inherited scope-report metrics GMP command remains available during transition | `/api/v1/scopes/{scope_id}/reports/{scope_report_id}/metrics` | Runtime and browser smoke continue to prove the native path while GMP compatibility remains intact. |
| Scope-report evidence tabs | GSA Results, Hosts, Ports, Applications, Operating Systems, CVEs, TLS Certificates, and Error Messages tabs now use typed native JSON through the authenticated `gsad` proxy | `/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results`, `/hosts`, `/ports`, `/applications`, `/operating-systems`, `/cves`, `/tls-certificates`, and `/errors` | Browser smoke proves aggregated tabs load through native JSON and no longer render per-source raw-report sections. |
| Runtime report/scope helpers | Some `turbovasctl` helpers still use inherited control paths; raw report summary/export and scope-report summary/metrics no longer use legacy XML helper scripts | Native API-backed helper calls | `runtime-report-summary`, `runtime-report-export`, `runtime-report-metrics`, `runtime-scope-report-metrics`, and `runtime-scope-report-summary` now use the internal native API. Native result rows carry hostname, NVT family, and description excerpts, and the old `tools/runtime_report.py` XML helper has been removed. Raw report `vulnerability_count` mirrors inherited raw-report summary semantics. |
| Read-only report/scope/target/task automation | Imported GMP scripts, plus TurboVAS scope/report list scripts | `tools/turbovasctl native-api-request --json --path '/api/v1/...'` or `just native-api-request -- --json --path '/api/v1/...'` | Raw report, scope, scope-report, target, task, and scope-report result listing now have a DB-backed native GET path. The obsolete read-only `gvm-tools` scripts are removed where equivalent native reads exist. |
| gvm-tools write/control scripts | Imported GMP scripts for generation or scanner/control workflows | Future native write/control APIs after safety design | Write/control scripts remain compatibility-only until the corresponding native APIs are explicitly designed and proven. |
| Direct scriptable operator API | Temporary automation still uses inherited GMP helpers, `turbovasctl` wrappers, or internal-only native development probes depending on workflow coverage. | Authenticated TLS-protected `/api/v1` access usable by `curl`, generated OpenAPI clients, and TurboVAS-owned automation without GSA, `gsad`, GMP/XML, `python-gvm`, or `gvm-tools` as required interfaces. | A native API exposure/authentication design lands, read-only automation migrates first, write/control endpoints are added only after safety review, and required product/operator scripts no longer depend on inherited GMP tooling. |

## Expansion Rule

Every native API expansion must state which inherited path it replaces, which
tests prove parity, and what removal criterion it advances. If an endpoint only
forwards XML or creates another untyped payload shape, it does not count as
progress toward this map.
