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

The first live proof is the Docker-internal Rust `turbovas-api` sidecar for
scope-report collections. It queries PostgreSQL directly and is intentionally
not exposed on a host port; same-origin browser access is a later authenticated
boundary step.

## Workflow Retirement Classes

| Class | Meaning | Current candidates |
| --- | --- | --- |
| Ready for native API proof | Low-risk read workflows with DB-owned state and existing validation. | Scope-report Hosts/CVEs, report metrics, scope-report metrics, scope-report Results after parity stabilizes. |
| Later after product semantics | Workflows needing stronger operator-model decisions first. | Exposure-duration views, owner/patchability/support status, non-operator delivery, BYO inventory. |
| High-consequence control path | Keep inherited control path until a separate design proves safety. | Scan start/stop, credentials, account/auth, feed import, scanner registration, runtime feed state. |
| Compatibility-only | Retain only until no required TurboVAS workflow depends on it. | `python-gvm` request helpers, `gvm-tools` GMP scripts, direct XML report helper paths. |

## Initial Map

| Workflow | Current path | Native target | Retirement criterion |
| --- | --- | --- | --- |
| Raw report list/detail | GSA GMP commands -> gsad -> gvmd XML -> PostgreSQL | `/api/v1/reports` and `/api/v1/reports/{report_id}` | GSA can read raw report list/detail via typed JSON with equal browser/test coverage. |
| Raw report metrics | `get_report_metrics` over GMP and `runtime-report-metrics` through `python-gvm` | `/api/v1/reports/{report_id}/metrics` | Runtime helper and GSA Metrics tab no longer require `python-gvm` or GMP for this read. |
| Scope list/detail | GMP scope commands and GSA scope pages | `/api/v1/scopes` and `/api/v1/scopes/{scope_id}` | Scope metadata and membership reads move to typed JSON; writes remain inherited until designed. |
| Scope-report list/detail | GMP scope-report commands and GSA scope-report pages | `/api/v1/scopes/reports` and canonical scoped detail path | GSA list/detail reads use server-backed JSON collections and browser smoke remains green. |
| Scope-report Results | gvmd source-report-constrained GMP collection | `/api/v1/scopes/{scope_id}/reports/{scope_report_id}/results` | Same filters/sorts/pages and raw evidence links work without UI-side XML parsing. |
| Scope-report Hosts/CVEs | Lazy GSA tabs currently stitch source raw reports | `/api/v1/scopes/{scope_id}/reports/{scope_report_id}/hosts` and `/cves` | DB-backed collection contracts replace source-by-source raw report loading. |
| Runtime report/scope helpers | `turbovasctl` helpers using `python-gvm` | Native API-backed helper calls | `native-tooling-state --json` reports no required runtime helper dependence for migrated reads. |
| gvm-tools product scripts | Imported GMP scripts, plus TurboVAS scope/report scripts | `turbovasctl` or native API client commands | No operator or validation workflow requires `gvm-tools`; remaining scripts are optional compatibility or removed. |

## Expansion Rule

Every native API expansion must state which inherited path it replaces, which
tests prove parity, and what removal criterion it advances. If an endpoint only
forwards XML or creates another untyped payload shape, it does not count as
progress toward this map.
