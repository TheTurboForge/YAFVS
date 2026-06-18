<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS HTTP/JSON API Contract

TurboVAS is adding typed HTTP/JSON product APIs under `/api/v1` for DB-backed
operator workflows. Several read-only report and scope endpoints are already
live through the internal Rust sidecar and authenticated `gsad` proxy; the
inherited GSA, gsad, gvmd, GMP/XML, `python-gvm`, and `gvm-tools` paths remain
temporary compatibility and control plumbing during the strangler migration.

The goal is not to wrap GMP/XML in REST. New TurboVAS product reads should be
sourced from gvmd/PostgreSQL-owned state and should keep GMP/XML contained as a
compatibility and control protocol while native APIs replace product workflow
needs over time.

## Initial Boundary

The first API phase is read-only and report-focused:

- raw report list, detail, result rows, hosts, ports, applications, operating
  systems, CVEs, TLS certificates, error messages, and metrics;
- scope list and scope detail;
- scope-report list, detail, results, hosts, ports, applications, operating
  systems, CVEs, TLS certificates, error messages, and metrics.

Scanner control, credential management, feed import, account management, and
other high-consequence operations stay on the inherited path until separate
native replacements are designed and proven.

The current browser integration is intentionally same-origin and proxied
through `gsad`. That keeps the browser proof inside the existing authenticated
Web UI boundary while TurboVAS proves typed JSON reads. It is not the final
scriptable API exposure model.

The long-term API target is direct, documented, scriptable HTTP/JSON access for
operator automation and generated OpenAPI clients. That target must be
independent of GSA, `gsad`, GMP/XML, `python-gvm`, and `gvm-tools` as required
product interfaces. Direct access requires a separate authentication, TLS,
host-binding, audit, and write-safety design before it is exposed beyond the
internal development network.

## Common Contract Rules

- Base path: `/api/v1`.
- Authentication: same-origin operator session through the existing `gsad` web
  boundary for the current browser proof. Future direct scriptable API access
  must use an explicit native API authentication model. See
  `docs/NATIVE_API_AUTH_BOUNDARY.md`.
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

Internal read-only automation can use `just native-api-request --json --path
'/api/v1/...'` to call the Docker-internal native API. This replaces covered
read-only GMP scripts for report and scope listing workflows; it is not the
final externally exposed scriptable API boundary.

The first runtime implementation proof is scoped in
`docs/NATIVE_API_PROOF_PLAN.md`. It starts with an internal-only Rust sidecar
for raw report list/detail/result rows/hosts/ports/applications/operating
systems/CVEs/TLS certificates/errors, scope list/detail, scope-report list,
Results, Hosts, Ports, Applications, Operating Systems, CVEs, TLS Certificates,
Error Messages, scope-report Metrics, and raw report Metrics because those read
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

Native raw and scope-report result rows include host, optional hostname,
port, NVT OID/name/family, severity, QoD, creation time, source report ID,
raw evidence link, and a bounded description excerpt. These fields are enough
for summary views and report-export artifacts without asking GSA or runtime
helpers to stitch raw XML report payloads together client-side.
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
- Do not expose the first native API sidecar directly on LAN/Tailscale; it is
  Docker-internal and browser access must go through the authenticated
  same-origin boundary in `docs/NATIVE_API_AUTH_BOUNDARY.md`.
- Do not confuse the `gsad` same-origin proxy with the final scriptable API
  boundary; it is a migration bridge for browser reads.
- Do not keep `python-gvm` or `gvm-tools` as permanent TurboVAS product
  dependencies once native replacements exist.
