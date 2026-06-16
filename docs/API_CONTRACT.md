<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS HTTP/JSON API Contract

TurboVAS will add typed HTTP/JSON product APIs under `/api/v1` for DB-backed
operator workflows. This is a contract baseline, not a live endpoint promise:
the current runtime still uses GSA, gsad, gvmd, GMP/XML, `python-gvm`, and
`gvm-tools` for inherited control and compatibility paths.

The goal is not to wrap GMP/XML in REST. New TurboVAS product reads should be
sourced from gvmd/PostgreSQL-owned state and should keep GMP/XML contained as a
compatibility and control protocol while native APIs replace product workflow
needs over time.

## Initial Boundary

The first API phase is read-only and report-focused:

- raw report list, detail, and metrics;
- scope list and scope detail;
- scope-report list, detail, results, hosts, CVEs, and metrics.

Scanner control, credential management, feed import, account management, and
other high-consequence operations stay on the inherited path until separate
native replacements are designed and proven.

## Common Contract Rules

- Base path: `/api/v1`.
- Authentication: same-origin operator session, initially expected to be served
  behind the existing authenticated web surface when implemented.
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

The first runtime implementation proof is scoped in
`docs/NATIVE_API_PROOF_PLAN.md`. It starts with scope-report Hosts because that
read path validates DB-backed scope membership, evidence provenance, and lazy
tab loading without changing scanner control behavior.

## Non-Goals For V1

- Do not expose arbitrary GMP command forwarding through `/api/v1`.
- Do not invent a second source of truth for report results.
- Do not start scans, sync feeds, or mutate scanner state through this first
  read API.
- Do not keep `python-gvm` or `gvm-tools` as permanent TurboVAS product
  dependencies once native replacements exist.
