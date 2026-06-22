<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Trust Boundaries

TurboVAS is derived from OpenVAS/GVM, but TurboVAS changes the product model:
all authenticated users are scanner operators, raw scan reports remain evidence,
and scope reports provide aggregated operator reporting. The trust boundaries
below describe the current development architecture and the validation mindset
for future changes.

This document is descriptive, not a production security claim. See
`docs/PRODUCTION_POSTURE.md` before any production-like deployment.

## Current Boundaries

### Browser To `gsad`

Operators use the GSA web UI over HTTPS. In development, `gsad` uses a
self-signed certificate and is explicitly bound to loopback, LAN, or Tailscale
addresses by runtime configuration. The browser boundary must assume hostile
input: route parameters, form fields, filters, and uploaded or pasted values
need validation before they affect manager state.

Checks to consider:

- browser smoke for changed workflows;
- GSA unit tests for parsing and route behavior;
- production posture checks for host binding and TLS assumptions.

### `gsad` To `gvmd`

`gsad` proxies authenticated Web UI actions to `gvmd`. This is still largely an
inherited GMP/XML boundary. TurboVAS is moving product reads toward typed
HTTP/JSON APIs, but GMP/XML remains compatibility and control plumbing for now.

Changes here are high consequence because they can affect authentication,
manager command execution, XML parsing, and error reporting.

Checks to consider:

- GMP/GSAD parser or command tests;
- `runtime-app-smoke` and browser smoke;
- `security-policy-check` for path classification;
- explicit review before adding new XML/GMP product payloads where a DB-backed
  typed contract would be cleaner.

### Direct Native API Listener

`turbovas-api` is internal by default. Development direct access is an explicit
opt-in boundary: a separate bearer-auth listener can expose read-only `/api/v1`
paths, defaulting to loopback. `/healthz` is intentionally unauthenticated for
service checks; `/api/v1/...` must reject missing or wrong bearer tokens.
Valid-token non-GET `/api/v1` requests are rejected with JSON `405` so future
write/control endpoints cannot accidentally inherit the direct listener before
they have their own safety design.
Direct listener responses include `X-Request-Id`; client-supplied values are
accepted only when bounded and safe for logs/headers, otherwise a generated ID
is returned.

This direct path is a product direction, not a production security claim. Do not
add scanner control, credentials, feed operations, account writes, destructive
writes, or broad host exposure here without a separate design and validation
packet.

Checks to consider:

- `runtime-native-api-direct-smoke --json` for missing/wrong/valid bearer-token
  behavior, valid-token non-GET rejection, and internal-smoke compatibility;
- header-level probes for `X-Request-Id` on both unauthorized and successful
  direct `/api/v1` responses;
- OpenAPI and API contract review for new direct endpoints;
- production posture review before any non-development exposure.

### `gvmd` To PostgreSQL

PostgreSQL is the product system of record for users, tasks, targets, raw
reports, scope reports, metrics snapshots, and future evidence-oriented data.
Runtime JSON artifacts are diagnostics or exports, not product truth, unless a
future design explicitly says otherwise.

Checks to consider:

- migrations and schema version checks;
- `runtime-data-state --json`;
- fixture tests for report/scope/metric correctness;
- query/performance snapshots before optimizing or materializing new state.

### `gvmd` To OSPD/OpenVAS

`gvmd` delegates scan execution to OSPD/OpenVAS. TurboVAS keeps this boundary
working before challenging it. The scanner side needs raw-socket capability,
feed-backed VT state, scanner Redis KB state, and stable process hygiene.

Changes here can affect scan fidelity and host safety.

Checks to consider:

- scanner capability and Nmap capability checks;
- scanner process/zombie checks;
- OSPD/OpenVAS log review;
- guarded scan preflight before any authorized scan execution.

### Scanner Redis

Scanner Redis is retained OpenVAS KB/runtime state, exposed to scanner services
over a Unix socket only. It is separate from the removed inherited generic Redis
service. Do not remove or replace scanner Redis without controlled scan
lifecycle evidence and scan-fidelity proof.

Checks to consider:

- `runtime-redis-state --json`;
- `runtime-performance-snapshot --json`;
- before/during/after sampling around a controlled authorized scan.

### Mosquitto And Notus

Mosquitto supports Notus runtime messaging. Notus consumes signed feed content
from the runtime feed copy and uses the shared feed keyring. This boundary
should be kept until its failure modes, state flow, and replacement cost are
mapped.

Checks to consider:

- Notus log review;
- feed keyring/import checks;
- feed-content and signature-validation review for feed changes.

### Feed Cache And Runtime Feed Copy

The canonical downloaded feed cache is local untracked state. Runtime services
consume a working copy. TurboVAS must not bundle, commit, or redistribute feed
content without separate feed-terms review.

Checks to consider:

- `feed-state --json`;
- license and feed-terms review;
- no mutation of the canonical cache outside explicit feed-sync/update commands.

### Runtime Artifacts And Logs

Runtime artifacts, browser-smoke/browser-regression outputs, report exports, quality-gate history,
log-review outputs, and performance snapshots live outside git under the runtime
directory. They support diagnostics and reproducibility, but they are not the
canonical product database.

Checks to consider:

- redaction checks for logs and command tails;
- `runtime-data-state --json` product-data audit;
- `runtime-log-review --json` after runtime changes.

### Public Release Boundary

Publishing TurboVAS is a separate trust boundary. Public release requires
license/provenance review, non-affiliation wording, production posture, secret
handling, source-publication obligations, feed-content terms, and validation
standards to be satisfied.

Checks to consider:

- `license-report --json` for daily work;
- `license-public-release-gate --json` before publication;
- `production-posture-check --status-only --json` before production-like deployment;
- branding-state review before public-facing release artifacts.

## Working Rule

When a change crosses one of these boundaries, do not rely on a single green
test. Pick the smallest validation stack that exercises the affected boundary
from source, runtime, and operator perspective where feasible.
