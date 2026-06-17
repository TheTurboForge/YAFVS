<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API Authentication Boundary

TurboVAS is adding a DB-backed HTTP/JSON API for product reads, but the API
must not become a second public administration surface. The first native API
implementation is intentionally Docker-internal and unauthenticated by itself;
browser access must be mediated by the existing authenticated web boundary.

## Boundary Decision

The browser-facing boundary for native API reads is same-origin `gsad`, not a
host-exposed `turbovas-api` port.

Intended flow:

```text
browser -> gsad HTTPS/session -> gsad native API proxy -> turbovas-api -> PostgreSQL
```

Rules:

- `turbovas-api` stays internal to the Docker app network in the first browser
  proof. Do not publish it on LAN, Tailscale, or a host port.
- The browser calls same-origin paths under the existing `gsad` origin, such as
  `/api/v1/...`, so session cookies, TLS termination, and host binding remain
  centralized.
- `gsad` must authenticate the existing operator session before proxying a
  native API request.
- Native read requests may carry operator identity from `gsad` to
  `turbovas-api` for diagnostics/audit context, but `turbovas-api` must not
  treat user-supplied headers from arbitrary clients as authentication.
- CORS is not part of the first proof. Cross-origin browser access is out of
  scope.
- Writes, scan control, credential handling, feed import, account management,
  and scanner/runtime mutation remain on inherited control paths until a
  separate write/API safety design exists.

## Why Not Expose The Sidecar Directly?

Direct browser or LAN/Tailscale exposure would create a second authentication,
authorization, TLS, logging, CSRF, and deployment surface before the product API
has proven enough value to justify that complexity. It would also make the
temporary internal proof look more production-ready than it is.

TurboVAS currently uses an operator-account model: anyone who can log in is a
trusted scanner operator. That simplifies product authorization, but it does
not remove the need for one clear authentication boundary. For now, that
boundary remains `gsad`.

## First Browser Proof

The first browser proof is read-only and low consequence: raw-report Metrics
and scope-report Metrics load through authenticated same-origin `gsad` paths
and then proxy to the Docker-internal `turbovas-api` service. This proves the
browser can consume typed native JSON for one report-reading workflow without
exposing the sidecar, adding CORS, or removing the inherited GMP/XML report
paths.

Acceptance for the first proof:

- `turbovas-api` still has no host port.
- Browser requests use the existing `gsad` origin and session.
- Unauthenticated browser requests receive a clear unauthenticated response
  from `gsad` before reaching the sidecar.
- Authenticated requests are proxied to `turbovas-api` and return typed JSON
  matching `api/openapi/turbovas-v1.yaml`; the current allowlist covers only
  raw-report metrics and scope-report metrics.
- Existing GMP/GSA behavior remains available during the migration.
- Browser smoke validates the routed page or tab as a user-visible workflow.

## Future Hardening Questions

Before adding native write APIs or production deployment support, revisit:

- whether the sidecar should listen on a Unix socket or isolated network rather
  than a Docker-internal TCP port;
- how `gsad` should forward operator identity and request IDs to the sidecar;
- whether sidecar requests need a private proxy token, mTLS, or another
  defense-in-depth mechanism inside the app network;
- CSRF/origin handling for future non-GET requests;
- structured audit logging for native API access;
- rate limiting and payload limits for heavyweight report queries.

These are not blockers for the first read-only browser proof, but they are
blockers for broad native API expansion.
