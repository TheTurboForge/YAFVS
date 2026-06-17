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

In current TurboVAS documentation, **browser-proxied** means this exact pattern:
browser JavaScript calls same-origin `/api/v1/...` paths on `gsad`; `gsad`
checks the existing authenticated operator session, applies a small read-only
allowlist, and forwards the request to the Docker-internal `turbovas-api`
service. It does not mean that `turbovas-api` is the final external API
boundary, and it does not mean that scripts should depend on `gsad` forever.

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
  scope because browser calls stay same-origin through `gsad`.
- Writes, scan control, credential handling, feed import, account management,
  and scanner/runtime mutation remain on inherited control paths until a
  separate write/API safety design exists.

## Direct Scriptable API Target

The same-origin browser proxy is a transition step, not the long-term API
goal. The long-term TurboVAS direction is a typed HTTP/JSON API that can be
called directly by suitable automation tools, scripts, and generated OpenAPI
clients without requiring GSA, `gsad`, GMP/XML, `python-gvm`, or `gvm-tools` as
the product interface.

That direct API needs its own design before exposure: authentication tokens or
session semantics, TLS, host binding, audit logging, request limits, and write
safety all need explicit treatment. Until that design lands, direct scriptable
access should use internal development helpers only, and browser access should
continue through the authenticated `gsad` boundary.

## CORS

CORS, or Cross-Origin Resource Sharing, is a browser-enforced mechanism for
deciding whether JavaScript loaded from one origin may call another origin. An
origin is the tuple of scheme, host, and port, for example
`https://100.80.139.13:19392`. Servers opt in to cross-origin browser access by
returning CORS headers such as `Access-Control-Allow-Origin`.

CORS matters only to browsers. Command-line clients, server-side services,
`curl`, and generated API clients are not protected or enabled by CORS; they
need normal API authentication, TLS, and authorization controls.

For the current TurboVAS proof, GSA is served by `gsad` and calls `/api/v1/...`
on that same `gsad` origin. That keeps the browser path same-origin, so no CORS
headers are needed and no cross-origin API surface is opened. If a future
browser application is hosted separately from the API, CORS will become an
explicit security configuration decision, not a default convenience switch.

## Why Not Expose The Sidecar Directly?

Direct browser or LAN/Tailscale exposure would create a second authentication,
authorization, TLS, logging, CSRF, and deployment surface before the product API
has proven enough value to justify that complexity. It would also make the
temporary internal proof look more production-ready than it is.

TurboVAS currently uses an operator-account model: anyone who can log in is a
trusted scanner operator. That simplifies product authorization, but it does
not remove the need for one clear authentication boundary. For now, that
boundary remains `gsad`.

## Browser Proof Scope

The browser proof is read-only and low consequence: raw-report Metrics,
scope-report Metrics, and scope-report Results, Hosts, Ports, Applications,
Operating Systems, CVEs, TLS Certificates, and Error Messages load through
authenticated same-origin `gsad` paths and then proxy to the Docker-internal
`turbovas-api` service. This proves the browser can consume typed native JSON
for report-reading workflows without exposing the sidecar, adding CORS, or
removing inherited GMP/XML control paths prematurely.

Acceptance for the first proof:

- `turbovas-api` still has no host port.
- Browser requests use the existing `gsad` origin and session.
- Unauthenticated browser requests receive a clear unauthenticated response
  from `gsad` before reaching the sidecar.
- Authenticated requests are proxied to `turbovas-api` and return typed JSON
  matching `api/openapi/turbovas-v1.yaml`; the current allowlist covers only
  read-only raw-report, scope, and scope-report collections that have been
  explicitly migrated.
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
