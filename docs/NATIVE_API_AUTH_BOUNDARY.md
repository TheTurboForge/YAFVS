<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API Authentication Boundary

TurboVAS is adding DB-backed HTTP/JSON APIs for product reads. The API must be
scriptable without making `gsad`, GMP/XML, `python-gvm`, or `gvm-tools` required
automation interfaces, but it must also avoid becoming an accidental unauthenticated
scanner-administration surface.

## Current Boundary

`turbovas-api` now has two development listeners:

```text
browser -> gsad HTTPS/session -> gsad native API proxy -> turbovas-api internal listener -> PostgreSQL
script/curl -> opt-in direct bearer listener -> turbovas-api -> PostgreSQL
```

- The internal listener remains the default app-network path for `gsad` and
  runtime helpers.
- Direct host exposure is opt-in. The development helper publishes
  `127.0.0.1:19080` only when direct mode is requested. By default it creates
  an ignored runtime secret and passes it to the service as a read-only token
  file through `TURBOVAS_API_BEARER_TOKEN_FILE`; `TURBOVAS_API_BEARER_TOKEN`
  remains an explicit environment-token override/fallback for development.
- Direct bearer tokens must satisfy the local strength contract enforced by the
  service and helper: at least 32 printable non-whitespace ASCII characters.
  Generated runtime secrets use this stronger shape by default; weak configured
  environment tokens are rejected before use.
- `/healthz` is unauthenticated for readiness. `/api/v1/...` on the direct
  listener requires `Authorization: Bearer <token>` and returns JSON `401`
  errors for missing or wrong tokens.
- The direct listener rejects valid-token non-GET `/api/v1` requests with JSON
  `405 method_not_allowed`. This prevents future native write/control routes
  from becoming direct-scriptable without a separate safety design.
- The direct listener applies a fixed in-flight cap to authenticated direct
  `GET` requests and returns JSON `429 too_many_requests` with `X-Request-Id`
  when the cap is reached. This is a coarse development pressure guard, not a
  substitute for production rate limiting or per-operator authorization.
- Direct listener exposure is a positive allowlist, not simply every
  bearer-authenticated `GET`. Unclassified `/api/v1` routes and internal-only
  preview/scaffold endpoints, starting with the scope-report retention plan
  preview, return JSON `404 not_found` on the direct listener even when the
  bearer token is valid.
- Direct-read OpenAPI operations carry `x-turbovas-direct: true` and
  `just native-tooling-state --json` reports marker/inventory alignment through
  `native-tooling.direct-api-contract`. Treat drift there as a contract bug
  before expanding direct exposure.
- Direct listener responses include `X-Request-Id`. A client may provide a
  bounded ASCII request ID for correlation; unsafe, empty, or oversized values
  are replaced with a generated `tv-...` ID. Auth failures and direct-listener
  server-error responses log the request ID for diagnostics.
- The browser may keep using same-origin `gsad` paths while GSA migrations are
  in progress. That bridge is not the final scriptable API boundary.
- Direct development access currently uses HTTP on an explicit development host
  binding. Production or hosted use still requires B-109/B-134 TLS, bootstrap,
  host-binding, and deployment hardening. Until that work lands,
  `production-posture-check` treats non-loopback direct native API exposure as a
  hard failure, not as production-ready behavior protected merely by bearer
  auth.

## Direct API Rules

- Do not expose a wildcard direct host binding through the development helper.
- Do not treat explicit non-loopback direct host binding as production-ready
  before the production TLS/bootstrap/host-binding posture is implemented.
- Do not log, print, or commit bearer tokens. Runtime-generated tokens live under
  the ignored runtime `secrets/` directory and are mounted read-only into the
  direct API container for the opt-in helper. Do not pass generated runtime
  tokens through container environment variables.
- Keep direct v1 access read-only. Scanner control, credentials, feed sync,
  feed import/update/download/mirroring, account management, target/task writes,
  alert delivery, and destructive mutations stay inherited until native
  write/control designs are separately reviewed. Read-only feed inventory
  metadata at `/api/v1/feeds` is allowed only as a classified scriptable read
  endpoint.
- Read-only tag-dialog resource-name lookups, including alert, are also
  allowlisted scriptable reads. They expose only id/type/name lookup data;
  alert delivery, method/event/condition payloads, and alert mutations remain
  inherited.
- Do not expose arbitrary GMP command forwarding through `/api/v1`.
- Treat `X-Request-Id` as correlation metadata only. It is not authentication,
  authorization, operator identity, or a trusted audit principal.
- Treat CORS as out of scope for this first direct helper. Command-line clients
  do not need CORS; any future separately hosted browser app must receive a
  dedicated CORS/security design.

## Validation

Use these command surfaces:

```sh
just runtime-native-api-smoke --json
just runtime-native-api-direct-smoke --json
just runtime-native-api-direct-token --json
just runtime-native-api-direct-token --json --rotate
just native-api-client-contract --json
tools/turbovasctl native-api-request --direct --json --path '/api/v1/reports?page_size=1'
tools/turbovasctl native-api-request --direct --json --request-id 'operator-check-1' --path '/api/v1/reports?page_size=1'
```

`runtime-native-api-direct-token --rotate` rotates only the ignored development
runtime bearer-token secret and never prints the token value. Restart
`turbovas-api` or rerun `runtime-native-api-direct-smoke` before expecting a
running direct listener to accept the rotated token.

Raw `curl` clients use the same bearer boundary. For the default development
listener, first run the direct smoke so the ignored runtime secret exists, then
read the token into shell memory without printing it:

```sh
TOKEN="$(tr -d '\n' < ../TurboVAS-runtime/secrets/native-api-bearer-token)"
curl --fail-with-body -sS \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Accept: application/json' \
  -H 'X-Request-Id: operator-check-1' \
  'http://127.0.0.1:19080/api/v1/reports?page_size=1'
unset TOKEN
```

When direct host or port overrides are used, call the exact host and port that
the helper validated. Do not put bearer tokens in command history examples,
logs, screenshots, or committed configuration.

The direct smoke proves file-backed runtime-secret use by default, health
access, missing-token rejection, wrong-token
rejection, generated, safe client-supplied, and unsafe client-replaced
`X-Request-Id` response headers, valid-token JSON access without browser CORS
access headers, valid-token non-GET rejection, request-body,
`Transfer-Encoding`, malformed `Content-Length`, oversized-query rejection, and
the in-flight cap's JSON `429` contract through focused Rust tests; runtime
smoke covers direct feed inventory access, tag-dialog alert resource-name lookup, and
internal-only endpoint denial for the retention preview when a scope report is
available, plus continued internal native API smoke. Malformed HTTP framing can
be rejected by the HTTP parser before native middleware; the smoke records that
layer explicitly.
`native-api-request --request-id` sends a safe `X-Request-Id` value for
correlation; it is not an authentication or audit identity.
Direct listener host/port env is locally shape-checked as part of the direct
smoke and `native-api-request --direct`: host is one host name, IPv4 address, or
bracketed IPv6 address, port is one TCP port, and bind is `host:port` or
`[ipv6]:port`. Malformed URLs, host lists, whitespace, and invalid ports are
reported as local configuration failures before direct request execution.

## Remaining Hardening Questions

- whether the internal `gsad` -> `turbovas-api` hop should gain mTLS, a private
  proxy token, or a Unix socket;
- how operator identity should be forwarded for audit once direct access moves
  beyond a single development bearer token;
- rate limits and any per-endpoint limits beyond the current direct-v1 bounded
  request-shape guard;
- TLS/certificate strategy and host-binding defaults for production;
- CSRF/origin handling for future non-GET browser-accessible native APIs;
- generated-client packaging and versioning policy.
