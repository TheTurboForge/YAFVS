<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
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
  remains an explicit environment-token override/fallback for development smoke
  only and fails production-posture/bootstrap checks when direct exposure is
  enabled.
- Direct bearer tokens must satisfy the local strength contract enforced by the
  service and helper: at least 32 printable non-whitespace ASCII characters.
  Generated runtime secrets use this stronger shape by default; weak configured
  environment tokens are rejected before use.
- Optional direct operator identity is carried by `TURBOVAS_API_OPERATOR_UUID`
  and `TURBOVAS_API_OPERATOR_NAME`. The helper validates shape locally, and the
  service verifies configured operator UUIDs against `users` before exposing the
  direct listener. This identity is required by direct write-control, but it
  does not authorize write routes by itself.
- `TURBOVAS_API_DIRECT_WRITE_CONTROL` is the direct write-control enablement
  flag. It accepts only strict boolean values, requires
  `TURBOVAS_API_OPERATOR_UUID` when truthy, and currently exposes only the
  approved direct write-control route contracts for scopes, tags, filters, port
  lists, report configs, scan configs, schedules, targets, selected alert
  metadata, credential name/comment metadata, scanner metadata, task metadata,
  and related clone/restore/trash operations where the native contract has been
  explicitly reviewed.
- `/healthz` is unauthenticated for readiness. `/api/v1/...` on the direct
  listener requires `Authorization: Bearer <token>` and returns JSON `401`
  errors for missing or wrong tokens.
- The direct listener rejects valid-token non-GET `/api/v1` requests with JSON
  `405 method_not_allowed` unless the method/path pair is deliberately
  registered as direct write-control and `TURBOVAS_API_DIRECT_WRITE_CONTROL` is
  enabled with a verified operator identity. The current direct write surface is
  limited to explicitly approved metadata/control routes and is checked by
  OpenAPI metadata plus Rust route-contract tests. The authenticated same-origin
  `gsad` browser proxy exposes the browser-relevant subset of those routes,
  including no-body DELETE for current trash/delete operations, through exact C
  path allowlists and the internal browser-proxy secret/operator headers.
  Guarded task start and stop are browser-proxied through exact UUID action
  allowlists. Stop delegates over a private `0660` Unix socket using a strong
  internal shared secret. gvmd binds the authenticated operator UUID to its own
  ACL/session before applying
  scanner and report state changes; the socket is not a host API and does not
  carry GMP/XML. Credential secrets, alert delivery, other feed/scanner control,
  account/auth control, file import/export, and unreviewed destructive behavior
  remain inherited until separately designed.
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
  server-error responses log the request ID for diagnostics. Authenticated
  direct `/api/v1` audit logs include a non-secret structured `reason` field
  for outcomes such as allowlist denial, method denial, request-shape denial,
  rate limiting, handler client errors, server errors, and success. Structured
  direct audit-log fields must not include authorization headers or bearer-token
  material.
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
- Keep direct v1 write-control limited to explicitly reviewed routes. Scanner
  runtime control, credential secrets, feed sync,
  feed import/update/download/mirroring, account management, broad task control,
  target host/exclude/port-list/alive-test/reverse-DNS/credential-link writes,
  alert delivery, security-information tag assignment, filter/bulk tag actions,
  file import/export, and unreviewed destructive mutations stay inherited until
  native write/control designs are separately reviewed. Explicit tag add/remove
  for UUID resources on the tag's existing native-safe active-table resource
  type is allowed only through the direct write-control route. Read-only feed
  inventory metadata at
  `/api/v1/feeds` is allowed only as a classified scriptable read endpoint.
- Read-only tag-dialog resource-name lookups, including alert, credential, report, and result, are also
  allowlisted scriptable reads. They expose only id/type/name lookup data;
  alert name/comment metadata PATCH is direct write-control, while alert
  delivery, method/event/condition payloads, active state, task links,
  export/test actions, and broad mutations remain inherited. Credential lookup
  is redacted id/name metadata only; credential secrets and control paths remain
  inherited.
- Credential name/comment metadata PATCH is direct write-control, while
  credential secret material, credential-store selectors, type/allow-insecure
  settings, scanner/target links, export/download, create/clone/restore/delete,
  and secret-bearing writes remain inherited.
- Target name/comment metadata PATCH is direct write-control, while hosts,
  exclude hosts, port-list references, alive-test behavior, reverse-DNS flags,
  simultaneous-IP behavior, credential links, scanner/task control, clone,
  export, delete, and target creation remain inherited.
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
just runtime-native-api-direct-bootstrap --json
just runtime-native-api-direct-smoke --json
just runtime-native-api-direct-token --json
just runtime-native-api-direct-token --json --rotate
just native-api-client-contract --status-only --json
tools/turbovasctl native-api-request --direct --json --path '/api/v1/reports?page_size=1'
tools/turbovasctl native-api-request --direct --json --request-id 'operator-check-1' --path '/api/v1/reports?page_size=1'
```

`runtime-native-api-direct-bootstrap` creates the ignored development runtime
secret if needed, verifies local direct host/port/bind shape, refuses wildcard or
non-loopback host publication, checks that the runtime token secret is not
group/world accessible when that file is used, and reports only token metadata.
If direct exposure would use `TURBOVAS_API_BEARER_TOKEN` from the environment,
the bootstrap posture check fails and points operators back to the ignored
runtime secret file boundary.
It also requires helper-managed direct binds to target the fixed service
container port `9081`, matching the Compose publication boundary. It does not
start or expose the listener.
When `TURBOVAS_API_OPERATOR_UUID` is present, malformed UUID or operator-name
values fail helper validation before the runtime is refreshed; unknown user UUIDs
fail service startup rather than falling back to an arbitrary owner.

`runtime-native-api-direct-token --rotate` rotates only the ignored development
runtime bearer-token secret and never prints the token value. Restart
`turbovas-api` or rerun `runtime-native-api-direct-smoke` before expecting a
running direct listener to accept the rotated token. The helper reports a
machine-readable warning when it detects a currently published direct listener
that may still be using the old file-backed token.

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
smoke covers direct feed inventory access, tag-dialog alert/credential resource-name lookup, and
internal-only endpoint denial for the retention preview when a scope report is
available, plus continued internal native API smoke. Malformed HTTP framing can
be rejected by the HTTP parser before native middleware; the smoke records that
layer explicitly.
The write-control smoke also proves that direct DELETE requests reject bodies,
direct non-GET requests reject query strings before mutation, explicit tag
resource add/remove can round-trip without residue for a native-safe active-table
resource fixture, and target metadata PATCH preserves adjacent host, port-list,
alive-test, reverse-DNS, simultaneous-IP, and credential-link state.
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
