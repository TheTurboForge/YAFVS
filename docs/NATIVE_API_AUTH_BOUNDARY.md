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
  `127.0.0.1:19080` only when direct mode is requested and configures a bearer
  token from `TURBOVAS_API_BEARER_TOKEN` or an ignored runtime secret.
- `/healthz` is unauthenticated for readiness. `/api/v1/...` on the direct
  listener requires `Authorization: Bearer <token>` and returns JSON `401`
  errors for missing or wrong tokens.
- The browser may keep using same-origin `gsad` paths while GSA migrations are
  in progress. That bridge is not the final scriptable API boundary.
- Direct development access currently uses HTTP on an explicit development host
  binding. Production or hosted use still requires B-109/B-134 TLS, bootstrap,
  host-binding, and deployment hardening.

## Direct API Rules

- Do not expose a wildcard direct host binding through the development helper.
- Do not log, print, or commit bearer tokens. Runtime-generated tokens live under
  the ignored runtime `secrets/` directory.
- Keep direct v1 access read-only. Scanner control, credentials, feeds, account
  management, target/task writes, alert delivery, and destructive mutations stay
  inherited until native write/control designs are separately reviewed.
- Do not expose arbitrary GMP command forwarding through `/api/v1`.
- Treat CORS as out of scope for this first direct helper. Command-line clients
  do not need CORS; any future separately hosted browser app must receive a
  dedicated CORS/security design.

## Validation

Use these command surfaces:

```sh
just runtime-native-api-smoke --json
just runtime-native-api-direct-smoke --json
tools/turbovasctl native-api-request --direct --json --path '/api/v1/reports?page_size=1'
```

The direct smoke proves health access, missing-token rejection, wrong-token
rejection, valid-token JSON access, and continued internal native API smoke.

## Remaining Hardening Questions

- whether the internal `gsad` -> `turbovas-api` hop should gain mTLS, a private
  proxy token, or a Unix socket;
- how request IDs and operator identity should be forwarded for audit;
- rate limits and payload limits for heavyweight report queries;
- TLS/certificate strategy and host-binding defaults for production;
- CSRF/origin handling for future non-GET browser-accessible native APIs;
- generated-client packaging and versioning policy.
