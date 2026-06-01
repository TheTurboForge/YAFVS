# TurboVAS Runtime Groundwork

This directory documents the development/runtime Docker scaffolding. It is not a
production deployment definition yet.

The current Compose stack starts infrastructure services only:

- Postgres
- Redis
- Mosquitto
- optional `dev-shell` profile for toolchain/container experiments

Persistent state is stored outside the repository by default, normally in the
sibling `TurboVAS-runtime` directory. Runtime commands create these
host-visible directories before starting services:

- `postgres/`
- `redis/`
- `mosquitto/`
- `feeds/`
- `run/`
- `logs/`
- `artifacts/`

The initial services bind host ports to `127.0.0.1` only. Full `gvmd`, `gsad`,
`ospd-openvas`, `notus-scanner`, feed population, certificate generation,
scanner registration, and scan execution are intentionally deferred.
