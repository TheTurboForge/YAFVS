# Building TurboVAS

TurboVAS currently has an initial local build baseline for the first C dependency chain:

- `components/gvm-libs`
- `components/openvas-smb`
- `components/openvas-scanner`

Build output and the local install prefix are kept under ignored `build/` paths. The first two components install into `build/prefix` so downstream components can find their pkg-config metadata and headers without touching system paths.

## Commands

Check dependency readiness:

```sh
just deps
just deps gvm-libs
just deps openvas-smb
just deps openvas-scanner
```

Configure or build one CMake component:

```sh
just configure gvm-libs
just build gvm-libs
just build openvas-smb
just build openvas-scanner
```

Build the current core C chain in dependency order:

```sh
just build-core-c
```

Machine-readable output is available through `tools/forkctl`, for example:

```sh
tools/forkctl deps --json
tools/forkctl build-core-c --json
```

## Notes

The server baseline uses the Ubuntu `libcurl4-gnutls-dev` package because the scanner build expects the GnuTLS curl variant.

The scanner build currently passes `-isystem /usr/include/mit-krb5` through `forkctl` because Ubuntu's `mit-krb5-gssapi` pkg-config metadata exposes the GSSAPI header path there. This keeps the Phase 2 baseline reproducible without modifying imported source code.
