# Building TurboVAS

TurboVAS currently has a local inherited-stack build baseline for:

- C services: `gvm-libs`, `openvas-smb`, `openvas-scanner`, `gvmd`, `gsad`
- Web UI: `gsa`
- Python components: `python-gvm`, `gvm-tools`, `greenbone-feed-sync`, `ospd-openvas`, `notus-scanner`

Build output, local install artifacts, Python virtual environments, and component dependency directories are kept under ignored paths. C components install into `build/prefix` when downstream components need their pkg-config metadata and headers.

## Commands

Check dependency readiness:

```sh
just deps
just deps gvmd
just deps gsa
```

Build one supported component:

```sh
just build gvmd
just build gsad
just build gsa
just build python-gvm
```

Build grouped baselines:

```sh
just build-core-c
just build-c-services
just build-ui
just build-python
just build-baseline
```

Machine-readable output is available through `tools/forkctl`, for example:

```sh
tools/forkctl deps --json
tools/forkctl build-baseline --json
```

## Notes

The server baseline uses the Ubuntu `libcurl4-gnutls-dev` package because the scanner build expects the GnuTLS curl variant.

The scanner build currently passes `-isystem /usr/include/mit-krb5` through `forkctl` because Ubuntu's `mit-krb5-gssapi` pkg-config metadata exposes the GSSAPI header path there. This keeps the Phase 2 baseline reproducible without modifying imported source code.

The web UI baseline uses Node.js 22 with npm 11 from an official Node.js binary installation on the development server. The NodeSource apt repository was not used for the final install because its dry-run transaction would have removed unrelated distro Node tooling.

The Python baseline uses `uv` with per-component virtual environments under `build/venvs`.
