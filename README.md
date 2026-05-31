# TurboVAS

TurboVAS is an OpenVAS-derived monorepo for vulnerability scanner operators. It is intentionally organized around the components required to run OpenVAS Scan / TurboVAS as one coherent scanner system.

This repository is currently in an early private development phase. The initial source snapshot preserves upstream component boundaries and provenance so future changes can be made with clear licensing and attribution context.

## Components

Imported upstream components live under `components/`.

See `UPSTREAMS.md` for source provenance and imported commit IDs. See `LICENSE_AUDIT.md` for the initial license and provenance audit notes.

## Development Commands

TurboVAS provides a small root command surface for repository health checks:

- `just status`: show repository branch, HEAD, upstream, and worktree state.
- `just inventory`: list the expected monorepo components.
- `just doctor`: run structural and environment readiness checks.
- `just license-report`: check preserved license and provenance files.
- `just deps [component]`: check build dependency readiness.
- `just configure <component>`: configure a CMake component into `build/<component>/`.
- `just build <component>`: build a CMake component with local artifacts under `build/`.
- `just build-core-c`: build the initial core C chain.

The commands delegate to `tools/forkctl`, which also supports JSON output for automation, for example:

```sh
tools/forkctl doctor --json
```

See `BUILDING.md` for the current build baseline.
