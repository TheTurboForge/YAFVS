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
- `just build <component>`: build a supported component with local artifacts under ignored paths.
- `just build-core-c`: build the initial core C chain.
- `just build-c-services`: build the current C service baseline.
- `just build-ui`: install and build the web UI.
- `just build-python`: build/import-check Python components.
- `just build-baseline`: run the inherited-stack build baseline.
- `just runtime-plan`: show the persistent Docker runtime layout and deferred surfaces.
- `just up`: start the current Docker infrastructure services.
- `just down`: stop the current Docker infrastructure services.
- `just logs [service]`: show recent Docker runtime logs.
- `just runtime-status`: show Docker runtime status.
- `just runtime-smoke`: run infrastructure smoke checks.

The commands delegate to `tools/forkctl`, which also supports JSON output for automation, for example:

```sh
tools/forkctl doctor --json
```

See `BUILDING.md` for the current build baseline and `docker/runtime/README.md` for the current runtime groundwork.
