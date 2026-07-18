<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Performance Baseline

YAFVS should optimize only after it can measure the relevant cost. The
current goal is not to set thresholds or chase micro-optimizations. The goal is
to define the first repeatable baseline so future changes can answer: did this
make report reading, scope reporting, runtime services, or scanner execution
measurably better or worse?

Run the current baseline with:

```sh
just runtime-performance-snapshot --json
```

The command writes retained artifacts under
`$TURBOVAS_RUNTIME_DIR/artifacts/performance/`; when the variable is unset,
`tools/turbovasctl` uses the sibling `TurboVAS-runtime` directory. The snapshot
records Docker, PostgreSQL, report-workflow, scanner Redis, runtime artifact,
and GSA static-asset facts.

## Current Measurements

The snapshot currently captures:

- Docker CPU, memory, network I/O, block I/O, and PID counters per container;
- top containers by CPU, memory, network I/O, block I/O, and PID count;
- PostgreSQL database size, largest relations, and known table row counts;
- report-workflow counts and largest report/scope-report indicators;
- scanner Redis DB size, keyspace count, memory, client, command, and hit/miss
  counters without exposing key names or values;
- runtime artifact/log/build-prefix/GSA static tree size;
- largest staged GSA static assets.

These facts are thresholdless. A large value is not automatically a bug. It is
a prompt to inspect whether the cost is expected, useful, and stable.

## First Hot-Path Set

Use these as the first practical benchmark targets:

1. Scope-report list and Results reads.
   Measure filter/sort/page behavior, row counts, and response size before and
   after adding more DB-backed evidence collections.
2. Scope-report lazy evidence tabs.
   Compare source-by-source raw-report loading against future dedicated backend
   collections for applications, operating systems, and TLS certificates.
3. Raw report detail and metrics reads.
   Watch payload size and query cost when raw reports grow, because raw reports
   remain authoritative evidence.
4. GSA static bundle and route loading.
   Track largest assets and route chunks before frontend modernization or route
   splitting work.
5. Scanner Redis lifecycle during an authorized scan.
   Sample before, during, and after a controlled scan to understand KB/runtime
   pressure before challenging scanner Redis architecture.
6. PostgreSQL relation growth.
   Track `results`, `reports`, scope-report tables, metric tables, and any
   future evidence tables before introducing materialized views or denormalized
   snapshots.

## Baseline Procedure

Before a performance-sensitive change:

1. Run `just runtime-performance-snapshot --json`.
2. Run the focused workflow command or browser smoke that exercises the path.
3. Run `just runtime-performance-snapshot --json` again.
4. Compare retained artifacts by timestamp.
5. Record any meaningful difference in the implementation commit or private
   worklog.

For scanner lifecycle work, add `runtime-redis-state --json` at the same points.
Do not start scans just for performance curiosity; scan measurements require an
authorized scan objective.

## Non-Goals

- No production SLOs yet.
- No automatic pass/fail thresholds yet.
- No broad profiler setup until a baseline points at a concrete hot path.
- No optimization that weakens scan fidelity, raw evidence integrity,
  authentication boundaries, feed validation, or license/provenance hygiene.

## Next Step

The next implementation step is to pick one path, most likely scope-report
Hosts or CVEs, and compare the inherited source-report stitching cost with a
DB-backed collection contract.
