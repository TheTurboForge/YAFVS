<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Reporting Model

TurboVAS reporting is intentionally prescriptive. The product should guide
operators toward evidence quality, scope coverage, freshness, authenticated
coverage, and drill-down to raw evidence.

## First Reporting Loop

1. Define targets for technical evidence collection.
2. Define scopes for the populations that need reporting.
3. Associate scope targets as evidence sources.
4. Associate scope hosts as official reporting membership.
5. Run normal scan tasks outside the scope-report generator.
6. Generate scope reports from the newest completed raw reports for scope
   targets.
7. Read the scope report first, then drill down to raw report evidence when a
   finding, host, source, or fidelity question needs proof.

## Core Signals

Scope reports should make these signals visible:

- source report count;
- latest evidence time;
- member hosts with evidence;
- member hosts missing evidence;
- candidate hosts excluded from official custom-scope counts;
- CVSS Load by system and vulnerability;
- Authenticated Scan Coverage;
- raw source-report provenance.

## Reading Order

The intended operator reading order is:

1. Scope coverage and freshness: is this report representative enough to act on?
2. Authenticated Scan Coverage: which alive systems were credibly scanned with
   successful credentials?
3. CVSS Load: which systems and vulnerabilities carry the highest current
   burden?
4. Results: which findings need action or explanation?
5. Evidence sources: which raw report proves the finding, and how fresh is it?

Raw reports remain available under `/reports` for technical evidence, scan
fidelity troubleshooting, and source-level inspection.

## What This Is Not

Scope reports do not start scans. They do not copy raw result rows into a new
truth store. They do not replace raw evidence. They are generated snapshots over
source raw reports, with provenance preserved.

Trend storage, exposure-duration analysis, SLA policy, and incident-response
mechanics are future reporting layers, not part of the first snapshot loop.
