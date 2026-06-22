<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Scope-Based Reporting

TurboVAS intentionally separates technical scan collection from operator-facing
reporting.

Inherited OpenVAS concepts tend to make a technical target, a scan task, and a
generated report feel like one operational unit. That is often inconvenient for
real vulnerability management. One meaningful operational population may need
several technical targets because of network boundaries, credential sets,
scanner reachability, maintenance windows, port profiles, or scan constraints.

TurboVAS treats those concerns as different layers.

For operator usage, see `USER_MANUAL.md`. This document focuses on the product
model and implementation rationale.

## Core Concepts

### Target

A target is an evidence-collection unit.

It describes how TurboVAS should collect vulnerability evidence, including
technical details such as:

- host definitions;
- excluded hosts;
- credentials;
- port lists;
- alive-test behavior;
- scan constraints.

Targets are necessary scanner mechanics, but they are not the primary reporting
boundary.

### Scope

A scope is an accountability, policy, and reporting boundary.

It describes the population an operator wants to understand and manage. Examples
include:

- `Organization`;
- Windows servers;
- Linux desktops;
- network infrastructure;
- internet-exposed systems;
- identity infrastructure;
- high protection requirement systems;
- a business service or platform.

A scope may be associated with one or more technical targets. An asset may also
belong to several scopes. That overlap is expected.

### Scope Report

A scope report is generated for a scope, not for a single technical target.

It should show deduplicated asset and finding state for the scope, while keeping
the underlying target/task reports as evidence and provenance. A scope report
should also make coverage and freshness visible, because incomplete or stale
evidence changes the meaning of the report.

The fast browser guard `just runtime-browser-smoke --json` checks the
raw-report and scope-report reading workflow from the operator perspective. For
larger UI/API migrations or route/link/pagination symptoms, the deeper
`just runtime-browser-regression --json` command exercises scope-report detail
links, tab navigation, pagination stability, and raw-evidence routes. Neither
command starts scans or mutates feeds.

## Why Scopes Are Not Folders

TurboVAS does not model scopes as a strict tree.

Real environments are multi-dimensional. A single host can simultaneously be a
Windows server, part of identity infrastructure, internally exposed, in a high
protection requirement population, and relevant to a particular platform team.
Forcing that reality into one folder hierarchy creates inaccurate reporting and
weak ownership signals.

Scope membership should therefore be many-to-many.

## Organization Scope

TurboVAS should provide a default global scope named `Organization`.

The organization-level view must deduplicate assets and findings. It should not
sum lower-level scope reports, because overlapping scopes would inflate counts.

Correct organization reporting answers questions such as:

- how many unique assets are known;
- how many assets have fresh evidence;
- how many findings remain open;
- how old recurring findings are;
- which populations have stale or missing authenticated evidence;
- where repeated exposure points to unreliable patching or lifecycle processes.

## Protection Requirement

TurboVAS uses protection requirement terminology for impact-driven reporting
context.

The intended operator-facing values are:

- `Normal`;
- `High`;
- `Very High`.

Protection requirement describes how strongly an asset or scope should be
protected based on the consequences of compromise. It is not the same as an
information classification label such as public, internal, confidential, or
secret.

## Initial Product Direction

The first scope-based reporting implementation should stay deliberately simple:

- manual scope membership;
- a default `Organization` scope;
- scope-to-target association for evidence collection;
- scope reports built from the most recent completed relevant reports;
- explicit coverage and freshness indicators;
- deduplication of assets and findings across overlapping targets and scopes.

Rule-based membership, coordinated scope runs, richer ownership workflows, and
additional inventory sources can be added later after the basic model is useful.

## Implemented Behavior

The top-level `Reports` page keeps the inherited raw scan-report list. Scope
reports are reached through `Scopes`, where each scope shows its generated
scope-report history and links to scope-report details. Raw task reports remain
available as technical evidence from task, scope, and scope-report detail views.
Scope reports should behave like reports, not like dashboards: the familiar
report list/detail structure, status/severity presentation, information and
results tabs, and evidence links should remain recognizable. The core semantic
difference is the source set: a raw report is produced by one scan run, while a
scope report aggregates the newest completed raw reports for the targets that
belong to the scope.

Scopes manually manage two memberships:

- targets used as evidence sources;
- host assets included in official scope reporting membership.

The predefined `Organization` scope is global and non-deletable. It includes all
active targets and all known hosts by definition.

Generating a scope report does not start a scan. TurboVAS selects the newest
completed normal scan report for each associated target and stores the selected
source reports as snapshot provenance. Inherited import-task/report-upload
product behavior has been removed, so scope reports aggregate scanner-produced
raw reports. Custom scopes count only manually selected hosts. Candidate hosts
discovered in source reports are shown separately so operators can add them to a
scope deliberately.

Scope reports expose coverage and freshness signals: source report count, latest
evidence time, member hosts with evidence, member hosts without evidence, and
candidate hosts excluded from official counts.

Scope reports also persist snapshot metrics when they are generated. The first
metric families are `CVSS Load` and `Authenticated Scan Coverage`.

`CVSS Load` is calculated from vulnerability findings with positive severity,
excluding logs, false positives, scanner execution errors, informational rows,
and severity-zero rows. TurboVAS counts an NVT once per alive system, even if it
appears on multiple ports. A system's CVSS Load is the sum of the unique
vulnerability scores on that system. A vulnerability's CVSS Load is its score
multiplied by the number of affected systems. The average system load and
average vulnerability contribution divide those totals by the alive-system count
for the report or scope.

`Authenticated Scan Coverage` is evidence-based: only report evidence of
successful authenticated checks counts as authenticated. Missing target
credentials become `No Credential Path`; configured credentials without reliable
success or failure evidence become `Unknown`. This prevents TurboVAS from
mistaking intended authenticated scanning for proven authenticated scanning.

Findings are deduplicated by host identity, NVT/OID, port, and result identity.
The scope-report list is served through manager-side filtering, sorting, and
pagination. Scope-report evidence collections are now served through
TurboVAS-native JSON from PostgreSQL-backed source-report references, so
operators get aggregated tables with filtering, sorting, pagination, severity
presentation, and raw evidence links without browser-side raw-report stitching.
Raw source reports referenced by a scope report are protected from deletion so
the snapshot provenance remains intact.

The current implementation deliberately focuses on core report reading parity:
scope report list/detail views, information, results, metrics, evidence sources,
raw evidence links, and result navigation. Scope report details also expose lazy
evidence tabs. Results, Hosts, Ports, Applications, Operating Systems, CVEs, TLS
Certificates, and Error Messages are aggregated native scope-report collections.

Raw-only workflows such as import/upload, delta comparison, report-composer
downloads, alerts, and asset/tag mutation are not scope-report actions;
inherited import/upload and delta comparison have been removed from the operator
product.

Runtime helpers are available for development validation:

- `just runtime-scope-smoke --json` creates a temporary high-protection scope,
  generates a scope report from existing evidence, and cleans it up without
  starting a scan;
- `just runtime-scope-report-summary --json` summarizes the latest
  `Organization` scope report;
- `just runtime-report-metrics --json` reads CVSS Load and authenticated
  coverage for the latest completed full-test raw report through the internal
  native API;
- `just runtime-scope-report-metrics --json` reads CVSS Load and authenticated
  coverage for the latest `Organization` scope report through the internal
  native API.

## Product Rule

A target defines how TurboVAS collects evidence. A scope defines why that
evidence matters and how it is reported. A scope report is an aggregated report
over the newest completed evidence for the scope's targets, while raw
target/task reports remain the technical evidence trail.
