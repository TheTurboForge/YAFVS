<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
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

## Product Rule

A target defines how TurboVAS collects evidence. A scope defines why that
evidence matters and how it is reported. A scope report presents deduplicated
asset and finding state for the scope, while raw target/task reports remain the
technical evidence trail.
