<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Product Direction Roadmap

This roadmap describes the product outcomes TurboVAS is intended to support.
It is not a dated release plan, a promise that a capability already exists, or
a copy of the detailed engineering backlog. Current availability and maturity
are documented in the [README](../README.md) and
[User Manual](USER_MANUAL.md).

TurboVAS is intended to help one trusted vulnerability-management team turn
provenance-bearing technical evidence into a verified reduction in exposure.
Its product direction follows the operating model in
[Vulnerability Management Practice](VULNERABILITY_MANAGEMENT_PRACTICE.md):

- systematic IT hygiene and threat-aware prioritization are concurrent duties,
  not alternatives;
- threat information determines what jumps the queue, while housekeeping
  determines whether the queue and its recurring causes shrink;
- priority changes remediation order, not the obligation to remediate; and
- only verified closure makes a vulnerability safe. Acceptance, deferral,
  mitigation, or a low score may change treatment, but do not close the
  underlying vulnerability.

## Product Outcomes

### Trustworthy Evidence And Coverage

TurboVAS should combine evidence from the collection methods that fit the
environment, including network scanning, credentialed and uncredentialed
checks, imported inventory, and endpoint- or agent-derived observations where
they improve coverage.

The product should preserve source provenance, collection time, freshness,
confidence, and links to raw evidence. Missing, stale, failed, or ambiguous
collection must remain visible as uncertainty rather than being interpreted as
safety.

### Applicability-Aware Findings

Active checks can often identify a vulnerability directly. Inventory and
software observations need a separate applicability step that maps the
observed product, version, package, configuration, and vendor context to known
vulnerabilities.

TurboVAS should support both paths without pretending they have identical
certainty. The direction includes typed evidence observations, package and
vendor context, backport awareness, machine-readable applicability statements
such as VEX where useful, and explicit evidence for non-applicability. Operators
should be able to see why a finding exists and how strongly the evidence
supports it.

### Systematic Hygiene And Root-Cause Reduction

TurboVAS should help operators identify patterns that are larger than one CVE
on one host. Useful groupings include age, recurrence, owner, platform,
software family, support status, patchability, maintenance process, and common
deployment source.

The product direction includes campaign and cluster views that reveal failed
patching, lifecycle, ownership, image, and software-management processes. The
goal is not merely to close individual tickets, but to stop the same classes of
exposure from returning.

### Threat-Aware Prioritization

Threat urgency should remain a separate, explainable dimension alongside
housekeeping leverage. TurboVAS should be able to incorporate evidence such as
active exploitation, CISA KEV, EPSS, exploit maturity, attack exposure,
reachability, lateral-movement potential, technical consequence, asset and
business context, compensating controls, and detection capability.

Related threat signals must not be counted repeatedly as if they were
independent proof. No opaque composite score should hide the reasons a finding
moved ahead of another. Threat context accelerates urgent work; it does not
erase old, widespread, recurring, or less fashionable vulnerability debt.

### Remediation, Verified Closure, And Recurrence

TurboVAS should preserve the difference between open, mitigated, accepted,
deferred, fixed-but-unverified, and verified-closed findings. Closure should
require fresh evidence that the vulnerable condition was removed, that the
affected asset or component is gone, or that durable applicability evidence
shows the finding does not apply.

The product should make rescanning and other verification evidence easy to
connect to remediation, detect recurrence, and show whether urgent exposure,
the total open burden, and the operational causes of recurring findings are
actually shrinking.

### Scope-Based Reporting And Controlled Delivery

Scopes should remain overlapping accountability and reporting views over the
best available evidence, not folders and not new truth stores. Reports should
show coverage, freshness, confidence, open risk, treatment state, trends, and
raw-evidence provenance before presentation-oriented summaries.

The operator console is for the trusted vulnerability-management team. People
who need findings for remediation, management, audit, or compliance should
receive controlled reports, exports, notifications, or delivery artifacts
rather than broad console access. Where hard tenant isolation is required, the
product direction remains separate independently operated TurboVAS stacks, not
in-application RBAC presented as a substitute for isolation.

### A Maintainable Native Platform

The product surface should move toward typed TurboVAS-native HTTP/JSON and
OpenAPI contracts over PostgreSQL. New security-sensitive backend and product
infrastructure is Rust-first. Python remains appropriate for orchestration,
while inherited C, GMP/XML, and Python product paths should be hardened,
replaced, or removed when a validated native path is ready.

This direction also requires a real production posture: secure bootstrap,
authentication, TLS, bounded network exposure, auditability, secret handling,
backup and recovery, and explicit deployment boundaries. Source availability
or a working development stack is not a production-readiness claim.

## Delivery Shape

Development proceeds through small vertical slices that leave a usable,
testable product path rather than disconnected framework pieces.

1. Strengthen the foundation: evidence provenance, scope reporting, native API
   contracts, Rust operator tooling, retained-scanner hardening, and production
   boundaries.
2. Expand the actionability layer: evidence observations, additional inventory
   inputs, applicability reasoning, systemic clustering, remediation state, and
   recurrence analysis.
3. Enrich both concurrent work queues: improve housekeeping campaign views and
   add explainable threat, exposure, asset, and control context without turning
   either into a substitute for the other.
4. Close the feedback loop: verify remediation, measure sustained reduction,
   and deliver the right evidence to operators and non-operator stakeholders.

This sequence describes engineering dependencies, not an instruction to defer
urgent threat response until hygiene is perfect. Organizations must prioritize
urgent exposure and improve the systems that create recurring exposure at the
same time.

## Deliberate Non-Goals

The roadmap does not aim to make TurboVAS:

- a multi-tenant service inside one shared scanner stack;
- a generic workflow or dashboard builder that adapts to every process;
- an incident-response platform, although vulnerability evidence may justify
  escalation to incident response;
- an OpenVAS-compatible drop-in replacement; or
- a system that declares risk gone because it was scored, assigned, accepted,
  deferred, or temporarily mitigated.

## How To Read This Roadmap

The roadmap is directional and deliberately has no delivery dates. Detailed
sequencing changes as evidence, safety, architecture, and implementation work
develop. The [README](../README.md), [User Manual](USER_MANUAL.md), and API
contracts describe what exists now; this document describes where the product
is meant to go.
