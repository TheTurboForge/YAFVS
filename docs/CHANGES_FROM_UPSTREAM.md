<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changes From Upstream

YAFVS is an independent OpenVAS-derived project. It preserves upstream
component provenance, license records, and useful scanner behavior, but it is
intentionally not OpenVAS-compatible and is not a drop-in replacement. This is
a strategic product decision, not accidental drift or a compatibility backlog.
YAFVS changes or removes inherited APIs, data models, workflows, and features
when doing so makes the scanner simpler, safer, or clearer for its operators.

YAFVS is not affiliated with, sponsored by, or endorsed by Greenbone AG. For
official Greenbone/OpenVAS vulnerability-management products, support, or
services, contact Greenbone directly at https://www.greenbone.net/.

## Visual Identity

YAFVS uses an independent visual identity to avoid confusion with upstream
Greenbone/OpenVAS projects while preserving factual upstream provenance.
YAFVS branding should be understated, operator-focused, readable, accessible,
and clearly separate from upstream product branding.

## Feed Model

YAFVS supports the Greenbone Community Feed only. It does not support
Greenbone Enterprise Feed subscription keys or Enterprise Feed synchronization.
Organizations that need Greenbone Enterprise Feed access, official Greenbone
products, support, or services should contact Greenbone directly.

Feed data is treated as runtime state, not source code. Development feed caches
and runtime feed copies stay local and untracked. YAFVS must not bundle,
package, mirror, or redistribute feed content without a separate feed-terms
review.

## Reporting Model

Inherited OpenVAS behavior makes raw task reports the primary reporting surface.
YAFVS keeps raw reports under `/reports` for technical evidence, but adds
scopes as the population-level reporting layer.

Scopes let operators associate several technical targets with one reporting
population. Scope reports aggregate the newest completed raw report for each
scope target, preserve raw source-report provenance, expose coverage/freshness,
and provide report-like drill-down under `/scopes/reports` and
`/scopes/:scope_id/reports/:scope_report_id`.

## Operator-Only Console Model

YAFVS deliberately removed the inherited product RBAC model. This is an
intentional operating and trust-boundary decision, not an accidental omission,
a temporary simplification, or a compatibility feature planned for restoration.
One installation represents one trusted vulnerability-management or
scanner-operations team. Its individually authenticated operators intentionally
share visibility and authority over the scanner estate so they can understand
and continue one another's work and cover for one another during leave or other
absences. The number of scanned assets does not determine whether an
installation is multi-tenant.

People who only consume findings for compliance, remediation, management, or
reporting should not receive YAFVS console accounts. Their required
information should be delivered automatically through reports, exports,
notifications, and controlled appliance delivery workflows—for example, email
routed into a ticket system or files written to an approved network share. User
accounts remain for login identity, authentication source, preferences, and
attribution, not for modeling every organization's internal workflow as product
roles.

This is a deliberate tradeoff for YAFVS's intended deployment model.
Operational continuity naturally drives a scanner-operations team toward broad,
equivalent operator authority: every member needs enough context and control to
continue shared work, respond to incidents, and cover for an unavailable
colleague. If a role model prevents that handover, the team has a sound
operational reason to broaden its role assignments until continuity is
restored. The practical result is often nearly identical operator access. In
that setting, retaining a granular role layer can preserve its full
implementation and operating cost without creating a useful boundary between
teammates. For YAFVS those costs include:

- permission joins and filters on operational queries;
- visibility and edit rules that become harder to explain, diagnose, and test
  across related scanner resources;
- permission configuration drift and accidental gaps in team coverage;
- migrations and combinatorial tests for role and permission states; and
- a risk that resource-level visibility rules are mistaken for tenant
  isolation while privileged processes, data, secrets, and failure domains
  remain shared.

Removing that layer lets YAFVS make the actual boundary explicit: individual
identities establish who authenticated and who acted, while all admitted human
operators belong to the same product-level trust domain. This rationale is
specific to YAFVS. Products designed to host mutually untrusted groups inside
one application may reasonably choose a different authorization model; YAFVS
instead requires separate stacks for that problem.

When groups require a real administrative or confidentiality boundary, they
must use separate, independently operated stacks. That deployment boundary can
isolate databases, reports, scanner execution, runtime secrets, networks, logs,
exports, and backups; row or UI permissions inside one shared application and
failure domain cannot provide the same tenant isolation. YAFVS is not a
multi-tenant vulnerability-management collaboration platform.

The administration boundary is therefore explicit: use individual operator
accounts, restrict console login and operator API access, and retain appropriate
network, TLS, host, backup, deployment, audit, and credential controls. Shared
product authority does not imply shared login credentials or automatic
infrastructure access.
Development credentials are `admin` / `admin` and are not production guidance.

## Removed Inherited Product Surfaces

YAFVS removed inherited surfaces that do not fit the current operator-first
scanner workflow:

- OCI/container-image scanning;
- legacy Agent Controller functionality;
- top-level Dashboards, Notes, Tickets, Policies, Audits, and Audit Reports;
- main-menu Help/CVSS calculator;
- diagram/dashboard strips on retained entity-list pages;
- the inherited browser System Reports/Performance page and its GMP/gvmd
  bridge;
- task wizards, import tasks/report upload, task resume, and raw delta reports.

These were full-stack removals, not Web UI hides. Database schema, backend
handlers, GMP/API surfaces, clients, UI routes, tests, and documentation were
removed or migrated where applicable.
Operational runtime measurements remain available through the YAFVS-native
`runtime-performance-snapshot` command; they are not modeled as scan reports.

## Retained Foundations

YAFVS still keeps the scanner fundamentals:

- normal targets, tasks, raw scan reports, results, and assets;
- Notus and NASL inventory collection;
- generic runtime report summary/export helpers;
- Docker-based development/runtime infrastructure;
- Trashcan support for retained resource types;
- feed validation, immutable generations, and guarded service/database activation.

SSH-authenticated targets use explicit per-IP OpenSSH SHA-256 server host-key
pins. YAFVS refuses credentialed SSH authentication when a pin is missing,
malformed, or does not match, and permits multiple pins for controlled key
rotation. Existing SSH-authenticated targets therefore require verified pins
after upgrading.

Future inventory onboarding and vulnerability matching should be designed as
YAFVS-native workflows instead of preserving removed inherited subsystems.
