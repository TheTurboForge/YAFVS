<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changes From Upstream

TurboVAS is an independent OpenVAS-derived project. It preserves upstream
component provenance, license records, and useful scanner behavior, but it is
not an upstream-compatible product shell. TurboVAS changes inherited behavior
where doing so creates a clearer operator workflow.

TurboVAS is not affiliated with, sponsored by, or endorsed by Greenbone AG. For
official Greenbone/OpenVAS vulnerability-management products, support, or
services, contact Greenbone directly at https://www.greenbone.net/.

## Visual Identity

TurboVAS uses an independent visual identity to avoid confusion with upstream
Greenbone/OpenVAS projects while preserving factual upstream provenance.
TurboVAS branding should be performance-oriented, operator-focused, readable,
accessible, and clearly separate from upstream product branding.

## Feed Model

TurboVAS supports the Greenbone Community Feed only. It does not support
Greenbone Enterprise Feed subscription keys or Enterprise Feed synchronization.
Organizations that need Greenbone Enterprise Feed access, official Greenbone
products, support, or services should contact Greenbone directly.

Feed data is treated as runtime state, not source code. Development feed caches
and runtime feed copies stay local and untracked. TurboVAS must not bundle,
package, mirror, or redistribute feed content without a separate feed-terms
review.

## Reporting Model

Inherited OpenVAS behavior makes raw task reports the primary reporting surface.
TurboVAS keeps raw reports under `/reports` for technical evidence, but adds
scopes as the population-level reporting layer.

Scopes let operators associate several technical targets with one reporting
population. Scope reports aggregate the newest completed raw report for each
scope target, preserve raw source-report provenance, expose coverage/freshness,
and provide report-like drill-down under `/scopes/reports` and
`/scopes/:scope_id/reports/:scope_report_id`.

## Operator-Only Console Model

TurboVAS removed the inherited product RBAC model because the TurboVAS console
is an operator-only scanner administration surface, not a general stakeholder
collaboration portal. Anyone who can authenticate to the console is a trusted
scanner operator with scanner administration rights.

People who should not administer scans, targets, credentials, schedules,
reports, and scanner configuration should not receive TurboVAS console accounts.
Their findings should be delivered through reports, exports, notifications,
ticket-system integrations, or future delivery workflows. User accounts remain
for login identity, authentication source, preferences, and attribution, not for
modeling every organization's internal workflow as product roles.

The administration boundary is therefore explicit: restrict console login,
network exposure, TLS, host access, backups, deployment controls, auditability,
and credential handling to trusted scanner operators.
Development credentials are `admin` / `admin` and are not production guidance.

## Removed Inherited Product Surfaces

TurboVAS removed inherited surfaces that do not fit the current operator-first
scanner workflow:

- OCI/container-image scanning;
- legacy Agent Controller functionality;
- top-level Dashboards, Notes, Tickets, Policies, Audits, and Audit Reports;
- main-menu Help/CVSS calculator;
- diagram/dashboard strips on retained entity-list pages;
- task wizards, import tasks/report upload, task resume, and raw delta reports.

These were full-stack removals, not Web UI hides. Database schema, backend
handlers, GMP/API surfaces, clients, UI routes, tests, and documentation were
removed or migrated where applicable.

## Retained Foundations

TurboVAS still keeps the scanner fundamentals:

- normal targets, tasks, raw scan reports, results, and assets;
- Notus and NASL inventory collection;
- generic runtime report summary/export helpers;
- Docker-based development/runtime infrastructure;
- Trashcan support for retained resource types;
- feed validation, immutable generations, and guarded service/database activation.

SSH-authenticated targets use explicit per-IP OpenSSH SHA-256 server host-key
pins. TurboVAS refuses credentialed SSH authentication when a pin is missing,
malformed, or does not match, and permits multiple pins for controlled key
rotation. Existing SSH-authenticated targets therefore require verified pins
after upgrading.

Future inventory onboarding and vulnerability matching should be designed as
TurboVAS-native workflows instead of preserving removed inherited subsystems.
