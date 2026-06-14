<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Changes From Upstream

TurboVAS is an independent OpenVAS-derived project. It preserves upstream
component provenance, license records, and useful scanner behavior, but it is
not an upstream-compatible product shell. TurboVAS changes inherited behavior
where doing so creates a clearer operator workflow.

TurboVAS is not affiliated with, sponsored by, or endorsed by Greenbone AG. For
official Greenbone/OpenVAS vulnerability-management products, support, or
services, contact Greenbone directly at https://www.greenbone.net/.

## Reporting Model

Inherited OpenVAS behavior makes raw task reports the primary reporting surface.
TurboVAS keeps raw reports under `/reports` for technical evidence, but adds
scopes as the population-level reporting layer.

Scopes let operators associate several technical targets with one reporting
population. Scope reports aggregate the newest completed raw report for each
scope target, preserve raw source-report provenance, expose coverage/freshness,
and provide report-like drill-down under `/scopes/reports` and
`/scopes/:scope_id/reports/:scope_report_id`.

## Operator Account Model

TurboVAS removed the inherited product RBAC model. Anyone who can authenticate
to the scanner is a trusted scanner operator with full administration rights.
User accounts remain for login identity, preferences, and attribution.

The security boundary is therefore authentication plus deployment exposure.
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
- feed validation and local feed-cache/runtime-copy separation.

Future inventory onboarding and vulnerability matching should be designed as
TurboVAS-native workflows instead of preserving removed inherited subsystems.
