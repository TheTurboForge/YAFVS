<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS User Manual

TurboVAS is an independent OpenVAS-derived scanner for vulnerability management
operators. It is not affiliated with, sponsored by, or endorsed by Greenbone AG.
Greenbone remains the upstream source for the imported OpenVAS/Greenbone
components recorded in `../UPSTREAMS.md`; organizations looking for official
Greenbone/OpenVAS products, support, or services should contact Greenbone
directly at https://www.greenbone.net/.

TurboVAS is currently in private development. This manual describes the current
development runtime and implemented operator workflows. It is not production
deployment guidance.

## Operator Access And Security Boundary

TurboVAS is designed for scanner operators. Anyone who can log in can administer
the scanner. User accounts remain useful for login identity, preferences, and
attribution, but TurboVAS does not expose a product-level distinction between
admin and super admin accounts.

The current local development runtime uses the development credentials
`admin` / `admin`. Treat those credentials as a private development convenience
only. Do not use them as production authentication guidance.

The development GSA Web UI can be served through the Docker runtime. The current
runtime supports explicit loopback, LAN, and Tailscale bindings; non-loopback
access is intentionally configured when needed and should not be treated as a
production exposure model.

## Runtime State

The Docker runtime keeps valuable state outside the repository under the
TurboVAS runtime directory. That state includes PostgreSQL data, certificates,
logs, feed cache data, runtime feed copies, scanner state, and report artifacts.

Greenbone Community Feed data is handled as local runtime state, not as source
code. TurboVAS keeps a canonical downloaded feed cache and copies known feed
subtrees into the runtime feed tree for services to consume. Do not commit,
bundle, package, or redistribute feed content unless a separate feed-terms review
explicitly approves that use.

OpenVAS, OSPD, and Notus use runtime feed data and a persistent feed-signature
keyring. TurboVAS does not disable feed signature verification.

Useful development checks include:

- `just runtime-status`
- `just runtime-smoke`
- `just runtime-app-smoke`
- `just runtime-webui-smoke --json`
- `just feed-state --json`
- `just runtime-scope-smoke --json`
- `just runtime-scope-report-summary --json`

See `../BUILDING.md` and `../docker/runtime/README.md` for build and runtime
command details.

## Targets, Tasks, And Raw Evidence

Targets and tasks are technical evidence-collection mechanics.

A target describes how evidence is collected: host definitions, exclusions,
credentials, port lists, alive-test behavior, and scan constraints. A task runs a
scan against a target with a scan configuration and scanner. Raw task reports
remain available as technical evidence and provenance.

TurboVAS does not treat a raw task report as the main operator reporting unit.
Raw reports are important evidence, but they can be too tightly coupled to
technical scan boundaries such as subnets, credentials, reachability, or scanner
constraints.

## Scope Reports

The operator-facing `Reports` page lists scope reports.

A scope is a reporting population. It describes the set of assets an operator
wants to understand, such as an organization, a technology class, an exposure
class, a protection requirement group, or a business service.

TurboVAS provides a predefined global scope named `Organization`. It is
non-deletable and includes all active targets and known hosts by definition.

Custom scopes manage two memberships:

- targets used as evidence sources;
- host assets included in official scope reporting membership.

Protection requirement values are:

- `Normal`
- `High`
- `Very High`

Generating a scope report does not start a scan. TurboVAS selects the newest
completed scan report for each associated target, stores those source reports as
snapshot provenance, deduplicates findings, and exposes coverage and freshness
signals. Candidate hosts discovered in the source reports can be shown so an
operator can decide whether to add them to a custom scope.

Use `/scopes` to manage scopes, `/scope/:id` to inspect and edit a scope, and
`/scope-report/:id` to inspect a generated scope report. Raw `/report/:id` pages
remain reachable from task and scope-report evidence links.

See `SCOPE_BASED_REPORTING.md` for the detailed scope model and
`VULNERABILITY_MANAGEMENT_PRACTICE.md` for the operating model behind it.

## Intentional Changes From Upstream Behavior

TurboVAS intentionally diverges from inherited OpenVAS behavior when that makes
the product clearer for scanner operators. Upstream compatibility is not a
default goal.

Scope-based reporting replaces inherited target/report coupling. Technical
targets remain evidence-collection units, while scopes define the operational
population being reported on. This supports environments where one meaningful
reporting population requires several technical targets.

The operator-account model replaces inherited product RBAC. Anyone who can log
in can administer the scanner. Authentication and deployment exposure are
therefore the scanner administration boundary.

Dedicated OCI/container-image scanning was removed. TurboVAS is moving toward
inventory-based vulnerability matching, where scanner-collected and future
user-provided inventory can feed vulnerability matching workflows without a
separate dedicated container scanner subsystem.

The inherited Help/CVSS calculator, top-level Dashboards, Notes, Tickets,
Policies, Audits, and Audit Reports product surfaces were removed because they
do not fit the current operator-first scanner workflow.

Inherited diagram/dashboard strips were removed from retained list pages such as
Tasks, Reports, Results, Vulnerabilities, Overrides, Hosts, Operating Systems,
and TLS Certificates. The ordinary entity list tables and detail workflows remain
available.

Raw scan/report evidence, Notus, NASL inventory collection, generic report
import infrastructure, Docker runtime infrastructure, and agent functionality
remain unless a later full-stack product decision changes them.

## License And Provenance

TurboVAS preserves upstream component provenance and license files. See
`../UPSTREAMS.md` for imported source snapshots and `../LICENSE_AUDIT.md` for
current license and provenance notes.

Public release, packaging, publication, distribution, or feed redistribution
requires additional license and feed-terms review beyond the development checks
described in this manual.
