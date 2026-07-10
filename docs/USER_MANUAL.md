<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
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

TurboVAS is designed as an operator-only scanner console, not as a general
vulnerability-management collaboration portal. Every person who can log in to
TurboVAS is expected to be a trusted scanner operator who may administer scanner
workflows, targets, schedules, reports, credentials, and related scanner
configuration.

People who should not administer the scanner should not receive TurboVAS
console accounts. System owners, IT operations teams, application teams,
service owners, remediation teams, and ticket handlers should normally receive
findings through controlled outbound workflows such as reports, exports,
notifications, ticket-system integrations, or future delivery integrations.

This keeps the scanner administration boundary simple and explicit:

- TurboVAS console access is restricted to trusted scanner operators.
- Remediation work is delivered outward to the systems where operational teams
  already work.
- TurboVAS does not try to model every organization's internal workflow as
  in-product roles.
- Login, network exposure, TLS, host access, backups, deployment controls,
  auditability, and credential handling are the enterprise controls around
  scanner administration.

User accounts remain useful for login identity, authentication source,
preferences, and attribution, but TurboVAS does not expose a product-level
distinction between admin and super admin accounts. If a person should not be
allowed to administer the scanner, that person should not be able to log in to
TurboVAS.

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

TurboVAS supports the Greenbone Community Feed only. It does not support
Greenbone Enterprise Feed subscription keys or Enterprise Feed synchronization.
Operators who need Greenbone Enterprise Feed access, official Greenbone products,
or vendor support should contact Greenbone directly.

OpenVAS, OSPD, and Notus use runtime feed data and a persistent feed-signature
keyring. TurboVAS does not disable feed signature verification.

Useful development checks include:

- `just runtime-status`
- `just runtime-smoke`
- `just runtime-log-review --json`
- `just runtime-data-state --json`
- `just runtime-performance-snapshot --json`
- `just quality-gate-state --json`
- `just quality-gate-schedule --json --status`
- `just production-posture-check --status-only --json`
- `just runtime-app-smoke`
- `just runtime-native-api-smoke --json`
- `just runtime-native-api-direct-smoke --json`
- `just runtime-native-api-direct-write-smoke --status-only --json`
- `just runtime-native-api-direct-token --json`
- `just runtime-native-api-direct-token --json --rotate`
- `just runtime-webui-smoke --json`
- `just runtime-browser-smoke --json`
- `just runtime-browser-regression --json`
- `just runtime-credential-smoke --json`
- `just runtime-scanner-capability-check --json`
- `just runtime-nmap-capability-check --json`
- `just feed-state --json`
- `just runtime-scope-smoke --json`
- `just runtime-scope-report-summary --json`
- `just runtime-certbund-report --json`
- `just runtime-report-metrics --json`
- `just runtime-scope-report-metrics --json`

See `../BUILDING.md` and `../docker/runtime/README.md` for build and runtime
command details.

The native HTTP/JSON API is internal by default for browser/runtime migration.
For development automation, `just runtime-native-api-direct-smoke --json`
enables and validates an opt-in bearer-auth direct listener, defaulting to
loopback. That direct mode is for approved `/api/v1` development proof work:
broadly allowlisted reads plus explicitly gated write-control routes. It is not
production deployment guidance and does not authorize scanner control,
credential, feed, account, or destructive write endpoints.
It also has a fixed in-flight development pressure guard; hitting the cap
returns JSON `429 too_many_requests` rather than queueing unbounded work.
The helper creates an ignored runtime bearer-token secret and mounts it into the
direct API container as a read-only token file. Explicit
`TURBOVAS_API_BEARER_TOKEN` values still work as a development override, but
generated runtime secrets are not passed through the container environment.
Use `just runtime-native-api-direct-token --json --rotate` to rotate only this
ignored development runtime secret without printing it; rerun the direct smoke
or restart `turbovas-api` before expecting a running direct listener to accept
the rotated token.
Direct host and port overrides are intentionally narrow: use
`TURBOVAS_API_DIRECT_HOST` for one host name, IPv4 address, or bracketed IPv6
address such as `[::1]`, `TURBOVAS_API_DIRECT_PORT` for one TCP port, and
`TURBOVAS_API_DIRECT_BIND` for `host:port` or `[ipv6]:port`. Do not put URLs,
paths, comma-separated host lists, or whitespace in these values; the helper
rejects malformed direct settings before sending a direct request.
Owner-bearing native writes use direct operator identity metadata: set
`TURBOVAS_API_OPERATOR_UUID` to a real gvmd user UUID and, for audit
readability, `TURBOVAS_API_OPERATOR_NAME`. When an operator UUID is set,
`turbovas-api` verifies that it exists in `users` before binding the direct
listener. The direct write-control flag is
`TURBOVAS_API_DIRECT_WRITE_CONTROL=1`; it is strict-boolean, requires
`TURBOVAS_API_OPERATOR_UUID`, and currently enables only explicit contract-listed
native write/control routes for scopes, tags, filters, port lists, report
configs, scan configs, schedules, targets, selected alert metadata, credential
name/comment metadata, scanner metadata, task metadata, guarded task start, and
reviewed clone/
restore/trash operations. UUID-backed
resources use UUIDs; catalog-backed security information resources use exact
public IDs such as CPE URI, CVE name, NVT OID, or CERT/DFN advisory id. Alert
delivery/control, filter/bulk actions, generic file import/export, and target
credential-secret import,
credential secrets/control paths, users, reports, and results remain on
inherited compatibility paths. Direct mode otherwise accepts
only classified read-only `GET` requests.
Use a request ID when a direct probe needs a visible correlation ID in
responses/logs:

```sh
tools/turbovasctl native-api-request --direct --json --request-id 'operator-check-1' --path '/api/v1/reports?page_size=1'
```

Host-list target creation is available without GMP/XML or `gvm-tools` through
the guarded direct native API helper. Dry-run first to inspect the generated
request shape, then rerun with explicit write-control intent after direct
write-control is enabled:

```sh
tools/turbovasctl native-targets-from-host-list --json --hosts-file ./hosts.txt --dry-run
tools/turbovasctl native-targets-from-host-list --json --hosts-file ./hosts.txt --port-range 'T:1-443,U:53' --allow-write-control --status-only
tools/turbovasctl native-targets-from-csv --json --csv-file ./targets.csv --dry-run
tools/turbovasctl native-targets-from-csv --json --csv-file ./targets.csv --allow-write-control --status-only
tools/turbovasctl native-targets-from-xml --json --xml-file ./targets.xml --dry-run
tools/turbovasctl native-targets-from-xml --json --xml-file ./targets.xml --allow-write-control --status-only
tools/turbovasctl native-tags-from-csv --json --csv-file ./tags.csv --dry-run
tools/turbovasctl native-tags-from-csv --json --csv-file ./tags.csv --allow-write-control --status-only
tools/turbovasctl native-verify-scanners --json --allow-write-control --status-only
tools/turbovasctl native-start-task --task-id TASK_UUID --allow-write-control
tools/turbovasctl native-scan-new-system --host 192.0.2.10 --dry-run --status-only
tools/turbovasctl native-scan-new-system --host 192.0.2.10 --allow-scan-control --status-only
tools/turbovasctl native-export-report-csv --report-id REPORT_UUID --output ./report.csv --status-only
tools/turbovasctl native-delete-overrides-by-filter --filter 'obsolete policy' --dry-run --status-only
tools/turbovasctl native-delete-overrides-by-filter --filter 'obsolete policy' --allow-write-control --confirm-snapshot SNAPSHOT_SHA256 --status-only
tools/turbovasctl native-stop-task --task-id TASK_UUID --allow-write-control --status-only
tools/turbovasctl native-update-task-target --task-id TASK_UUID --host 192.0.2.10 --host 192.0.2.11 --exclude-host 192.0.2.11 --allow-write-control --status-only
tools/turbovasctl native-update-task-target --task-id TASK_UUID --hosts-file ./replacement-hosts.csv --allow-write-control --status-only
tools/turbovasctl native-start-tasks-from-csv --csv-file ./tasks.csv --allow-write-control --status-only
```

`native-update-task-target` replaces the retired GMP script with one guarded
direct request. It accepts exactly one explicit host input source: repeatable
`--host` values or a CSV whose first nonempty column supplies hosts; repeatable
`--exclude-host` values are optional. The current native contract is strict:
the task must be New with no report, and the operation atomically clones and
rebinds its target without starting a scan. The replacement preserves target
settings, credential links, and tags; the old target is moved to trash only
when no other live task or scope still references it. It does not accept target files, host filters,
or implicit host selection.

`native-scan-new-system` replaces the retired ad-hoc GMP scanner script with an
explicit native workflow. It accepts exactly one IPv4 or IPv6 address,
preflights the selected port list, scan config, and scan-capable scanner before
the first write, then creates a uniquely named target and task and submits the
guarded task-start request. Defaults retain the inherited IANA TCP/UDP port
list, Full and Fast config, and built-in OpenVAS scanner; each UUID can be
overridden explicitly. Use `--dry-run` to inspect the plan without runtime
writes. A real request requires `--allow-scan-control`. If task creation fails,
the helper attempts to remove its newly created target. If task start is not
accepted, it retains the prepared task and target, reads task detail to avoid
claiming a failed scan that may already be active, and reports the observed
state for diagnosis or retry.

`native-export-report-csv` replaces the inherited GMP CSV report-format script
with a deterministic TurboVAS evidence export over direct native JSON. It
preflights the exact report, paginates all result rows up to the explicit safety
cap, writes a private same-directory temporary file, and atomically replaces the
destination only after a complete export. Existing files require `--overwrite`.
The output is a stable result-evidence CSV rather than gvmd's configurable
report-format rendering; PDF and nested XML export remain separate workflows.

`native-delete-overrides-by-filter` replaces the inherited destructive GMP
script with an explicit two-step native workflow. Its `--filter` is a printable
case-insensitive substring, not GMP filter syntax. Dry-run reads a stable,
bounded override UUID set and returns its SHA-256 snapshot. A real run requires
`--allow-write-control` plus that exact hash; it takes a fresh snapshot and
refuses to proceed if the set changed. Each request enforces operator ownership,
moves one live override to trash transactionally, relocates associated tags, and
invalidates affected report override counts without hard-deleting history.
Default one-second pacing is configurable with `--delay-seconds`; partial
failures are reported while later rows continue.

`native-verify-scanners` replaces the inherited `gvm-tools` scanner verification
table with direct native API calls. It verifies each scanner without starting a
scan and reports remote/TLS/relay scanners as non-native verification warnings
until those paths have explicit native contracts.

`native-tags-from-csv` supports the native-safe subset of the inherited tag CSV
shape: Alert, Config, Credential, Scanner, Schedule, Target, and Task tags with
exact resource-name lookup. Inherited Report filter tags remain outside this
helper until their native safety contract is explicit.

`native-targets-from-xml` supports the retained secret-free target XML subset
with explicit `port_list` IDs. It rejects legacy `port_range` rows and non-SSH
credential ports instead of silently changing import semantics.

For raw `curl` probes, keep the bearer token in shell memory and read it from
the ignored runtime secret written by the direct smoke. Do not echo the token,
commit it, paste it into logs, or run this with shell xtrace enabled:

```sh
TOKEN="$(tr -d '\n' < ../TurboVAS-runtime/secrets/native-api-bearer-token)"
curl --fail-with-body -sS \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Accept: application/json' \
  -H 'X-Request-Id: operator-check-1' \
  'http://127.0.0.1:19080/api/v1/reports?page_size=1'
unset TOKEN
```

## Targets, Tasks, And Raw Evidence

Targets and tasks are technical evidence-collection mechanics.

A target describes how evidence is collected: host definitions, exclusions,
credentials, port lists, alive-test behavior, and scan constraints. A task runs a
scan against a target with a scan configuration and scanner. Raw task reports
remain available as technical evidence and provenance.

Task creation is deliberately streamlined. TurboVAS does not expose inherited
task wizards, import-task creation, task resume semantics, or per-task switches
for alterability and asset processing. Tasks are always alterable, scan results
are always added to assets, and old raw reports are automatically pruned by a
retention count. The default retention count is `10`. Pruning skips raw reports
that are referenced by scope reports so generated scope-report provenance remains
intact.

For bulk creation, `native-tasks-from-csv` accepts a headerless CSV with task,
target, scanner, scan-config, optional schedule, host ordering, and up
to five alert columns. It snapshots all required native collections and
resolves exact names or UUIDs before the first write. Missing or ambiguous
references and duplicate source names reject the full preflight; existing task
names are idempotent skips. The optional schedule and alert links are created
transactionally with each task. A blank host-ordering column defaults to
`RANDOM`, while invalid values are rejected. Host ordering is forwarded to
both OSP/OpenVAS and OpenVASD scanner transports.
Raw task XML import, interactive fallback selection, arbitrary scanner
preferences, and legacy partial-write behavior are deliberately not retained.

Starting a task is available through the guarded native
`POST /api/v1/tasks/{task_id}/start` route, either through the authenticated
browser proxy or direct API access. It requires explicit operator consent via
`tools/turbovasctl native-start-task --task-id TASK_UUID --allow-write-control`.
The request transactionally creates the report and gvmd `scan_queue` request;
gvmd remains responsible for scanner execution and result ingestion.
For name-based batch operation, `native-start-tasks-from-csv` reads the first
CSV column, resolves all tasks through paginated native reads, skips
`Running`, `Requested`, and `Queued` tasks, and reports each row while
continuing after individual failures. It replaces the inherited
`start-scans-from-csv.py` script without requiring GMP/XML or `gvm-tools`.
Stopping or cancelling a task uses guarded native
`POST /api/v1/tasks/{task_id}/stop`, available through the browser or
`native-stop-task`. The command returns success only after gvmd has serialized
the task against concurrent start/finalization work, verified scanner absence,
removed queued work, and finalized the task and active report as stopped.
Already-terminal orphan rows keep their terminal status while missing end times
are repaired. The private API-to-gvmd control socket is not host-exposed and
uses a strong internal shared secret plus validated operator/task UUIDs, never
GMP/XML. `native-stop-all-tasks` stops all active tasks, while
`native-stop-tasks-from-csv` resolves names from the first CSV column. Both
snapshot the complete task list before mutation, require explicit write-control
consent, de-duplicate UUIDs, continue after individual failures, and expose
structured result counts. CSV mode refuses ambiguous active names rather than
choosing one nondeterministically.
Resuming a partial scan is not part of the product model:
in-progress scan state is disposable, while completed raw reports and scope
reports are the valuable evidence artifacts.

For `Full and fast` scan fidelity, the development runtime keeps OpenVAS and
OSPD non-root and grants only the scanner/Nmap capabilities needed for raw
network probes. The scanner service also uses a stable runtime hostname so NASL
active checks can build packet-capture filters without Docker short-hostname
ambiguity. `just runtime-scanner-capability-check --json` and
`just runtime-nmap-capability-check --json` are the development gates for this
path. If those checks fail, or if a completed raw report contains Nmap wrapper
messages saying requested scan types require root privileges, treat the scan as
incomplete evidence rather than a trustworthy baseline.

TurboVAS does not treat a raw task report as the main operator reporting unit.
Raw reports are important evidence, but they can be too tightly coupled to
technical scan boundaries such as subnets, credentials, reachability, or scanner
constraints, or probe capability limits.

## Reports And Scope Reports

The `Reports` page keeps the inherited raw scan-report list. Use it when you
need to inspect individual technical task reports, unfinished reports, or
evidence from a specific scan run.

Scope reports are reached from `Scopes`, not from the top-level `Reports` page.
They are report-shaped snapshots for reporting populations. The experience is
intended to stay close to raw reports: information, results, severity, source
evidence, and drill-down remain recognizable, while the evidence source changes
from one technical scan report to the newest completed raw reports for the
scope's targets.

Scope report lists and evidence rows use server-backed filtering, sorting, and
pagination for the core reading workflow. Scope-report Results, Hosts, Ports,
Applications, Operating Systems, CVEs, TLS Certificates, Error Messages, and
Metrics are aggregated views backed by TurboVAS-native JSON;
result rows preserve severity display and link back to the raw scan report
evidence they were derived from. Raw report management actions that do not fit
aggregated snapshots, such as report-composer downloads, alerts, and asset/tag
mutation, remain raw-report workflows rather than scope report actions.
Inherited operator-facing report upload/import and raw delta-report comparison
workflows have been removed.

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

Because scope reports are source-reference snapshots, TurboVAS blocks deletion
of a raw source report while a scope report still references it. Delete the scope
report first if the raw evidence can intentionally be removed.

Scope report finding counts exclude scanner execution error rows, such as VT
timeout messages. Those rows remain available in the raw technical reports for
scan-fidelity troubleshooting.

Raw report details and scope report details include a `Metrics` tab. The first
snapshot metrics are `CVSS Load` and `Authenticated Scan Coverage`.

`CVSS Load` is a derived burden metric, not a replacement for CVSS itself.
TurboVAS counts each vulnerability once per alive system, even when the same NVT
appears on several ports. It excludes logs, false positives, scanner execution
errors, informational rows, and severity-zero rows. A system's CVSS Load is the
sum of the unique vulnerability scores found on that system. The report or scope
average divides the total system load by the number of alive systems. The
vulnerability view shows each NVT's score, affected-system count, total CVSS
Load contribution, and average contribution per alive system.

`Authenticated Scan Coverage` is also conservative. TurboVAS counts an alive
system as authenticated only when the report contains evidence of successful
authenticated checks. A configured credential alone is not treated as success.
Systems without a credential path are shown as `No Credential Path`; systems
with configured credentials but unclear report evidence are shown as `Unknown`.
For scope reports, these values are part of the generated scope-report snapshot
and therefore do not change when newer raw reports are created later.

Use `/scopes` to manage scopes, `/scopes/reports` to list generated scope
reports, `/scopes/:id` to inspect and edit a scope, and
`/scopes/:id/reports/:report_id` to inspect a generated scope report. Scope
editing uses explicit target and host membership controls; candidate hosts found
in evidence can be promoted into official custom-scope membership before saving.
Raw `/reports` and `/report/:id` pages remain available for technical evidence.

Scope report details include lazy evidence tabs for Hosts, Ports, Applications,
Operating Systems, CVEs, TLS Certificates, and Error Messages. These tabs are
shown as aggregated scope-report collections backed by the native DB-backed API.
The Evidence Sources tab remains the provenance view for raw report, task, and
target links.

See `SCOPE_BASED_REPORTING.md` for the detailed scope model and
`REPORTING_MODEL.md` for the first reporting loop. See
`VULNERABILITY_MANAGEMENT_PRACTICE.md` for the operating model behind it.

## Intentional Changes From Upstream Behavior

TurboVAS intentionally diverges from inherited OpenVAS behavior when that makes
the product clearer for scanner operators. Upstream compatibility is not a
default goal.

Scope-based reporting augments inherited raw scan reports instead of hiding
them. Technical targets remain evidence-collection units, raw reports remain
available for individual scan evidence, and scopes define the operational
population being reported on. This supports environments where one meaningful
reporting population requires several technical targets.

The operator-only console model replaces inherited product RBAC. A TurboVAS
account is an operator account: anyone who can log in can administer the
scanner. This is a deliberate simplification of the scanner administration
boundary, not a statement that enterprise controls are unnecessary. Stakeholder
delivery belongs in reports, exports, notifications, ticket integrations, or
future delivery workflows rather than in broad console accounts.

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

Inherited task wizards, import tasks/report upload, task resume, and raw
delta-report comparison were removed. TurboVAS uses one normal task form with
prescribed defaults: tasks are alterable, results are added to assets, and old
unreferenced raw reports are pruned by retention count.

The Trashcan remains available for retained resource types. It is useful as an
operator recovery mechanism, but it only covers resource types still supported by
TurboVAS.

Legacy Agent Controller functionality, including agent groups, agent installers,
and agent tasks, has been removed. TurboVAS keeps raw scan/report evidence,
Notus, NASL inventory collection, runtime report summary/export helpers, and
Docker runtime infrastructure. Future endpoint evidence or user-provided
inventory workflows should be designed as separate TurboVAS features instead of
preserving the inherited Agent Controller subsystem.

## License And Provenance

TurboVAS preserves upstream component provenance and license files. See
`../UPSTREAMS.md` for imported source snapshots and `../LICENSE_AUDIT.md` for
current license and provenance notes.

Public release, packaging, publication, distribution, or feed redistribution
requires additional license and feed-terms review beyond the development checks
described in this manual.

For release and deployment posture, see `PRODUCTION_POSTURE.md` and
`PUBLIC_RELEASE_READINESS.md`.
