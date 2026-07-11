<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# GVM Example Scripts

## CERT-Bund scan configurations

The unreliable `cfg-gen-for-certs.gmp.py` compatibility script has been
retired without a parity replacement. Use ordinary retained scan
configurations together with native CERT-Bund, CVE, and NVT reporting.

The script could lose duplicate OIDs, perform incomplete partial writes, rely
on hardcoded feed OIDs and family authority, report errors misleadingly, and
provide no provenance for generated configurations.

---

## `combine-reports.gmp.py`

This script will combine desired reports into a single report. The combined report will then be sent to a desired container task. This script will create a container task for the combined report to be sent to, however, if you would like the report to be sent to an existing task, place the report of the desired task first and add the argument 'first_task'.

### Arguments

* `<report_1_uuid>, ..., <report_n_uuid>`: UUIDs of the reports to be combined

### Example

`$ gvm-script --gmp-username=namessh --gmp-password=pass ssh --hostname=hostname scripts/combine-reports.gmp.py "d15a337c-56f3-4208-a462-afeb79eb03b7" "303fa0a6-aa9b-43c4-bac0-66ae0b2d1698" 'first_task'`

---

## TurboVAS override deletion

The inherited filter-delete script has been replaced by
`tools/turbovasctl native-delete-overrides-by-filter`. The native helper first
creates a bounded, deterministic UUID snapshot from a printable substring
filter. A real trash move requires explicit write-control permission and that
exact snapshot hash, then processes each override with configurable pacing.
The API enforces operator ownership and moves one override to trash per request;
it does not hard-delete override history.

---

## `generate-random-reports.gmp.py`

This script generates randomized report data.

### Arguments

* `-T <number of tasks>`:   number of tasks to be generated
* `-r <number of reports>`: number of reports per task
* `-R <number of results>`: number of results per report
* `--hosts <number of hosts>`:   number of randomized hosts to select from
* `'with-gauss'`: if you would like for the number of reports/task and results/report to be randomized along a Gaussian distribution
* `--task-type {container,scan}`: Type of Task(s) to store the generated Reports. Can either be 'container' or 'scan', default: 'container'.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/gen-random-reports.gmp.py -T 5 -r 4 -R 3 --hosts 10 --with-gauss`

---

## TurboVAS reporting

The three GOS-version-specific monthly-report scripts have been removed. They
implemented incompatible report-created, host-modified, and unique-NVT summary
rules for old appliance releases rather than a retained TurboVAS reporting
contract. Use native raw-report evidence or scope reports instead.

---

## `nvt-scan.gmp.py`

This script creates a new task with specific host and nvt!

### Arguments
* `<oid>`:   oid of the nvt
* `<target>`: scan target.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> 1.3.6.1.4.1.25623.1.0.106223 localhost`

---

## `pdf-report.gmp.py`

This script requests the given report and saves it as a pdf file locally.

### Arguments

* `<report_id>`: ID of the report
* `<pdf_filename>`: (optional), pdf file name

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/pdf-report.gmp.py <report_id> <pdf_file>`

---

## `start-alert-scan.gmp.py`

This script makes an alert scan and sends the report via email.

### Arguments

* `<sender_email>`:      E-Mail of the sender
* `<receiver_email>`:    E-Mail of the receiver

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/start-alert-scan.gmp.py <sender_email> <receiver_email>`

---

## `start-nvt-scan.gmp.py`

This script creates a new task (if the target is not existing) with specific host and nvt!

### Arguments
* `<oid>`:   oid of the nvt
* `<target>`: scan target.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/start-nvt-scan.gmp.py 1.3.6.1.4.1.25623.1.0.106223 localhost`

---

## Native alert CSV import

The inherited `create-alerts-from-csv.gmp.py` script has been retired. Use
`just native-alerts-from-csv -- --csv-file alerts.csv` for the retained EMAIL
and SMB nine-column positional rows. The command defaults to a local-only dry
run. Writes require `--allow-write-control`; it resolves alert, report-format,
and SMB credential references through the native API before creating anything.
Created alerts are active, matching the inherited creation default.

Only EMAIL and SMB rows are retained. EMAIL notice values map as `0=include`,
`1=simple`, and `2=attach`. SMB uses the resolved UP credential and the native
default maximum protocol. Command output is deliberately redacted and does not
show delivery addresses, SMB locations, credential references, request bodies,
or local input paths.

## Native CSV schedule creation

TurboVAS retired the inherited create-schedules-from-csv.gmp.py script.
Use tools/turbovasctl native-schedules-from-csv with --csv-file and
--allow-write-control for the inherited three-column name,timezone,icalendar
shape. Use --dry-run to inspect bounded request summaries without contacting
the runtime.

## Native XML schedule import

TurboVAS retired the inherited send-schedules.gmp.py script. Use
tools/turbovasctl native-schedules-from-xml with --xml-file and
--allow-write-control for an inherited XML document containing direct schedule
children. Name, timezone, and iCalendar are required; comment is optional.
Use --dry-run to validate every row and show only bounded, calendar-redacted
summaries before runtime access.

## Native bulk schedule calendar modification

TurboVAS retired the inherited `bulk-modify-schedules.gmp.py` script. Use
`tools/turbovasctl native-bulk-modify-schedules` with a bounded `--filter` and
at least one of `--timezone` or `--icalendar-file`. Start with `--dry-run` to
obtain the deterministic snapshot hash, then repeat the same request with
`--allow-write-control --confirm-snapshot HASH` to issue sequential native
PATCH requests. The snapshot binds the filter, selected UUIDs, timezone, and
iCalendar SHA-256 without printing calendar content. The command stops on the
first failed PATCH; prior successes remain committed and it does not claim a
rollback.

## Native CSV credential creation

TurboVAS retired the inherited `create-credentials-from-csv.gmp.py` GMP
script. Use `tools/turbovasctl native-credentials-from-csv --csv-file
./credentials.csv` or `just native-credentials-from-csv -- --csv-file
./credentials.csv`.

The default is an offline dry run: it structurally preflights the complete
bounded document, including local SSH key files, and contacts no runtime. Add
`--allow-write-control` to resolve all existing credential names and issue
sequential native writes. The helper stops after the first failed write and
does not attempt a rollback.

The CSV is positional and has **no header row**. Because it contains secrets,
it must be a private regular file with no group or world permissions. Retained
rows are exactly:

```text
name,UP,login,password
name,SSH,login,passphrase,key-path
```

Only the exact `UP` and `SSH` labels are supported. Broken inherited
`SNMP`/`ESX` branches and unknown labels are rejected. Relative key paths
must stay within the CSV directory; keys must be private regular UTF-8 files.
The helper never emits passwords, passphrases, private-key content, or local
key paths in its findings. Authoritative SSH-key/passphrase validation still
occurs inside `gvmd`; if a later row fails there, earlier successful rows remain
committed and later rows are not attempted.

## CSV tag creation

TurboVAS retired the inherited GMP `create-tags-from-csv.gmp.py` script. Use
`tools/turbovasctl native-tags-from-csv` for explicit native tag creation from
CSV. It supports Alert, Config, Credential, Report, Scanner, Schedule, Target,
and Task tags resolved by exact resource name/ID, and it rejects inherited
implicit report-filter rows that lacked explicit resources.

## Native CSV task creation

The inherited GMP CSV creator and interactive XML task sender have been
removed. TurboVAS retains explicit task import through the guarded native
operator command rather than raw XML, interactive fallback selection,
arbitrary scanner preferences, or legacy partial-write behavior:

`$ just native-tasks-from-csv -- --csv-file *task.csv* --allow-write-control`

The headerless CSV accepts 4 to 11 columns: task, target, scanner, scan config,
optional schedule, host ordering, and up to five optional alerts.
The command snapshots every required native collection and resolves exact names
or UUIDs before the first write. Missing or ambiguous references and duplicate
source task names abort preflight; existing task names are idempotent skips.
A blank host-ordering column defaults to `RANDOM`; invalid values are rejected.
Host ordering is persisted as a task preference and forwarded to both OSP/OpenVAS
and OpenVASD scanner transports.

## Native explicit-host scan start

The inherited `scan-new-system.gmp.py` script has been removed. Plan or start
the retained workflow through explicit native contracts:

`$ just native-scan-new-system -- --host 192.0.2.10 --dry-run --status-only`

`$ just native-scan-new-system -- --host 192.0.2.10 --allow-scan-control --status-only`

The command preflights its exact port list, scan config, and scanner before
creating a unique target/task and invoking guarded native task start. It does
not accept hostnames, CIDRs, ranges, interactive selection, or implicit scan
inputs.

## Native Trashcan empty

TurboVAS retired the inherited `empty-trash.gmp.py` GMP script. Start with the
counts-only operator preview:

`$ just native-empty-trash -- --status-only`

Permanent deletion is deliberately a second command. It requires all three
explicit acknowledgements, fetches a new preview immediately before the POST,
and refuses to send the POST when `--expected-total` differs from that preview:

`$ just native-empty-trash -- --allow-write-control --acknowledge-permanent-deletion --expected-total N --status-only`

The helper sends the permanent-delete request once only. A mismatch, API
rejection, and ambiguous result remain distinct in its compact output; an
ambiguous result must be checked with a new preview before another attempt.

## Native report evidence exports

The inherited `export-csv-report.gmp.py` script has been removed. Export a
report's curated result table through the direct native API:

`$ just native-export-report-csv -- --report-id *report_uuid* --output ./output.csv --status-only`

The native helper paginates deterministic result reads, writes atomically, and
refuses to overwrite an existing file unless `--overwrite` is explicit. Its
stable TurboVAS result-view schema is intentionally independent of gvmd report
format rendering.

For complete machine-processable retained evidence, including hostless scanner
error messages, export the versioned native report bundle:

`$ just native-export-report-bundle -- --report-id *report_uuid* --output ./report.turbovas-report.zip --status-only`

The bundle contains canonical raw-result JSON, typed analytical JSON
collections, report metrics and provenance, plus human-friendly Results and
Error Messages CSV views. It replaces the removed standalone nested-XML export
script; exact legacy XML bytes and schema ornamentation are not retained.

## `export-pdf-report.gmp.py`

Requests the report specified and exports it as a pdf formatted report locally.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket export-pdf-report.gmp.py *report_uuid* ./output.pdf`

- Get the *report_uuid* from the UI or a native read such as `tools/turbovasctl native-api-request --json --path '/api/v1/reports?page_size=25'`. If the output is not specified it will be named *report_uuid.pdf*

**Note**: the only changes to this script is an added ignore_pagination=True, details=True to get the full report.

## User listing

The old `list-users.gmp.py` compatibility script has been removed. Use the
redacted native API instead:

`$ tools/turbovasctl native-api-request --json --path '/api/v1/users?page_size=50'`

Returns user name, uuid, comment, and timestamps. Password hashes, auth methods,
permissions, sessions, and account writes remain inherited.

¹ The default order is "None" which equals sequential, meaning that if this field is empty scanning will be sequential as it will be if specifically set to sequential. Possible results are None, Sequential, Reverse, or Random.

## Native bulk task start from CSV

The inherited `start-scans-from-csv.py` workflow is retired. Use the guarded
native operator command instead:

`$ just native-start-tasks-from-csv -- --csv-file *csv-file with task names* --allow-write-control`

The command reads task metadata through the native API, skips tasks whose status
is `Running`, `Requested`, or `Queued`, reports every CSV row, and continues
after individual start failures. Write-control consent is required because an
eligible row creates a report and queues scanner execution.

## Native bulk task stop

The inherited GMP stop scripts have been removed. Use the guarded native
operator commands instead:

`$ just native-stop-all-tasks -- --allow-write-control`

`$ just native-stop-tasks-from-csv -- --csv-file *csv-file with task names* --allow-write-control`

Both commands snapshot all paginated task metadata before stopping anything,
select only `Running`, `Requested`, or `Queued` tasks, de-duplicate task
UUIDs, continue after individual failures, and return structured counts.
CSV lookup uses the first column and refuses ambiguous names when multiple
active tasks share one name.
