<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_logo_resilience_horizontal.png)

# GVM Example Scripts

## `cfg-gen-for-certs.gmp.py`

This script creates a new scan config with nvts from a given CERT-Bund!

### Arguments

* `<cert>`: Name or ID of the CERT-Bund

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/cfg-gen-for-certs.gmp.py CB-K16/0943`

---

## `combine-reports.gmp.py`

This script will combine desired reports into a single report. The combined report will then be sent to a desired container task. This script will create a container task for the combined report to be sent to, however, if you would like the report to be sent to an existing task, place the report of the desired task first and add the argument 'first_task'.

### Arguments

* `<report_1_uuid>, ..., <report_n_uuid>`: UUIDs of the reports to be combined

### Example

`$ gvm-script --gmp-username=namessh --gmp-password=pass ssh --hostname=hostname scripts/combine-reports.gmp.py "d15a337c-56f3-4208-a462-afeb79eb03b7" "303fa0a6-aa9b-43c4-bac0-66ae0b2d1698" 'first_task'`

---

## `delete-overrides-by-filter.gmp.py`

This script deletes overrides with a specific filter value.

### Arguments

* `<filter>`: the parameter for the filter.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/delete-overrides-by-filter.gmp.py <filter>`

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

## `monthly-report.gmp.py`

This script will display all vulnerabilities from the hosts of the reports in a given month!

### Arguments

* `<month>`: month of the monthly report
* `<year>`: year of the monthly report
* `'with-tables'`: (optional), parameter to activate a verbose output of hosts.

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/monthly-report.gmp.py 05 2019 with-tables`

---

## `monthly-report2.gmp.py`

This script will display all vulnerabilities from the hosts of the reports in a given month!

### Arguments

* `<month>`: month of the monthly report
* `<year>`: year of the monthly report

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/monthly-report2.gmp.py 05 2019`

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

## `scan-new-system.gmp.py`

This script starts a new scan on the given host.

### Arguments

* `<host_ip>`  IP Address of the host system

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/scan-new-system.gmp.py <host_ip>`

---

## `send-schedules.gmp.py`

This script pulls schedule data from an xml document and feeds it to a desired GSM.

### Arguments

* `<xml_doc>`:   .xml file containing schedules

### Example

`$ gvm-script --gmp-username name --gmp-password pass ssh --hostname <gsm> scripts/send-schedules.gmp.py example_file.xml`

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

## `create-alerts-from-csv.gmp.py`

Creates alerts as specified in a csv-file. See alerts.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-alerts-from-csv.gmp.py alerts.csv `

- For SMB Alerts use something like %N_%CT%z in the naming of the report, as shown in the example alerts.csv
- %N is the name for the object or the associated task for reports, %C is the creation date in the format YYYYMMDD, and %c is the creation time in the format HHMMSS.
- The script only support EMAIL and SMB Alerts, please note that the fields are quite different between the two alert types, but refer to the sample alerts.csv
- The CSV must starts with name, type (EMAIL or SMB). The remaining fields then depend on the type chosen, specifically:
- EMAIL; *senders email*, *recipients email*, *mail subject*, *message body*, *notice type* (0=Report in message 1=Simple Notice or 2=Attach Report), *Report Type* (e.g. CSV Results), *Status* (Done, Requested)
- SMB; *SMB Credentials*,*SMB Share Path*,*Report Name*, *Report Folder* (if not stored in the root of the share), *Not used*, *Report Type* (e.g. CSV Results), *Status* (Done, Requested)
- A simple example below with 1 EMAIL alert and 1 SMB Alert.
Alert_EMAIL_Stop,EMAIL,"martin@example.org","noc@example.org","Message Subject","Message Body",1,"CSV Results","Stop Requested"
Alert_SMB_Done,SMB,"Cred_Storage_SMB","\\smbserver\share","%N_%CT%cZ","Reports",,"CSV Results","Done"

**Note**: This script relies on credentials as/if specified in alerts.csv as well as a working SMTP server on the Greenbone primary server. If you're using SMB add the required credentials first using [create-credentials-from-csv.gmp.py](#create-credentials-from-csvgmppy).

## `create-schedules-from-csv.gmp.py`

Creates schedules as specified in a csv-file. See schedules.csv for file format/contents.

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-schedules-from-csv.gmp.py ./schedules.csv`

**Note**: create schedules, then credentials, then targets, then tasks and make sure to use the same names between the input csv-files.
The sample files should serve as examples, however a short explanation of a VCALENDAR stream exported from Greenbone below¹.

```
Example Key:Value pair | Comment
---|---
BEGIN:VCALENDAR | Begin VCalendar Entry
VERSION:2.0 | iCalendar Version number
PRODID:-//Greenbone.net//NONSGML Greenbone Security Manager 23.1.0//EN | As generated by Greenbone replace with something else if you want to
BEGIN:VEVENT | Start of Vevent
DTSTART:20231125T220000Z | Start date
DURATION:PT1H | Duration of scan. PT0S means "Entire Operation". S = seconds, M = minutes, H = hours
RRULE:FREQ=HOURLY;INTERVAL=4 | Frequency; Yearly, Monthly, Weekly, Hourly. Optionally Interval withs same unit
DTSTAMP:20231125T212042Z | Date stamp created
END:VEVENT | End Vevent
END:VCALENDAR | End VCalendar Entry
```

¹ See also https://www.rfc-editor.org/rfc/rfc5545.txt Internet Calendaring and Scheduling Core Object Specification (iCalendar)

## `create-credentials-from-csv.gmp.py`

Creates credentials as specified in a csv-file. See credentials.csv for file format/contents.

### Example

`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket create-credentials-from-csv.gmp.py ./credentials.csv`

**Note**: create schedules, then credentials, then targets, then tasks and make sure to use the same names between the input csv-files.
The sample files should serve as an example.

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

## `empty-trash.gmp.py`

- Does what is says on the tin, empties the trashcan in Greenbone.
- Use it when you're testing like crazy and have a trashcan with ~ a gazillion objects
- You can also just use `gvm-cli --gmp-username *admin-user* --gmp-password *password* socket --pretty --xml "<empty_trashcan/>"`

## `export-csv-report.gmp.py`

Requests the report specified and exports it as a csv formatted report locally.

### Example
`$ gvm-script --gmp-username *admin-user* --gmp-password *password* socket export-csv-report.gmp.py *report_uuid* ./output.csv`

- Get the *report_uuid* from the UI or a native read such as `tools/turbovasctl native-api-request --json --path '/api/v1/reports?page_size=25'`. If the output is not specified it will be named *report_uuid.csv*
- Note the only changes to this script is an added ignore_pagination=True, details=True to get the full report.

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
