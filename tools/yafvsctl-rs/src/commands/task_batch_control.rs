// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded, sequential bulk task controls.  This deliberately keeps planning
//! separate from mutation: a failed task snapshot can never cause a POST.

use super::common::{compact_finding, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const PAGE_SIZE: u64 = 500;
const MAX_PAGES: u64 = 1000;
const MAX_CSV_BYTES: usize = 1024 * 1024;
const MAX_CSV_ROWS: usize = 4095;
const ACTIVE: [&str; 3] = ["Running", "Requested", "Queued"];

#[derive(Clone, Debug)]
struct CsvRow {
    number: usize,
    name: String,
}

struct ApiReply {
    output: ProcessOutput,
    parsed: Option<Value>,
    http_status: Option<i64>,
    oversized: bool,
    config: Finding,
}

trait BatchApi {
    fn call(
        &self,
        root: &Path,
        path: &str,
        method: &str,
        config_check: &str,
        token_check: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>>;
}

struct GuardedApi;

impl BatchApi for GuardedApi {
    fn call(
        &self,
        root: &Path,
        path: &str,
        method: &str,
        config_check: &str,
        token_check: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>> {
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            None,
            config_check,
            token_check,
            runner,
        )
        .map(reply_from_guarded)
    }
}

fn reply_from_guarded(call: GuardedDirectApiCall) -> ApiReply {
    ApiReply {
        output: call.output,
        parsed: call.parsed,
        http_status: call.http_status,
        oversized: call.oversized,
        config: call.config,
    }
}

pub fn command_native_start_tasks_from_csv(
    root: &Path,
    csv: &Path,
    allow: bool,
    status_only: bool,
) -> ResultEnvelope {
    let rows = match load_rows(csv) {
        Ok(rows) => rows,
        Err(error) => return csv_failure(root, start_command(), csv, error, status_only),
    };
    run_start(
        root,
        csv,
        rows,
        allow,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
    )
}

pub fn command_native_stop_tasks_from_csv(
    root: &Path,
    csv: &Path,
    allow: bool,
    status_only: bool,
) -> ResultEnvelope {
    let rows = match load_rows(csv) {
        Ok(rows) => rows,
        Err(error) => return csv_failure(root, stop_csv_command(), csv, error, status_only),
    };
    run_stop(
        root,
        stop_csv_command(),
        Some(csv),
        Some(rows),
        StopOptions { allow, status_only },
        &SystemCommandRunner,
        &GuardedApi,
    )
}

pub fn command_native_stop_all_tasks(
    root: &Path,
    allow: bool,
    status_only: bool,
) -> ResultEnvelope {
    run_stop(
        root,
        stop_all_command(),
        None,
        None,
        StopOptions { allow, status_only },
        &SystemCommandRunner,
        &GuardedApi,
    )
}

const fn start_command() -> &'static str {
    "native-start-tasks-from-csv"
}
const fn stop_csv_command() -> &'static str {
    "native-stop-tasks-from-csv"
}
const fn stop_all_command() -> &'static str {
    "native-stop-all-tasks"
}

fn envelope(
    root: &Path,
    command: &str,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
) -> ResultEnvelope {
    make_result(metadata(root, command, runner), summary.into(), findings).with_details(details)
}

fn start_details(csv: &Path, row_count: usize) -> Value {
    json!({"csv_file":csv,"row_count":row_count,"task_count":0,"matched_count":0,
        "skipped_count":0,"started_count":0,"failure_count":0,"rows":[]})
}

fn stop_details(csv: Option<&Path>, row_count: usize) -> Value {
    let mut details = json!({"mode":if csv.is_some() {"csv"} else {"all-active"},
        "row_count":row_count,"task_count":0,"matched_count":0,"selected_count":0,
        "skipped_count":0,"stopped_count":0,"failure_count":0,"rows":[]});
    if let Some(csv) = csv {
        details["csv_file"] = json!(csv);
    }
    details
}

fn load_rows(path: &Path) -> Result<Vec<CsvRow>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read task CSV file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read task CSV file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("failed to read task CSV file: path is not a regular file".into());
    }
    if metadata.len() > MAX_CSV_BYTES as u64 {
        return Err(format!(
            "failed to read task CSV file: file exceeds the {MAX_CSV_BYTES} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_CSV_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read task CSV file: {error}"))?;
    if input.len() > MAX_CSV_BYTES {
        return Err(format!(
            "failed to read task CSV file: file exceeds the {MAX_CSV_BYTES} byte limit"
        ));
    }
    let mut rows = Vec::new();
    for (index, record) in ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(input.as_slice())
        .records()
        .enumerate()
    {
        let record = record.map_err(|error| format!("failed to read task CSV file: {error}"))?;
        if let Some(name) = record.get(0).map(str::trim).filter(|name| !name.is_empty()) {
            rows.push(CsvRow {
                number: index + 1,
                name: name.to_string(),
            });
            if rows.len() > MAX_CSV_ROWS {
                return Err(format!(
                    "task CSV file must contain at most {MAX_CSV_ROWS} nonempty first-column values"
                ));
            }
        }
    }
    Ok(rows)
}

fn csv_failure(
    root: &Path,
    command: &str,
    csv: &Path,
    error: String,
    status_only: bool,
) -> ResultEnvelope {
    let mut details = if command == start_command() {
        start_details(csv, 0)
    } else {
        stop_details(Some(csv), 0)
    };
    if command != start_command() {
        increment(&mut details, "failure_count");
    }
    finish_status(
        envelope(
            root,
            command,
            &SystemCommandRunner,
            "Native CSV task control rejected before runtime access.",
            vec![
                Finding::new("fail", &format!("{command}.rows"), error)
                    .with_details(json!({"csv_file":csv})),
            ],
            details,
        ),
        command,
        status_only,
    )
}

struct Snapshot {
    tasks: Vec<Value>,
    config: Finding,
}

fn fetch_tasks(
    root: &Path,
    command: &str,
    runner: &dyn CommandRunner,
    api: &dyn BatchApi,
) -> Result<Snapshot, Vec<Finding>> {
    let mut tasks = Vec::new();
    let mut page_number = 1_u64;
    let mut config = None;
    for _ in 0..MAX_PAGES {
        let path = format!("/api/v1/tasks?page={page_number}&page_size={PAGE_SIZE}&sort=name");
        let call = match api.call(
            root,
            &path,
            "GET",
            &format!("{command}.direct-config-shape"),
            &format!("{command}.direct-token-strength"),
            runner,
        ) {
            Ok(call) => call,
            Err(mut findings) => {
                findings.push(task_read_failure(
                    command,
                    &path,
                    None,
                    "Direct native API task lookup was rejected; no task mutations were attempted.",
                ));
                return Err(findings);
            }
        };
        if config.is_none() {
            config = Some(call.config);
        }
        let object = call.parsed.as_ref().and_then(Value::as_object);
        let items = object
            .and_then(|object| object.get("items"))
            .and_then(Value::as_array);
        if call.oversized
            || !call.output.success
            || call.http_status != Some(200)
            || items.is_none()
        {
            return Err(vec![
                config.expect("config retained after guarded call"),
                task_read_failure(
                    command,
                    &path,
                    call.http_status,
                    "Native task list lookup failed; no task mutations were attempted.",
                ),
            ]);
        }
        let items = items.expect("checked above");
        tasks.extend(items.iter().filter(|item| item.is_object()).cloned());
        let page = object
            .and_then(|object| object.get("page"))
            .and_then(Value::as_object);
        let total = page
            .and_then(|page| page.get("total"))
            .and_then(Value::as_i64)
            .unwrap_or(items.len() as i64);
        let actual = page
            .and_then(|page| page.get("page"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let size = page
            .and_then(|page| page.get("page_size"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let actual = if actual == 0 {
            page_number
        } else {
            u64::try_from(actual).map_err(|_| pagination_failure(command, config.take()))?
        };
        if actual > MAX_PAGES {
            return Err(pagination_failure(command, config.take()));
        }
        let size = if size == 0 {
            PAGE_SIZE
        } else {
            u64::try_from(size).map_err(|_| pagination_failure(command, config.take()))?
        };
        let total = u64::try_from(total).map_err(|_| pagination_failure(command, config.take()))?;
        let consumed = actual
            .checked_mul(size)
            .ok_or_else(|| pagination_failure(command, config.take()))?;
        if items.is_empty() || consumed >= total {
            return Ok(Snapshot {
                tasks,
                config: config.expect("config retained"),
            });
        }
        page_number = actual
            .checked_add(1)
            .ok_or_else(|| pagination_failure(command, config.take()))?;
        if page_number > MAX_PAGES {
            return Err(pagination_failure(command, config.take()));
        }
    }
    Err(pagination_failure(command, config))
}

fn task_read_failure(
    command: &str,
    path: &str,
    http_status: Option<i64>,
    message: &str,
) -> Finding {
    let mut details = json!({"path":path});
    if let Some(status) = bounded_http_status(http_status) {
        details["http_status"] = json!(status);
    }
    Finding::new("fail", &format!("{command}.task-read"), message.into()).with_details(details)
}

fn pagination_failure(command: &str, config: Option<Finding>) -> Vec<Finding> {
    let mut findings = config.into_iter().collect::<Vec<_>>();
    findings.push(Finding::new("fail", &format!("{command}.task-read"), "Native task list pagination was invalid or exceeded the safety limit; no task mutations were attempted.".into()));
    findings
}

fn run_start(
    root: &Path,
    csv: &Path,
    rows: Vec<CsvRow>,
    allow: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn BatchApi,
) -> ResultEnvelope {
    let command = start_command();
    let mut details = start_details(csv, rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{command}.rows"),
        format!("Loaded {} non-empty CSV row(s).", rows.len()),
    )];
    if !allow {
        findings.push(Finding::new("fail", &format!("{command}.write-control-intent"), "Starting tasks requires --allow-write-control because it creates reports and queues scanner execution.".into()));
        return finish_status(
            envelope(
                root,
                command,
                runner,
                "Native CSV task start rejected before runtime access.",
                findings,
                details,
            ),
            command,
            status_only,
        );
    }
    if rows.is_empty() {
        return finish_status(
            envelope(
                root,
                command,
                runner,
                "Native CSV task start completed; no task rows were supplied.",
                findings,
                details,
            ),
            command,
            status_only,
        );
    }
    let snapshot = match fetch_tasks(root, command, runner, api) {
        Ok(snapshot) => snapshot,
        Err(findings) => {
            return finish_status(
                envelope(
                    root,
                    command,
                    runner,
                    "Native CSV task start failed during task lookup.",
                    findings,
                    details,
                ),
                command,
                status_only,
            );
        }
    };
    details["task_count"] = json!(snapshot.tasks.len());
    findings.push(snapshot.config);
    findings.push(Finding::new(
        "pass",
        &format!("{command}.task-read"),
        format!(
            "Read {} task(s) through the native API.",
            snapshot.tasks.len()
        ),
    ));
    let mut planned = Vec::new();
    let mut ids = HashSet::new();
    for row in &rows {
        let matches: Vec<&Value> = snapshot
            .tasks
            .iter()
            .filter(|task| task_name(task) == Some(row.name.as_str()))
            .collect();
        if !matches.is_empty() {
            increment(&mut details, "matched_count");
        }
        let eligible: Vec<&Value> = matches
            .iter()
            .copied()
            .filter(|task| !is_active(task))
            .collect();
        if eligible.is_empty() {
            let reason = if matches.is_empty() {
                "task name not found"
            } else {
                "active task status"
            };
            add_row(
                &mut details,
                RowFields {
                    row: Some(row),
                    id: None,
                    status: "skipped",
                    reason,
                    http_status: None,
                    task_status: None,
                    report_id: None,
                    name: None,
                    extra: Map::new(),
                },
            );
            increment(&mut details, "skipped_count");
            findings.push(Finding::new(
                "warn",
                &format!("{command}.row.{}", row.number),
                format!("Skipped task {}: {reason}.", row.name),
            ));
            continue;
        }
        let task = eligible.last().expect("non-empty eligible");
        let id = task_id(task).unwrap_or_default();
        if validate_operator_uuid(id, "task_id").is_err() {
            add_row(
                &mut details,
                RowFields {
                    row: Some(row),
                    id: None,
                    status: "failed",
                    reason: "task list row did not contain a valid UUID",
                    http_status: None,
                    task_status: None,
                    report_id: None,
                    name: None,
                    extra: Map::new(),
                },
            );
            increment(&mut details, "failure_count");
            findings.push(Finding::new(
                "fail",
                &format!("{command}.row.{}", row.number),
                format!(
                    "Task {} could not be started: task list row did not contain a valid UUID.",
                    row.name
                ),
            ));
        } else if !ids.insert(id.to_string()) {
            add_row(
                &mut details,
                RowFields {
                    row: Some(row),
                    id: Some(id),
                    status: "skipped",
                    reason: "duplicate task row",
                    http_status: None,
                    task_status: None,
                    report_id: None,
                    name: None,
                    extra: Map::new(),
                },
            );
            increment(&mut details, "skipped_count");
            findings.push(Finding::new(
                "warn",
                &format!("{command}.row.{}", row.number),
                format!("Skipped duplicate task row for {}.", row.name),
            ));
        } else {
            planned.push((row.clone(), id.to_string()));
        }
    }
    for (row, id) in planned {
        let outcome = mutation(api, root, command, &id, "start", runner);
        let accepted = outcome.accepted_start(&id);
        let reason = if accepted {
            ""
        } else {
            outcome.reason("Native API task start failed or returned an invalid acknowledgement.")
        };
        add_row(
            &mut details,
            RowFields {
                row: Some(&row),
                id: Some(&id),
                status: if accepted { "started" } else { "failed" },
                reason,
                http_status: outcome.http_status(),
                task_status: outcome.task_status(),
                report_id: outcome.report_id(),
                name: None,
                extra: Map::new(),
            },
        );
        increment(
            &mut details,
            if accepted {
                "started_count"
            } else {
                "failure_count"
            },
        );
        findings.push(Finding::new(
            if accepted { "pass" } else { "fail" },
            &format!("{command}.row.{}", row.number),
            if accepted {
                format!("Native API accepted start for task {}.", row.name)
            } else {
                format!("Native API start failed for task {}: {reason}", row.name)
            },
        ));
    }
    let failed = count(&details, "failure_count") > 0;
    finish_status(
        envelope(
            root,
            command,
            runner,
            if failed {
                "Native CSV task start failed."
            } else {
                "Native CSV task start completed."
            },
            findings,
            details,
        ),
        command,
        status_only,
    )
}

struct StopOptions {
    allow: bool,
    status_only: bool,
}

fn run_stop(
    root: &Path,
    command: &str,
    csv: Option<&Path>,
    rows: Option<Vec<CsvRow>>,
    options: StopOptions,
    runner: &dyn CommandRunner,
    api: &dyn BatchApi,
) -> ResultEnvelope {
    let StopOptions { allow, status_only } = options;
    let mut details = stop_details(csv, rows.as_ref().map_or(0, Vec::len));
    if !allow {
        return finish_status(envelope(root, command, runner, "Native bulk task stop rejected before runtime access.", vec![Finding::new("fail", &format!("{command}.write-control-intent"), "Stopping tasks requires --allow-write-control because it controls scanner task execution.".into())], details), command, status_only);
    }
    if rows.as_ref().is_some_and(Vec::is_empty) {
        return finish_status(
            envelope(
                root,
                command,
                runner,
                "Native bulk task stop completed; no task rows were supplied.",
                vec![Finding::new(
                    "pass",
                    &format!("{command}.rows"),
                    "The CSV contains no non-empty task names.".into(),
                )],
                details,
            ),
            command,
            status_only,
        );
    }
    let snapshot = match fetch_tasks(root, command, runner, api) {
        Ok(snapshot) => snapshot,
        Err(findings) => {
            return finish_status(
                envelope(
                    root,
                    command,
                    runner,
                    "Native bulk task stop failed during task lookup.",
                    findings,
                    details,
                ),
                command,
                status_only,
            );
        }
    };
    details["task_count"] = json!(snapshot.tasks.len());
    let mut findings = vec![
        snapshot.config,
        Finding::new(
            "pass",
            &format!("{command}.task-read"),
            format!(
                "Snapshotted {} task(s) through the native API before any stop.",
                snapshot.tasks.len()
            ),
        ),
    ];
    let all_mode = rows.is_none();
    let mut candidates: Vec<(Option<CsvRow>, Value)> = Vec::new();
    if let Some(rows) = rows {
        for row in rows {
            let named: Vec<&Value> = snapshot
                .tasks
                .iter()
                .filter(|task| task_name(task) == Some(row.name.as_str()))
                .collect();
            if !named.is_empty() {
                increment(&mut details, "matched_count");
            }
            let active: Vec<&Value> = named
                .iter()
                .copied()
                .filter(|task| is_active(task))
                .collect();
            if active.len() > 1 {
                increment(&mut details, "failure_count");
                let mut extra = Map::new();
                extra.insert("match_count".into(), json!(active.len()));
                add_row(
                    &mut details,
                    RowFields {
                        row: Some(&row),
                        id: None,
                        status: "failed",
                        reason: "multiple active tasks share this name",
                        http_status: None,
                        task_status: None,
                        report_id: None,
                        name: None,
                        extra,
                    },
                );
                findings.push(Finding::new(
                    "fail",
                    &format!("{command}.row.{}", row.number),
                    format!(
                        "Refused ambiguous task {}: {} active matches.",
                        row.name,
                        active.len()
                    ),
                ));
            } else if let Some(task) = active.first() {
                candidates.push((Some(row), (*task).clone()));
            } else {
                let reason = if named.is_empty() {
                    "task name not found"
                } else {
                    "no active matching task"
                };
                increment(&mut details, "skipped_count");
                add_row(
                    &mut details,
                    RowFields {
                        row: Some(&row),
                        id: None,
                        status: "skipped",
                        reason,
                        http_status: None,
                        task_status: None,
                        report_id: None,
                        name: None,
                        extra: Map::new(),
                    },
                );
                findings.push(Finding::new(
                    "warn",
                    &format!("{command}.row.{}", row.number),
                    format!("Skipped task {}: {reason}.", row.name),
                ));
            }
        }
    } else {
        let mut active: Vec<Value> = snapshot.tasks.into_iter().filter(is_active).collect();
        active.sort_by(|left, right| {
            (task_name(left).unwrap_or(""), task_id(left).unwrap_or(""))
                .cmp(&(task_name(right).unwrap_or(""), task_id(right).unwrap_or("")))
        });
        details["matched_count"] = json!(active.len());
        candidates.extend(active.into_iter().map(|task| (None, task)));
    }
    let mut ids = HashSet::new();
    let mut planned = Vec::new();
    for (index, (row, task)) in candidates.into_iter().enumerate() {
        let id = task_id(&task).unwrap_or_default();
        let name = task_name(&task).unwrap_or("").to_string();
        if validate_operator_uuid(id, "task_id").is_err() {
            increment(&mut details, "failure_count");
            add_row(
                &mut details,
                RowFields {
                    row: row.as_ref(),
                    id: None,
                    status: "failed",
                    reason: "task list row did not contain a valid UUID",
                    http_status: None,
                    task_status: None,
                    report_id: None,
                    name: Some(&name),
                    extra: Map::new(),
                },
            );
            let check = if all_mode {
                format!("{command}.task.invalid.{}", index + 1)
            } else {
                format!("{command}.row.{}", row.as_ref().expect("csv row").number)
            };
            findings.push(Finding::new(
                "fail",
                &check,
                "Task list row did not contain a valid UUID; stop refused.".into(),
            ));
        } else if !ids.insert(id.to_string()) {
            increment(&mut details, "skipped_count");
            add_row(
                &mut details,
                RowFields {
                    row: row.as_ref(),
                    id: Some(id),
                    status: "skipped",
                    reason: "duplicate task UUID",
                    http_status: None,
                    task_status: None,
                    report_id: None,
                    name: Some(&name),
                    extra: Map::new(),
                },
            );
            let check = if all_mode {
                format!("{command}.task.{id}")
            } else {
                format!("{command}.row.{}", row.as_ref().expect("csv row").number)
            };
            findings.push(Finding::new(
                "warn",
                &check,
                "Skipped duplicate task UUID.".into(),
            ));
        } else {
            planned.push((row, name, id.to_string()));
        }
    }
    details["selected_count"] = json!(planned.len());
    for (row, name, id) in planned {
        let outcome = mutation(api, root, command, &id, "stop", runner);
        let accepted = outcome.accepted_stop(&id);
        let reason = if accepted {
            ""
        } else {
            outcome.reason("Native API task stop failed or returned an invalid acknowledgement.")
        };
        add_row(
            &mut details,
            RowFields {
                row: row.as_ref(),
                id: Some(&id),
                status: if accepted { "stopped" } else { "failed" },
                reason,
                http_status: outcome.http_status(),
                task_status: outcome.task_status(),
                report_id: None,
                name: Some(&name),
                extra: Map::new(),
            },
        );
        increment(
            &mut details,
            if accepted {
                "stopped_count"
            } else {
                "failure_count"
            },
        );
        let check = if all_mode {
            format!("{command}.task.{id}")
        } else {
            format!("{command}.row.{}", row.as_ref().expect("csv row").number)
        };
        findings.push(Finding::new(
            if accepted { "pass" } else { "fail" },
            &check,
            if accepted {
                format!("Native API verified stop for task {name}.")
            } else {
                format!("Native API stop failed for task {name}: {reason}")
            },
        ));
    }
    let failed = count(&details, "failure_count") > 0;
    finish_status(
        envelope(
            root,
            command,
            runner,
            if failed {
                "Native bulk task stop completed with failures."
            } else {
                "Native bulk task stop completed."
            },
            findings,
            details,
        ),
        command,
        status_only,
    )
}

enum GuardedRejection {
    Configuration,
    TokenValidation,
    Other,
}

struct Mutation {
    call: Option<ApiReply>,
    guarded: Option<GuardedRejection>,
}

fn mutation(
    api: &dyn BatchApi,
    root: &Path,
    command: &str,
    id: &str,
    action: &str,
    runner: &dyn CommandRunner,
) -> Mutation {
    let path = format!("/api/v1/tasks/{id}/{action}");
    match api.call(
        root,
        &path,
        "POST",
        &format!("{command}.direct-config-shape"),
        &format!("{command}.direct-token-strength"),
        runner,
    ) {
        Ok(call) => Mutation {
            call: Some(call),
            guarded: None,
        },
        Err(findings) => Mutation {
            call: None,
            guarded: Some(classify_guarded_rejection(&findings)),
        },
    }
}

fn classify_guarded_rejection(findings: &[Finding]) -> GuardedRejection {
    if findings
        .iter()
        .any(|finding| finding.check.ends_with(".direct-token-strength"))
    {
        GuardedRejection::TokenValidation
    } else if findings
        .iter()
        .any(|finding| finding.check.ends_with(".direct-config-shape"))
    {
        GuardedRejection::Configuration
    } else {
        GuardedRejection::Other
    }
}

impl Mutation {
    fn accepted_start(&self, id: &str) -> bool {
        self.call
            .as_ref()
            .is_some_and(|call| accepted(call, id, true))
    }
    fn accepted_stop(&self, id: &str) -> bool {
        self.call
            .as_ref()
            .is_some_and(|call| accepted(call, id, false))
    }
    fn reason(&self, fallback: &'static str) -> &'static str {
        if let Some(rejection) = &self.guarded {
            match rejection {
                GuardedRejection::Configuration => "guarded direct API configuration was rejected",
                GuardedRejection::TokenValidation => {
                    "guarded direct API token validation rejected the request"
                }
                GuardedRejection::Other => "guarded direct API call was rejected",
            }
        } else {
            fallback
        }
    }
    fn http_status(&self) -> Option<i64> {
        self.call
            .as_ref()
            .and_then(|call| bounded_http_status(call.http_status))
    }
    fn task_status(&self) -> Option<String> {
        self.call
            .as_ref()
            .and_then(|call| call.parsed.as_ref())
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            .and_then(bounded_text)
    }
    fn report_id(&self) -> Option<String> {
        self.call
            .as_ref()
            .and_then(|call| call.parsed.as_ref())
            .and_then(|value| value.get("report_id"))
            .and_then(Value::as_str)
            .and_then(|report_id| validate_operator_uuid(report_id, "report_id").ok())
    }
}

fn accepted(call: &ApiReply, id: &str, start: bool) -> bool {
    let object = call.parsed.as_ref().and_then(Value::as_object);
    !call.oversized
        && call.output.success
        && object.is_some_and(|object| object.get("task_id").and_then(Value::as_str) == Some(id))
        && if start {
            call.http_status == Some(202)
                && object.is_some_and(|object| {
                    object.get("status").and_then(Value::as_str) == Some("requested")
                        && object.get("report_id").and_then(Value::as_str).is_some_and(
                            |report_id| validate_operator_uuid(report_id, "report_id").is_ok(),
                        )
                })
        } else {
            call.http_status == Some(200)
                && object.is_some_and(|object| {
                    object.get("status").and_then(Value::as_str) == Some("stopped")
                })
        }
}

fn task_name(task: &Value) -> Option<&str> {
    task.get("name").and_then(Value::as_str)
}
fn task_id(task: &Value) -> Option<&str> {
    task.get("id").and_then(Value::as_str)
}
fn is_active(task: &Value) -> bool {
    ACTIVE.contains(&task.get("status").and_then(Value::as_str).unwrap_or(""))
}
fn bounded_http_status(status: Option<i64>) -> Option<i64> {
    status.filter(|status| (0..=999).contains(status))
}
fn bounded_text(value: &str) -> Option<String> {
    (value.len() <= 256 && !value.chars().any(char::is_control)).then(|| value.to_string())
}
fn count(details: &Value, key: &str) -> u64 {
    details.get(key).and_then(Value::as_u64).unwrap_or(0)
}
fn increment(details: &mut Value, key: &str) {
    details[key] = json!(count(details, key) + 1);
}

struct RowFields<'a> {
    row: Option<&'a CsvRow>,
    id: Option<&'a str>,
    status: &'a str,
    reason: &'a str,
    http_status: Option<i64>,
    task_status: Option<String>,
    report_id: Option<String>,
    name: Option<&'a str>,
    extra: Map<String, Value>,
}

fn add_row(details: &mut Value, fields: RowFields<'_>) {
    let RowFields {
        row,
        id,
        status,
        reason,
        http_status,
        task_status,
        report_id,
        name,
        mut extra,
    } = fields;
    if let Some(report_id) = report_id {
        extra.insert("report_id".into(), json!(report_id));
    }
    let mut value = Map::new();
    if let Some(row) = row {
        value.insert("row".into(), json!(row.number));
        value.insert("task_name".into(), json!(row.name));
    } else if let Some(name) = name {
        value.insert("task_name".into(), json!(name));
    }
    value.insert("status".into(), json!(status));
    if let Some(id) = id {
        value.insert("task_id".into(), json!(id));
    }
    if !reason.is_empty() {
        value.insert("reason".into(), json!(reason));
    }
    if let Some(http_status) = bounded_http_status(http_status) {
        value.insert("http_status".into(), json!(http_status));
    }
    if let Some(task_status) = task_status {
        value.insert("task_status".into(), json!(task_status));
    }
    for (key, value_item) in extra {
        value.insert(key, value_item);
    }
    details["rows"]
        .as_array_mut()
        .expect("details rows is an array")
        .push(Value::Object(value));
}

fn finish_status(mut result: ResultEnvelope, command: &str, status_only: bool) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    result.findings = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect();
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{command}.status-only"),
            "Native bulk task control passed; row details summarized.".into(),
        ));
    }
    let details = result.details.take().unwrap_or_else(|| json!({}));
    let keys: &[&str] = if command == start_command() {
        &[
            "csv_file",
            "row_count",
            "task_count",
            "matched_count",
            "skipped_count",
            "started_count",
            "failure_count",
        ]
    } else if command == stop_csv_command() {
        &[
            "mode",
            "csv_file",
            "row_count",
            "task_count",
            "matched_count",
            "selected_count",
            "skipped_count",
            "stopped_count",
            "failure_count",
        ]
    } else {
        &[
            "mode",
            "row_count",
            "task_count",
            "matched_count",
            "selected_count",
            "skipped_count",
            "stopped_count",
            "failure_count",
        ]
    };
    let compact = keys
        .iter()
        .filter_map(|key| {
            details
                .get(*key)
                .map(|value| ((*key).to_string(), value.clone()))
        })
        .collect();
    result.details = Some(Value::Object(compact));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    const C: &str = "33333333-3333-4333-8333-333333333333";
    const TOKEN: &str = "TOKEN-SENTINEL-MUST-NOT-APPEAR-IN-RESULT";
    #[derive(Default)]
    struct Runner;
    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }
    }
    struct Fake {
        replies: Mutex<VecDeque<Result<ApiReply, Vec<Finding>>>>,
        calls: Mutex<Vec<String>>,
    }
    impl Fake {
        fn new(replies: Vec<Result<ApiReply, Vec<Finding>>>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }
    impl BatchApi for Fake {
        fn call(
            &self,
            _: &Path,
            path: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &dyn CommandRunner,
        ) -> Result<ApiReply, Vec<Finding>> {
            self.calls.lock().unwrap().push(path.into());
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted response")
        }
    }
    fn reply(status: i64, body: Value) -> Result<ApiReply, Vec<Finding>> {
        Ok(ApiReply {
            output: ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            },
            parsed: Some(body),
            http_status: Some(status),
            oversized: false,
            config: Finding::new("pass", "config", "safe".into()),
        })
    }
    fn rejected() -> Result<ApiReply, Vec<Finding>> {
        Err(vec![Finding::new(
            "fail",
            "x.direct-token-strength",
            "bad".into(),
        )])
    }
    fn task(id: &str, name: &str, status: &str) -> Value {
        json!({"id":id,"name":name,"status":status})
    }
    fn list(items: Vec<Value>, page: i64, total: i64) -> Value {
        json!({"items":items,"page":{"page":page,"page_size":500,"total":total}})
    }
    fn csv(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "yafvs-task-batch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }
    fn root() -> &'static Path {
        Path::new("/tmp/yafvs-task-batch")
    }
    fn rows(result: &ResultEnvelope) -> &Vec<Value> {
        result
            .details
            .as_ref()
            .unwrap()
            .get("rows")
            .unwrap()
            .as_array()
            .unwrap()
    }

    #[test]
    fn csv_hardening_rejects_before_runtime() {
        let missing = Path::new("/tmp/yafvs-no-such-batch-csv");
        assert!(load_rows(missing).is_err());
        let target = csv("x\n");
        let link = target.with_extension("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(load_rows(&link).is_err());
        let directory = std::env::temp_dir();
        assert!(load_rows(&directory).is_err());
        let huge = csv(&"a".repeat(MAX_CSV_BYTES + 1));
        assert!(load_rows(&huge).is_err());
        for path in [&target, &link, &huge] {
            let _ = std::fs::remove_file(path);
        }
    }
    #[test]
    fn refusals_and_empty_csv_make_no_runtime_calls() {
        let path = csv("name\n");
        for command in [start_command(), stop_csv_command(), stop_all_command()] {
            let fake = Fake::new(vec![]);
            let runner = Runner;
            let result = if command == start_command() {
                run_start(
                    root(),
                    &path,
                    load_rows(&path).unwrap(),
                    false,
                    false,
                    &runner,
                    &fake,
                )
            } else {
                run_stop(
                    root(),
                    command,
                    (command == stop_csv_command()).then_some(path.as_path()),
                    (command == stop_csv_command()).then(|| load_rows(&path).unwrap()),
                    StopOptions {
                        allow: false,
                        status_only: false,
                    },
                    &runner,
                    &fake,
                )
            };
            assert!(
                result
                    .findings
                    .iter()
                    .any(|f| f.check == format!("{command}.write-control-intent"))
            );
            assert!(fake.calls.lock().unwrap().is_empty());
        }
        let empty = csv("\n,ignored\n");
        for command in [start_command(), stop_csv_command()] {
            let fake = Fake::new(vec![]);
            let runner = Runner;
            let result = if command == start_command() {
                run_start(
                    root(),
                    &empty,
                    load_rows(&empty).unwrap(),
                    true,
                    false,
                    &runner,
                    &fake,
                )
            } else {
                run_stop(
                    root(),
                    command,
                    Some(&empty),
                    Some(load_rows(&empty).unwrap()),
                    StopOptions {
                        allow: true,
                        status_only: false,
                    },
                    &runner,
                    &fake,
                )
            };
            assert_eq!(result.status, "pass");
            assert!(fake.calls.lock().unwrap().is_empty());
        }
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(empty);
    }
    #[test]
    fn start_characterizes_pages_selection_and_failures() {
        let path = csv("one\ntwo\nrun\nreq\nqueue\nmissing\none\n");
        let fake = Fake::new(vec![
            reply(
                200,
                list(
                    vec![
                        task(A, "two", "Ready"),
                        task(B, "one", "Failed"),
                        task(C, "run", "Running"),
                    ],
                    1,
                    1500,
                ),
            ),
            reply(
                200,
                list(
                    vec![
                        task("44444444-4444-4444-8444-444444444444", "req", "Requested"),
                        task("55555555-5555-4555-8555-555555555555", "queue", "Queued"),
                    ],
                    2,
                    1500,
                ),
            ),
            reply(200, list(vec![], 3, 1500)),
            reply(202, json!({"task_id":B,"report_id":C,"status":"requested"})),
            reply(503, json!({"task_id":A,"status":"failed"})),
        ]);
        let runner = Runner;
        let result = run_start(
            root(),
            &path,
            load_rows(&path).unwrap(),
            true,
            false,
            &runner,
            &fake,
        );
        assert_eq!(result.details.as_ref().unwrap()["task_count"], 5);
        assert_eq!(result.details.as_ref().unwrap()["matched_count"], 6);
        assert_eq!(result.details.as_ref().unwrap()["skipped_count"], 5);
        assert_eq!(result.details.as_ref().unwrap()["started_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["failure_count"], 1);
        assert_eq!(
            rows(&result),
            &vec![
                json!({"row":3,"task_name":"run","status":"skipped","reason":"active task status"}),
                json!({"row":4,"task_name":"req","status":"skipped","reason":"active task status"}),
                json!({"row":5,"task_name":"queue","status":"skipped","reason":"active task status"}),
                json!({"row":6,"task_name":"missing","status":"skipped","reason":"task name not found"}),
                json!({"row":7,"task_name":"one","status":"skipped","task_id":B,"reason":"duplicate task row"}),
                json!({"row":1,"task_name":"one","status":"started","task_id":B,"http_status":202,"task_status":"requested","report_id":C}),
                json!({"row":2,"task_name":"two","status":"failed","task_id":A,"reason":"Native API task start failed or returned an invalid acknowledgement.","http_status":503,"task_status":"failed"}),
            ]
        );
        assert_eq!(
            fake.calls.lock().unwrap().as_slice(),
            [
                "/api/v1/tasks?page=1&page_size=500&sort=name",
                "/api/v1/tasks?page=2&page_size=500&sort=name",
                "/api/v1/tasks?page=3&page_size=500&sort=name",
                &format!("/api/v1/tasks/{B}/start"),
                &format!("/api/v1/tasks/{A}/start")
            ]
        );
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn stop_csv_has_ambiguity_details_and_keeps_token_out() {
        let path = csv("Alpha\nBeta\nAlpha\nIdle\nMissing\nAmb\n");
        let fake = Fake::new(vec![
            reply(
                200,
                list(
                    vec![
                        task(A, "Alpha", "Running"),
                        task(B, "Beta", "Queued"),
                        task(C, "Idle", "Done"),
                    ],
                    1,
                    1000,
                ),
            ),
            reply(
                200,
                list(
                    vec![
                        task("44444444-4444-4444-8444-444444444444", "Amb", "Running"),
                        task("55555555-5555-4555-8555-555555555555", "Amb", "Requested"),
                    ],
                    2,
                    1000,
                ),
            ),
            reply(200, json!({"task_id":A,"status":"stopped"})),
            reply(502, json!({"task_id":B,"status":"failed","token":TOKEN})),
        ]);
        let runner = Runner;
        let result = run_stop(
            root(),
            stop_csv_command(),
            Some(&path),
            Some(load_rows(&path).unwrap()),
            StopOptions {
                allow: true,
                status_only: false,
            },
            &runner,
            &fake,
        );
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["matched_count"], 5);
        assert_eq!(details["selected_count"], 2);
        assert_eq!(details["skipped_count"], 3);
        assert_eq!(details["stopped_count"], 1);
        assert_eq!(details["failure_count"], 2);
        assert_eq!(
            rows(&result),
            &vec![
                json!({"row":4,"task_name":"Idle","status":"skipped","reason":"no active matching task"}),
                json!({"row":5,"task_name":"Missing","status":"skipped","reason":"task name not found"}),
                json!({"row":6,"task_name":"Amb","status":"failed","reason":"multiple active tasks share this name","match_count":2}),
                json!({"row":3,"task_name":"Alpha","status":"skipped","task_id":A,"reason":"duplicate task UUID"}),
                json!({"row":1,"task_name":"Alpha","status":"stopped","task_id":A,"http_status":200,"task_status":"stopped"}),
                json!({"row":2,"task_name":"Beta","status":"failed","task_id":B,"reason":"Native API task stop failed or returned an invalid acknowledgement.","http_status":502,"task_status":"failed"}),
            ]
        );
        assert_eq!(
            fake.calls.lock().unwrap().as_slice(),
            [
                "/api/v1/tasks?page=1&page_size=500&sort=name",
                "/api/v1/tasks?page=2&page_size=500&sort=name",
                &format!("/api/v1/tasks/{A}/stop"),
                &format!("/api/v1/tasks/{B}/stop"),
            ]
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(TOKEN));
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn stop_all_orders_deduplicates_and_status_only_compacts_details() {
        let full = Fake::new(vec![
            reply(
                200,
                list(
                    vec![
                        task(B, "Alpha", "Running"),
                        task(A, "Beta", "Requested"),
                        task(A, "Beta", "Queued"),
                        task("bad", "Zero", "Queued"),
                        task(C, "Idle", "Done"),
                    ],
                    1,
                    5,
                ),
            ),
            reply(500, json!({"task_id":B,"status":"failed"})),
            reply(200, json!({"task_id":A,"status":"stopped"})),
        ]);
        let runner = Runner;
        let full_result = run_stop(
            root(),
            stop_all_command(),
            None,
            None,
            StopOptions {
                allow: true,
                status_only: false,
            },
            &runner,
            &full,
        );
        assert_eq!(full_result.details.as_ref().unwrap()["failure_count"], 2);
        assert_eq!(full_result.details.as_ref().unwrap()["stopped_count"], 1);
        assert!(
            rows(&full_result)
                .iter()
                .all(|row| row.get("row").is_none())
        );
        assert_eq!(
            full.calls.lock().unwrap().as_slice(),
            [
                "/api/v1/tasks?page=1&page_size=500&sort=name",
                &format!("/api/v1/tasks/{B}/stop"),
                &format!("/api/v1/tasks/{A}/stop"),
            ]
        );
        let duplicate = task(A, "Beta", "Queued");
        let fake = Fake::new(vec![
            reply(
                200,
                list(
                    vec![
                        task(B, "Alpha", "Running"),
                        task(A, "Beta", "Requested"),
                        duplicate,
                        task("bad", "Zero", "Queued"),
                        task(C, "Idle", "Done"),
                    ],
                    1,
                    5,
                ),
            ),
            reply(500, json!({"task_id":B,"status":"failed"})),
            reply(200, json!({"task_id":A,"status":"stopped"})),
        ]);
        let result = run_stop(
            root(),
            stop_all_command(),
            None,
            None,
            StopOptions {
                allow: true,
                status_only: true,
            },
            &runner,
            &fake,
        );
        let details = result.details.unwrap();
        assert_eq!(
            details,
            json!({"mode":"all-active","row_count":0,"task_count":5,"matched_count":4,"selected_count":2,"skipped_count":1,"stopped_count":1,"failure_count":2})
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.status != "pass")
                || result.findings.len() == 1
        );
        assert_eq!(
            fake.calls.lock().unwrap().as_slice(),
            [
                "/api/v1/tasks?page=1&page_size=500&sort=name",
                &format!("/api/v1/tasks/{B}/stop"),
                &format!("/api/v1/tasks/{A}/stop")
            ]
        );
    }
    #[test]
    fn list_failure_does_not_post_and_invalid_rows_and_acknowledgements_fail() {
        let path = csv("bad\n");
        let fake = Fake::new(vec![reply(500, json!({"items":[]}))]);
        let runner = Runner;
        let result = run_start(
            root(),
            &path,
            load_rows(&path).unwrap(),
            true,
            false,
            &runner,
            &fake,
        );
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
        assert_eq!(result.status, "fail");
        let fake = Fake::new(vec![
            reply(
                200,
                list(
                    vec![task("not-a-uuid", "bad", "Ready"), task(A, "ok", "Ready")],
                    1,
                    2,
                ),
            ),
            reply(
                202,
                json!({"task_id":A,"report_id":"not-a-uuid","status":"requested"}),
            ),
        ]);
        let path2 = csv("bad\nok\n");
        let result = run_start(
            root(),
            &path2,
            load_rows(&path2).unwrap(),
            true,
            false,
            &runner,
            &fake,
        );
        assert_eq!(result.details.as_ref().unwrap()["failure_count"], 2);
        assert_eq!(rows(&result)[1]["status"], "failed");
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path2);
    }
    #[test]
    fn pagination_fallbacks_remain_bounded_and_invalid_totals_do_not_post() {
        let path = csv("a\n");
        let runner = Runner;
        let permissive = Fake::new(vec![
            reply(
                200,
                json!({
                    "items":[task(A, "a", "Ready")],
                    "page":{"page":0,"page_size":0,"total":501}
                }),
            ),
            reply(200, json!({"items":[]})),
            reply(202, json!({"task_id":A,"report_id":C,"status":"requested"})),
        ]);
        let result = run_start(
            root(),
            &path,
            load_rows(&path).unwrap(),
            true,
            false,
            &runner,
            &permissive,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            permissive.calls.lock().unwrap().as_slice(),
            [
                "/api/v1/tasks?page=1&page_size=500&sort=name",
                "/api/v1/tasks?page=2&page_size=500&sort=name",
                &format!("/api/v1/tasks/{A}/start"),
            ]
        );

        let invalid = Fake::new(vec![reply(
            200,
            json!({
                "items":[task(A, "a", "Ready")],
                "page":{"page":1,"page_size":500,"total":-1}
            }),
        )]);
        let result = run_start(
            root(),
            &path,
            load_rows(&path).unwrap(),
            true,
            false,
            &runner,
            &invalid,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(invalid.calls.lock().unwrap().len(), 1);
        assert_eq!(result.details.as_ref().unwrap()["started_count"], 0);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn guarded_mutation_rejection_is_per_row_and_continues() {
        let path = csv("a\nb\n");
        let fake = Fake::new(vec![
            reply(
                200,
                list(vec![task(A, "a", "Ready"), task(B, "b", "Ready")], 1, 2),
            ),
            rejected(),
            reply(202, json!({"task_id":B,"report_id":C,"status":"requested"})),
        ]);
        let runner = Runner;
        let result = run_start(
            root(),
            &path,
            load_rows(&path).unwrap(),
            true,
            false,
            &runner,
            &fake,
        );
        assert_eq!(result.details.as_ref().unwrap()["failure_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["started_count"], 1);
        assert_eq!(
            rows(&result)[0]["reason"],
            "guarded direct API token validation rejected the request"
        );
        let _ = std::fs::remove_file(path);
    }
}
