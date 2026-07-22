// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded CSV task creation with complete native-reference preflight.

use super::{ApiReply, GuardedApi, TargetApi, acknowledged_id};
use crate::commands::common::metadata;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const COMMAND: &str = "native-tasks-from-csv";
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 4095;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_ALERTS: usize = 5;
const PAGE_SIZE: usize = 500;
const MAX_COLLECTION_PAGES: usize = 200;
const MAX_COLLECTION_ITEMS: usize = PAGE_SIZE * MAX_COLLECTION_PAGES;
const MAX_SNAPSHOT_ITEMS: usize = 100_000;
const MAX_API_REQUESTS: usize = 4095;
const MAX_REPORTED: usize = 10;
const MAX_ROW_DETAILS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TaskCsvRow {
    row_number: usize,
    name: String,
    target_name: String,
    scanner_name: String,
    config_name: String,
    schedule_name: String,
    hosts_ordering: String,
    alert_names: Vec<String>,
}

pub fn command_native_tasks_from_csv(
    root: &Path,
    csv_file: &Path,
    allow_write_control: bool,
    status_only: bool,
) -> ResultEnvelope {
    let rows = match load_rows(csv_file) {
        Ok(rows) => rows,
        Err(error) => {
            return finish_status(
                envelope(
                    root,
                    &SystemCommandRunner,
                    "Native CSV task creation rejected before runtime access.",
                    vec![
                        Finding::new("fail", &format!("{COMMAND}.rows"), error)
                            .with_details(json!({"csv_file": csv_file})),
                    ],
                    base_details(csv_file),
                ),
                status_only,
            );
        }
    };
    command_with(
        root,
        csv_file,
        rows,
        allow_write_control,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
    )
}

fn envelope(
    root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
) -> ResultEnvelope {
    make_result(metadata(root, COMMAND, runner), summary.into(), findings).with_details(details)
}

fn base_details(csv_file: &Path) -> Value {
    json!({
        "csv_file": csv_file,
        "row_count": 0,
        "task_count": 0,
        "planned_count": 0,
        "skipped_count": 0,
        "host_ordering_count": 0,
        "created_count": 0,
        "failure_count": 0,
        "rows": [],
    })
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, String> {
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
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(format!(
            "failed to read task CSV file: file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_FILE_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read task CSV file: {error}"))?;
    if input.len() > MAX_FILE_BYTES {
        return Err(format!(
            "failed to read task CSV file: file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    Ok(input)
}

fn load_rows(path: &Path) -> Result<Vec<TaskCsvRow>, String> {
    parse_rows(&read_bounded_file(path)?)
}

fn parse_rows(input: &[u8]) -> Result<Vec<TaskCsvRow>, String> {
    std::str::from_utf8(input).map_err(|_| "failed to read task CSV file: input is not UTF-8")?;
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(input);
    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let row_number = index + 1;
        let record = record.map_err(|error| format!("failed to read task CSV file: {error}"))?;
        if record.is_empty() || record.iter().all(|field| field.trim().is_empty()) {
            continue;
        }
        if !(4..=11).contains(&record.len()) {
            return Err(format!(
                "row {row_number} must contain 4 to 11 columns: task, target, scanner, scan config, optional schedule, legacy host ordering, and up to five alerts"
            ));
        }
        for field in &record {
            if field.len() > MAX_FIELD_BYTES {
                return Err(format!(
                    "row {row_number} fields must be at most {MAX_FIELD_BYTES} bytes"
                ));
            }
            if field.chars().any(is_c0_or_c1) {
                return Err(format!("row {row_number} fields must be printable text"));
            }
        }
        let mut fields = record.iter().map(str::trim).collect::<Vec<_>>();
        fields.resize(11, "");
        if fields[..4].iter().any(|field| field.is_empty()) {
            return Err(format!(
                "row {row_number} must include task, target, scanner, and scan config names"
            ));
        }
        let hosts_ordering = if fields[5].is_empty() {
            "RANDOM".to_string()
        } else {
            fields[5].to_ascii_uppercase()
        };
        if !matches!(hosts_ordering.as_str(), "RANDOM" | "SEQUENTIAL" | "REVERSE") {
            return Err(format!(
                "row {row_number} host ordering must be one of: RANDOM, REVERSE, SEQUENTIAL"
            ));
        }
        rows.push(TaskCsvRow {
            row_number,
            name: fields[0].into(),
            target_name: fields[1].into(),
            scanner_name: fields[2].into(),
            config_name: fields[3].into(),
            schedule_name: fields[4].into(),
            hosts_ordering,
            alert_names: fields[6..]
                .iter()
                .filter(|name| !name.is_empty())
                .map(|name| (*name).to_string())
                .collect(),
        });
        if rows.len() > MAX_ROWS {
            return Err(format!(
                "task CSV file must contain at most {MAX_ROWS} non-empty rows"
            ));
        }
    }
    if rows.is_empty() {
        Err("task CSV file is empty".into())
    } else {
        Ok(rows)
    }
}

fn is_c0_or_c1(character: char) -> bool {
    matches!(character as u32, 0..=31 | 127..=159)
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    csv_file: &Path,
    rows: Vec<TaskCsvRow>,
    allow_write_control: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
) -> ResultEnvelope {
    let mut details = base_details(csv_file);
    details["row_count"] = json!(rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{COMMAND}.rows"),
        format!("Loaded {} non-empty CSV row(s).", rows.len()),
    )];
    if !allow_write_control {
        findings.push(Finding::new(
            "fail",
            &format!("{COMMAND}.write-control-intent"),
            "Creating tasks requires --allow-write-control.".into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV task creation rejected before runtime access.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut collections = Map::new();
    let mut required = vec!["tasks", "targets", "scanners", "scan-configs"];
    if rows.iter().any(|row| !row.schedule_name.is_empty()) {
        required.push("schedules");
    }
    if rows.iter().any(|row| !row.alert_names.is_empty()) {
        required.push("alerts");
    }
    let mut config_recorded = false;
    let mut request_count = 0usize;
    let mut snapshot_item_count = 0usize;
    for collection in required {
        match snapshot_collection(
            root,
            collection,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut request_count,
        ) {
            Ok(items) => {
                snapshot_item_count = snapshot_item_count.saturating_add(items.len());
                if snapshot_item_count > MAX_SNAPSHOT_ITEMS {
                    findings.push(Finding::new(
                        "fail",
                        &format!("{COMMAND}.snapshot.{collection}"),
                        format!(
                            "Native collection snapshots exceed the {MAX_SNAPSHOT_ITEMS} aggregate item limit; no task creates were attempted."
                        ),
                    ));
                    return finish_status(
                        envelope(
                            root,
                            runner,
                            "Native CSV task creation failed during reference snapshot.",
                            findings,
                            details,
                        ),
                        status_only,
                    );
                }
                collections.insert(collection.into(), Value::Array(items));
            }
            Err(failure) => {
                findings.push(
                    Finding::new(
                        "fail",
                        &format!("{COMMAND}.snapshot.{collection}"),
                        format!(
                            "Native {collection} snapshot failed; no task creates were attempted."
                        ),
                    )
                    .with_details(failure),
                );
                return finish_status(
                    envelope(
                        root,
                        runner,
                        "Native CSV task creation failed during reference snapshot.",
                        findings,
                        details,
                    ),
                    status_only,
                );
            }
        }
    }
    details["task_count"] = json!(collection_items(&collections, "tasks").len());
    details["collection_counts"] = Value::Object(
        collections
            .iter()
            .map(|(name, items)| {
                (
                    name.clone(),
                    json!(items.as_array().map(Vec::len).unwrap_or_default()),
                )
            })
            .collect(),
    );
    details["snapshot_request_count"] = json!(request_count);
    findings.push(
        Finding::new(
            "pass",
            &format!("{COMMAND}.snapshot"),
            "Snapshotted every required native collection before task creation.".into(),
        )
        .with_details(details["collection_counts"].clone()),
    );

    let existing_task_names = collection_items(&collections, "tasks")
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .collect::<HashSet<_>>();
    let mut planned = Vec::new();
    let mut seen_csv_names = HashSet::new();
    let mut reported_preflight = 0usize;
    let mut reported_duplicate_alerts = 0usize;
    for row in rows {
        if existing_task_names.contains(row.name.as_str()) {
            increment(&mut details, "skipped_count");
            push_row_detail(
                &mut details,
                json!({
                    "row": row.row_number,
                    "task_name": row.name,
                    "status": "skipped",
                    "reason": "task name already exists",
                }),
            );
            continue;
        }
        if !seen_csv_names.insert(row.name.clone()) {
            increment(&mut details, "failure_count");
            push_row_detail(
                &mut details,
                json!({
                    "row": row.row_number,
                    "task_name": row.name,
                    "status": "failed",
                    "reason": "duplicate task name in CSV",
                }),
            );
            if reported_preflight < MAX_REPORTED {
                findings.push(Finding::new(
                    "fail",
                    &format!("{COMMAND}.row.{}.preflight", row.row_number),
                    format!(
                        "Duplicate task name {:?} in CSV; no task creates will be attempted.",
                        row.name
                    ),
                ));
                reported_preflight += 1;
            }
            continue;
        }

        let mut body = Map::new();
        body.insert("name".into(), json!(row.name));
        let mut errors = Vec::new();
        for (field, collection, name) in [
            ("target_id", "targets", row.target_name.as_str()),
            ("scanner_id", "scanners", row.scanner_name.as_str()),
            ("config_id", "scan-configs", row.config_name.as_str()),
        ] {
            match exact_reference(collection_items(&collections, collection), name) {
                Ok(id) => {
                    body.insert(field.into(), json!(id));
                }
                Err(error) => errors.push(format!("{collection} {name:?}: {error}")),
            }
        }
        if !row.schedule_name.is_empty() {
            match exact_reference(
                collection_items(&collections, "schedules"),
                &row.schedule_name,
            ) {
                Ok(id) => {
                    body.insert("schedule_id".into(), json!(id));
                }
                Err(error) => errors.push(format!("schedules {:?}: {error}", row.schedule_name)),
            }
        }

        let mut alert_ids = Vec::new();
        let mut duplicate_alert_names = Vec::new();
        for alert_name in &row.alert_names {
            match exact_reference(collection_items(&collections, "alerts"), alert_name) {
                Ok(id) if alert_ids.contains(&id) => {
                    duplicate_alert_names.push(alert_name.clone());
                }
                Ok(id) => alert_ids.push(id),
                Err(error) => errors.push(format!("alerts {alert_name:?}: {error}")),
            }
        }
        if alert_ids.len() > MAX_ALERTS {
            errors.push(format!("alerts exceed the {MAX_ALERTS} item limit"));
        } else if !alert_ids.is_empty() {
            body.insert("alert_ids".into(), json!(alert_ids));
        }
        if !duplicate_alert_names.is_empty() && reported_duplicate_alerts < MAX_REPORTED {
            findings.push(
                Finding::new(
                    "warn",
                    &format!("{COMMAND}.row.{}.duplicate-alerts", row.row_number),
                    format!(
                        "Duplicate alert references were de-duplicated for task {:?}.",
                        row.name
                    ),
                )
                .with_details(json!({"alert_names": duplicate_alert_names})),
            );
            reported_duplicate_alerts += 1;
        }
        body.insert(
            "hosts_ordering".into(),
            json!(row.hosts_ordering.to_ascii_lowercase()),
        );
        increment(&mut details, "host_ordering_count");

        if !errors.is_empty() {
            increment(&mut details, "failure_count");
            push_row_detail(
                &mut details,
                json!({
                    "row": row.row_number,
                    "task_name": row.name,
                    "status": "failed",
                    "reason": "reference preflight failed",
                    "errors": errors,
                }),
            );
            if reported_preflight < MAX_REPORTED {
                findings.push(
                    Finding::new(
                        "fail",
                        &format!("{COMMAND}.row.{}.preflight", row.row_number),
                        format!("Task {:?} reference preflight failed.", row.name),
                    )
                    .with_details(json!({"errors": errors})),
                );
                reported_preflight += 1;
            }
            continue;
        }
        planned.push((row, Value::Object(body)));
    }

    details["planned_count"] = json!(planned.len());
    if count(&details, "failure_count") != 0 {
        findings.push(
            Finding::new(
                "fail",
                &format!("{COMMAND}.preflight"),
                "Native CSV task creation preflight failed; no task creates were attempted.".into(),
            )
            .with_details(json!({
                "failure_count": count(&details, "failure_count"),
                "reported_failure_count": reported_preflight,
            })),
        );
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV task creation rejected before writes.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut reported_creates = 0usize;
    for (row, body) in planned {
        let reply = api.call(
            root,
            "/api/v1/tasks",
            "POST",
            Some(&body),
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        );
        let (accepted, task_id, http_status) = match reply {
            Ok(reply) => {
                let task_id = acknowledged_id(&reply, 201);
                let response_name = reply
                    .parsed
                    .as_ref()
                    .and_then(Value::as_object)
                    .and_then(|object| object.get("name"))
                    .and_then(Value::as_str);
                let accepted = task_id.is_some() && response_name == Some(row.name.as_str());
                let http_status = reply.http_status;
                if !config_recorded {
                    findings.push(reply.config);
                    config_recorded = true;
                }
                (accepted, task_id, http_status)
            }
            Err(rejected) => {
                append_rejection(
                    &mut findings,
                    rejected,
                    &mut config_recorded,
                    &mut reported_creates,
                );
                (false, None, None)
            }
        };
        push_row_detail(
            &mut details,
            json!({
                "row": row.row_number,
                "task_name": row.name,
                "task_id": task_id,
                "status": if accepted {"created"} else {"failed"},
                "http_status": http_status,
            }),
        );
        if accepted {
            increment(&mut details, "created_count");
        } else {
            increment(&mut details, "failure_count");
        }
        if reported_creates < MAX_REPORTED {
            findings.push(
                Finding::new(
                    if accepted { "pass" } else { "fail" },
                    &format!("{COMMAND}.row.{}.create", row.row_number),
                    if accepted {
                        "Native API created the task with resolved references.".into()
                    } else {
                        "Native API task creation failed or returned an invalid acknowledgement."
                            .into()
                    },
                )
                .with_details(json!({
                    "http_status": http_status,
                    "task_id": task_id,
                    "task_name": row.name,
                })),
            );
            reported_creates += 1;
        }
    }

    let failed = count(&details, "failure_count") != 0;
    finish_status(
        envelope(
            root,
            runner,
            if failed {
                "Native CSV task creation completed with failures."
            } else {
                "Native CSV task creation completed."
            },
            findings,
            details,
        ),
        status_only,
    )
}

#[allow(clippy::too_many_arguments)]
fn snapshot_collection(
    root: &Path,
    collection: &str,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
    request_count: &mut usize,
) -> Result<Vec<Value>, Value> {
    let mut output = Vec::new();
    let mut expected_total = None;
    for page in 1..=MAX_COLLECTION_PAGES {
        if *request_count >= MAX_API_REQUESTS {
            return Err(json!({
                "reason": "native collection snapshot request safety limit exceeded",
                "collection": collection,
                "page": page,
            }));
        }
        *request_count += 1;
        let path = format!("/api/v1/{collection}?page={page}&page_size={PAGE_SIZE}&sort=name");
        let reply = match api.call(
            root,
            &path,
            "GET",
            None,
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        ) {
            Ok(reply) => reply,
            Err(rejected) => {
                let mut reported = 0;
                append_rejection(findings, rejected, config_recorded, &mut reported);
                return Err(json!({
                    "reason": format!("native {collection} list lookup failed"),
                    "path": path,
                    "page": page,
                }));
            }
        };
        let ApiReply {
            output: process,
            parsed,
            http_status,
            oversized,
            config,
        } = reply;
        if !*config_recorded {
            findings.push(config);
            *config_recorded = true;
        }
        if oversized || !process.success || http_status != Some(200) {
            return Err(json!({
                "reason": format!("native {collection} list lookup failed"),
                "path": path,
                "http_status": http_status,
                "page": page,
            }));
        }
        let Some(object) = parsed.as_ref().and_then(Value::as_object) else {
            return Err(json!({
                "reason": "native collection snapshot response was malformed",
                "collection": collection,
                "page": page,
            }));
        };
        let Some(items) = object.get("items").and_then(Value::as_array) else {
            return Err(json!({
                "reason": "native collection snapshot response was malformed",
                "collection": collection,
                "page": page,
            }));
        };
        let Some(page_info) = object.get("page").and_then(Value::as_object) else {
            return Err(json!({
                "reason": "native collection snapshot pagination was malformed",
                "collection": collection,
                "page": page,
            }));
        };
        let (Some(total), Some(observed_page), Some(observed_page_size)) = (
            page_info.get("total").and_then(Value::as_u64),
            page_info.get("page").and_then(Value::as_u64),
            page_info.get("page_size").and_then(Value::as_u64),
        ) else {
            return Err(json!({
                "reason": "native collection snapshot pagination was malformed",
                "collection": collection,
                "page": page,
            }));
        };
        let offset = (page - 1).saturating_mul(PAGE_SIZE) as u64;
        let expected_items = total
            .checked_sub(offset)
            .map(|remaining| remaining.min(PAGE_SIZE as u64) as usize);
        if total > MAX_COLLECTION_ITEMS as u64
            || expected_total.is_some_and(|expected| expected != total)
            || observed_page != page as u64
            || observed_page_size != PAGE_SIZE as u64
            || expected_items != Some(items.len())
        {
            return Err(json!({
                "reason": "native collection snapshot pagination contract was invalid",
                "collection": collection,
                "page": page,
                "total": total,
            }));
        }
        expected_total = Some(total);
        for item in items {
            if !item.is_object() {
                return Err(json!({
                    "reason": "native collection snapshot item was malformed",
                    "collection": collection,
                    "page": page,
                }));
            }
            output.push(item.clone());
        }
        if offset + items.len() as u64 >= total {
            return Ok(output);
        }
    }
    Err(json!({
        "reason": "native collection snapshot pagination exceeded safety limit",
        "collection": collection,
        "page": MAX_COLLECTION_PAGES + 1,
    }))
}

fn collection_items<'a>(collections: &'a Map<String, Value>, name: &str) -> &'a [Value] {
    collections
        .get(name)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn exact_reference(items: &[Value], value: &str) -> Result<String, String> {
    let matches = items
        .iter()
        .filter(|item| {
            item.get("name").and_then(Value::as_str) == Some(value)
                || item.get("id").and_then(Value::as_str) == Some(value)
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err("name not found".into());
    }
    if matches.len() != 1 {
        return Err(format!("name is ambiguous ({} matches)", matches.len()));
    }
    let Some(id) = matches[0].get("id").and_then(Value::as_str) else {
        return Err("matching resource did not contain a valid UUID".into());
    };
    super::validate_operator_uuid(id, "matching resource id")
        .map_err(|_| "matching resource did not contain a valid UUID".to_string())?;
    Ok(id.into())
}

fn append_rejection(
    findings: &mut Vec<Finding>,
    mut rejected: Vec<Finding>,
    config_recorded: &mut bool,
    reported: &mut usize,
) {
    let config_check = format!("{COMMAND}.direct-config-shape");
    if *config_recorded {
        rejected.retain(|finding| finding.check != config_check);
    } else if rejected.iter().any(|finding| finding.check == config_check) {
        *config_recorded = true;
    }
    for finding in rejected {
        if *reported >= MAX_REPORTED {
            break;
        }
        findings.push(finding);
        *reported += 1;
    }
}

fn push_row_detail(details: &mut Value, detail: Value) {
    let can_push = details
        .get("rows")
        .and_then(Value::as_array)
        .is_some_and(|rows| rows.len() < MAX_ROW_DETAILS);
    if can_push {
        if let Some(rows) = details["rows"].as_array_mut() {
            rows.push(detail);
        }
    } else {
        increment(details, "row_detail_truncated_count");
    }
}

fn increment(details: &mut Value, key: &str) {
    details[key] = json!(count(details, key) + 1);
}

fn count(details: &Value, key: &str) -> u64 {
    details.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn finish_status(mut result: ResultEnvelope, status_only: bool) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    let details = result
        .details
        .as_ref()
        .cloned()
        .unwrap_or_else(|| json!({}));
    result.details = Some(json!({
        "csv_file": details.get("csv_file"),
        "row_count": count(&details, "row_count"),
        "task_count": count(&details, "task_count"),
        "planned_count": count(&details, "planned_count"),
        "skipped_count": count(&details, "skipped_count"),
        "host_ordering_count": count(&details, "host_ordering_count"),
        "created_count": count(&details, "created_count"),
        "failure_count": count(&details, "failure_count"),
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.status-only"),
            "Native CSV task creation passed; row details summarized.".into(),
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Runner;

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbeef\n".into(),
                stderr: String::new(),
            })
        }
    }

    struct FakeApi {
        replies: Mutex<VecDeque<Result<ApiReply, Vec<Finding>>>>,
        calls: Mutex<Vec<(String, String, Value)>>,
    }

    impl FakeApi {
        fn new(replies: Vec<Result<ApiReply, Vec<Finding>>>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl TargetApi for FakeApi {
        fn call(
            &self,
            _root: &Path,
            path: &str,
            method: &str,
            body: Option<&Value>,
            _request_check: &str,
            _config_check: &str,
            _token_check: &str,
            _runner: &dyn CommandRunner,
        ) -> Result<ApiReply, Vec<Finding>> {
            self.calls.lock().unwrap().push((
                path.into(),
                method.into(),
                body.cloned().unwrap_or(Value::Null),
            ));
            self.replies.lock().unwrap().pop_front().unwrap()
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
            config: Finding::new(
                "pass",
                &format!("{COMMAND}.direct-config-shape"),
                "valid".into(),
            ),
        })
    }

    fn page(page: usize, total: usize, items: Value) -> Result<ApiReply, Vec<Finding>> {
        reply(
            200,
            json!({
                "page": {"page": page, "page_size": PAGE_SIZE, "total": total},
                "items": items,
            }),
        )
    }

    fn item(id: &str, name: &str) -> Value {
        json!({"id": id, "name": name})
    }

    fn required_pages() -> Vec<Result<ApiReply, Vec<Finding>>> {
        vec![
            page(1, 0, json!([])),
            page(
                1,
                1,
                json!([item("11111111-1111-4111-8111-111111111111", "Target")]),
            ),
            page(
                1,
                1,
                json!([item("22222222-2222-4222-8222-222222222222", "Scanner")]),
            ),
            page(
                1,
                1,
                json!([item("33333333-3333-4333-8333-333333333333", "Config")]),
            ),
        ]
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "yafvsctl-task-csv-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn securely_loads_bounded_rows_and_validates_shape() {
        let directory = temp_dir("load");
        let path = directory.join("tasks.csv");
        fs::write(
            &path,
            " Minimal , Target , Scanner , Config \n\"Scheduled, quoted\",Target,Scanner,Config,Daily,reverse,Mail,Mail\n",
        )
        .unwrap();
        let rows = load_rows(&path).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Minimal");
        assert_eq!(rows[0].hosts_ordering, "RANDOM");
        assert_eq!(rows[1].name, "Scheduled, quoted");
        assert_eq!(rows[1].hosts_ordering, "REVERSE");
        assert_eq!(rows[1].alert_names, ["Mail", "Mail"]);

        let link = directory.join("link.csv");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_rows(&link).unwrap_err().contains("failed to read"));
        let oversized = directory.join("oversized.csv");
        fs::write(&oversized, vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
        assert!(load_rows(&oversized).unwrap_err().contains("byte limit"));
        assert!(parse_rows(b"too,few,columns\n").is_err());
        assert!(parse_rows(b"Task,Target,Scanner,Config,,sideways\n").is_err());
        assert!(parse_rows(b"Bad\x01,Target,Scanner,Config\n").is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refusal_never_calls_api() {
        let api = FakeApi::new(Vec::new());
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tasks.csv"),
            parse_rows(b"Task,Target,Scanner,Config\n").unwrap(),
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn snapshots_resolves_optional_links_and_creates() {
        let mut replies = required_pages();
        replies.push(page(
            1,
            1,
            json!([item("44444444-4444-4444-8444-444444444444", "Daily")]),
        ));
        replies.push(page(
            1,
            1,
            json!([item("55555555-5555-4555-8555-555555555555", "Mail")]),
        ));
        replies.push(reply(
            201,
            json!({
                "id":"66666666-6666-4666-8666-666666666666",
                "name":"New"
            }),
        ));
        let api = FakeApi::new(replies);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tasks.csv"),
            parse_rows(b"New,Target,Scanner,Config,Daily,reverse,Mail,Mail\n").unwrap(),
            true,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "warn");
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["created_count"], 1);
        assert_eq!(details["planned_count"], 1);
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 7);
        let body = &calls[6].2;
        assert_eq!(body["target_id"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(body["scanner_id"], "22222222-2222-4222-8222-222222222222");
        assert_eq!(body["config_id"], "33333333-3333-4333-8333-333333333333");
        assert_eq!(body["schedule_id"], "44444444-4444-4444-8444-444444444444");
        assert_eq!(
            body["alert_ids"],
            json!(["55555555-5555-4555-8555-555555555555"])
        );
        assert_eq!(body["hosts_ordering"], "reverse");
    }

    #[test]
    fn preflight_failure_attempts_no_create() {
        let api = FakeApi::new(required_pages());
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tasks.csv"),
            parse_rows(
                b"Valid,Target,Scanner,Config\nInvalid,Missing,Scanner,Config\nValid,Target,Scanner,Config\n",
            )
            .unwrap(),
            true,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["planned_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["failure_count"], 2);
        assert_eq!(result.details.as_ref().unwrap()["host_ordering_count"], 2);
        assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));
    }

    #[test]
    fn create_failures_continue_and_responses_do_not_leak() {
        let mut replies = required_pages();
        replies.push(reply(409, json!({"secret":"do-not-retain"})));
        replies.push(reply(
            201,
            json!({
                "id":"77777777-7777-4777-8777-777777777777",
                "name":"Second"
            }),
        ));
        let api = FakeApi::new(replies);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tasks.csv"),
            parse_rows(b"First,Target,Scanner,Config\nSecond,Target,Scanner,Config\n").unwrap(),
            true,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["created_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["failure_count"], 1);
        assert_eq!(api.calls.lock().unwrap().len(), 6);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-retain")
        );
    }

    #[test]
    fn snapshot_pagination_is_strict_and_bounded() {
        let first = Value::Array(
            (0..PAGE_SIZE)
                .map(|index| {
                    item(
                        &format!("11111111-1111-4111-8111-{index:012}"),
                        &format!("item-{index}"),
                    )
                })
                .collect(),
        );
        let api = FakeApi::new(vec![
            page(1, PAGE_SIZE + 1, first),
            page(
                2,
                PAGE_SIZE + 1,
                json!([item("22222222-2222-4222-8222-222222222222", "last")]),
            ),
        ]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        let items = snapshot_collection(
            Path::new("/srv/YAFVS"),
            "targets",
            &Runner,
            &api,
            &mut findings,
            &mut config,
            &mut requests,
        )
        .unwrap();
        assert_eq!(items.len(), PAGE_SIZE + 1);
        assert_eq!(requests, 2);

        let malformed = FakeApi::new(vec![reply(
            200,
            json!({"page":{"page":2,"page_size":500,"total":0},"items":[]}),
        )]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        assert!(
            snapshot_collection(
                Path::new("/srv/YAFVS"),
                "targets",
                &Runner,
                &malformed,
                &mut findings,
                &mut config,
                &mut requests,
            )
            .unwrap_err()["reason"]
                .as_str()
                .unwrap()
                .contains("pagination contract")
        );
    }

    #[test]
    fn status_only_compacts_success() {
        let mut replies = required_pages();
        replies.push(reply(
            201,
            json!({
                "id":"88888888-8888-4888-8888-888888888888",
                "name":"Task"
            }),
        ));
        let api = FakeApi::new(replies);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tasks.csv"),
            parse_rows(b"Task,Target,Scanner,Config\n").unwrap(),
            true,
            true,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["created_count"], 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].check,
            "native-tasks-from-csv.status-only"
        );
    }
}
