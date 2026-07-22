// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{GuardedApi, TargetApi, acknowledged_id, target_body};
use crate::commands::native_runtime::percent_encode_component;
use crate::commands::{common::iso_system_time, common::metadata};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::SystemTime;

const COMMAND: &str = "native-targets-from-csv";
const DEFAULT_PORT_LIST_ID: &str = "730ef368-57e2-11e1-a90f-406186ea4fc5";
const DEFAULT_ALIVE_TEST: &str = "Scan Config Default";
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 4095;
const MAX_FIELD_BYTES: usize = 4096;
const LOOKUP_PAGE_SIZE: usize = 100;
const MAX_LOOKUP_PAGES: usize = 1000;
const MAX_LOOKUP_ITEMS: usize = LOOKUP_PAGE_SIZE * MAX_LOOKUP_PAGES;
const MAX_LOOKUP_REQUESTS: usize = 4095;
const MAX_REPORTED_FAILURES: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TargetCsvRow {
    row_number: usize,
    name: String,
    host: String,
    smb_credential_name: String,
    ssh_credential_name: String,
    alive_test: String,
}

#[derive(Clone, Debug)]
struct ResolvedTarget {
    row: TargetCsvRow,
    credentials: Map<String, Value>,
}

pub fn command_native_targets_from_csv(
    root: &Path,
    csv_file: &Path,
    port_list_id: Option<&str>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    let rows = match load_rows(csv_file) {
        Ok(rows) => rows,
        Err(error) => {
            return finish_status(
                envelope(
                    root,
                    &SystemCommandRunner,
                    "Native CSV target creation rejected before runtime access.",
                    vec![
                        Finding::new("fail", &format!("{COMMAND}.rows"), error)
                            .with_details(json!({"csv_file":csv_file})),
                    ],
                    base_details(csv_file, port_list_id, dry_run),
                ),
                status_only,
            );
        }
    };
    command_with(
        root,
        csv_file,
        rows,
        port_list_id,
        allow_write_control,
        dry_run,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
        iso_system_time(SystemTime::now()).unwrap_or_else(|| "unknown".into()),
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

fn base_details(csv_file: &Path, port_list_id: Option<&str>, dry_run: bool) -> Value {
    json!({
        "csv_file": csv_file,
        "row_count": 0,
        "dry_run": dry_run,
        "port_list_id": port_list_id.unwrap_or(DEFAULT_PORT_LIST_ID),
        "skipped_existing_target_count": 0,
        "created_target_count": 0,
        "created_target_ids": [],
        "skipped_existing_targets": [],
    })
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read target CSV file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read target CSV file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("failed to read target CSV file: path is not a regular file".into());
    }
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(format!(
            "failed to read target CSV file: file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_FILE_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read target CSV file: {error}"))?;
    if input.len() > MAX_FILE_BYTES {
        return Err(format!(
            "failed to read target CSV file: file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    Ok(input)
}

fn load_rows(path: &Path) -> Result<Vec<TargetCsvRow>, String> {
    parse_rows(&read_bounded_file(path)?)
}

fn parse_rows(input: &[u8]) -> Result<Vec<TargetCsvRow>, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(input);
    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let row_number = index + 1;
        let record = record.map_err(|error| format!("failed to read target CSV file: {error}"))?;
        if record.is_empty() {
            continue;
        }
        if record.len() < 7 {
            return Err(format!("row {row_number} must have at least 7 columns"));
        }
        for field in &record {
            if field.len() > MAX_FIELD_BYTES {
                return Err(format!(
                    "row {row_number} fields must be at most {MAX_FIELD_BYTES} bytes"
                ));
            }
        }
        let name = record[0].trim();
        let host = record[1].trim();
        if name.is_empty() || host.is_empty() {
            return Err(format!(
                "row {row_number} must include target name and host"
            ));
        }
        rows.push(TargetCsvRow {
            row_number,
            name: name.into(),
            host: host.into(),
            smb_credential_name: record[2].trim().into(),
            ssh_credential_name: record[3].trim().into(),
            alive_test: match record[6].trim() {
                "" => DEFAULT_ALIVE_TEST.into(),
                value => value.into(),
            },
        });
        if rows.len() > MAX_ROWS {
            return Err(format!(
                "target CSV file must contain at most {MAX_ROWS} non-empty rows"
            ));
        }
    }
    if rows.is_empty() {
        return Err("target CSV file is empty".into());
    }
    Ok(rows)
}

fn target_csv_body(
    row: &TargetCsvRow,
    port_list_id: &str,
    timestamp: &str,
    credentials: &Map<String, Value>,
) -> Value {
    let mut body = target_body(&row.host, port_list_id, timestamp);
    body["name"] = json!(row.name);
    body["alive_tests"] = json!([row.alive_test]);
    if !credentials.is_empty() {
        body["credentials"] = Value::Object(credentials.clone());
    }
    body
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    csv_file: &Path,
    rows: Vec<TargetCsvRow>,
    port_list_id: Option<&str>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    timestamp: String,
) -> ResultEnvelope {
    let mut details = base_details(csv_file, port_list_id, dry_run);
    details["row_count"] = json!(rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{COMMAND}.rows"),
        format!("Loaded {} non-empty CSV row(s).", rows.len()),
    )];
    let port_list_id = port_list_id.unwrap_or(DEFAULT_PORT_LIST_ID);
    if super::validate_operator_uuid(port_list_id, "--port-list-id").is_err() {
        findings.push(
            Finding::new(
                "fail",
                &format!("{COMMAND}.port-list-id"),
                "--port-list-id must be a UUID.".into(),
            )
            .with_details(json!({"port_list_id":port_list_id})),
        );
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV target creation rejected before runtime access.",
                findings,
                details,
            ),
            status_only,
        );
    }
    details["port_list_id"] = json!(port_list_id);

    if dry_run {
        let empty = Map::new();
        details["planned_targets"] = Value::Array(
            rows.iter()
                .map(|row| target_csv_body(row, port_list_id, &timestamp, &empty))
                .collect(),
        );
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.dry-run"),
            "Dry run planned native target writes without runtime access or credential resolution."
                .into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV target creation dry run completed.",
                findings,
                details,
            ),
            status_only,
        );
    }
    if !allow_write_control {
        findings.push(Finding::new(
            "fail",
            &format!("{COMMAND}.write-control-intent"),
            "Creating targets requires --allow-write-control.".into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV target creation rejected before runtime access.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut resolved = Vec::new();
    let mut preflight_failures = Vec::new();
    let mut skipped = Vec::new();
    let mut planned_names = HashSet::new();
    let mut config_recorded = false;
    let mut lookup_requests = 0usize;
    for row in rows {
        if planned_names.contains(&row.name) {
            skipped.push(row.name);
            continue;
        }
        let target_matches = match lookup_exact(
            root,
            "/api/v1/targets",
            &row.name,
            None,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut lookup_requests,
        ) {
            Ok(matches) => matches,
            Err(failure) => {
                preflight_failures.push(preflight_failure(&row, None, None, failure));
                continue;
            }
        };
        if !target_matches.is_empty() {
            skipped.push(row.name);
            continue;
        }

        let mut credentials = Map::new();
        for (field, name, allowed_types) in [
            ("smb", row.smb_credential_name.as_str(), &["up"][..]),
            ("ssh", row.ssh_credential_name.as_str(), &["up", "usk"][..]),
        ] {
            if name.is_empty() {
                continue;
            }
            let matches = match lookup_exact(
                root,
                "/api/v1/credentials",
                name,
                Some(allowed_types),
                runner,
                api,
                &mut findings,
                &mut config_recorded,
                &mut lookup_requests,
            ) {
                Ok(matches) => matches,
                Err(failure) => {
                    preflight_failures.push(preflight_failure(
                        &row,
                        Some(name),
                        Some(field),
                        failure,
                    ));
                    continue;
                }
            };
            if matches.len() != 1 {
                preflight_failures.push(json!({
                    "row": row.row_number,
                    "name": row.name,
                    "credential": name,
                    "field": field,
                    "reason": "credential lookup was missing or ambiguous",
                    "match_count": matches.len(),
                }));
                continue;
            }
            let id = matches[0].get("id").and_then(Value::as_str);
            let Some(id) = id.filter(|value| {
                super::validate_operator_uuid(value, "credential response id").is_ok()
            }) else {
                preflight_failures.push(json!({
                    "row": row.row_number,
                    "name": row.name,
                    "credential": name,
                    "field": field,
                    "reason": "credential response did not include a UUID id",
                }));
                continue;
            };
            credentials.insert(field.into(), json!({"id":id}));
        }
        resolved.push(ResolvedTarget {
            row: row.clone(),
            credentials,
        });
        planned_names.insert(row.name);
    }
    details["skipped_existing_targets"] = json!(skipped);
    details["skipped_existing_target_count"] = json!(skipped.len());
    details["lookup_request_count"] = json!(lookup_requests);
    if !preflight_failures.is_empty() {
        let reported = preflight_failures
            .iter()
            .take(MAX_REPORTED_FAILURES)
            .cloned()
            .collect::<Vec<_>>();
        details["preflight_failure_count"] = json!(preflight_failures.len());
        details["preflight_failures"] = json!(reported);
        findings.push(
            Finding::new(
                "fail",
                &format!("{COMMAND}.preflight"),
                "Native CSV target creation preflight failed before creating targets.".into(),
            )
            .with_details(json!({
                "failure_count":preflight_failures.len(),
                "failures":reported,
            })),
        );
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV target creation rejected before target writes.",
                findings,
                details,
            ),
            status_only,
        );
    }
    findings.push(Finding::new(
        "pass",
        &format!("{COMMAND}.preflight"),
        format!(
            "Preflight resolved {} target create row(s) and skipped {} existing target(s).",
            resolved.len(),
            skipped.len()
        ),
    ));

    let mut created_ids = Vec::new();
    let mut failures = Vec::new();
    for resolved in &resolved {
        let body = target_csv_body(
            &resolved.row,
            port_list_id,
            &timestamp,
            &resolved.credentials,
        );
        let reply = match api.call(
            root,
            "/api/v1/targets",
            "POST",
            Some(&body),
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        ) {
            Ok(reply) => reply,
            Err(mut rejected) => {
                if config_recorded {
                    remove_duplicate_config(&mut rejected);
                }
                findings.append(&mut rejected);
                failures.push(json!({
                    "row": resolved.row.row_number,
                    "name": resolved.row.name,
                    "http_status": null,
                }));
                break;
            }
        };
        let id = acknowledged_id(&reply, 201);
        if !config_recorded {
            findings.push(reply.config);
            config_recorded = true;
        }
        if let Some(id) = id {
            created_ids.push(id);
            continue;
        }
        failures.push(json!({
            "row": resolved.row.row_number,
            "name": resolved.row.name,
            "http_status": reply.http_status,
        }));
        break;
    }
    details["created_target_ids"] = json!(created_ids);
    details["created_target_count"] = json!(created_ids.len());
    if failures.is_empty() {
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.target-create"),
            format!(
                "Created {} target(s) through the native API.",
                created_ids.len()
            ),
        ));
    } else {
        details["create_failures"] = json!(failures);
        findings.push(
            Finding::new(
                "fail",
                &format!("{COMMAND}.target-create"),
                "One or more native target create requests failed.".into(),
            )
            .with_details(json!({"failure_count":failures.len(),"failures":failures})),
        );
    }
    let failed = findings.iter().any(|finding| finding.status == "fail");
    finish_status(
        envelope(
            root,
            runner,
            if failed {
                "Native CSV target creation failed."
            } else {
                "Native CSV target creation completed."
            },
            findings,
            details,
        ),
        status_only,
    )
}

#[allow(clippy::too_many_arguments)]
fn lookup_exact(
    root: &Path,
    base_path: &str,
    name: &str,
    allowed_types: Option<&[&str]>,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
    request_count: &mut usize,
) -> Result<Vec<Value>, Value> {
    let mut matches = Vec::new();
    let encoded = percent_encode_component(name);
    let mut expected_total = None;
    let mut expected_page_size = None;
    for page in 1..=MAX_LOOKUP_PAGES {
        if *request_count >= MAX_LOOKUP_REQUESTS {
            return Err(json!({
                "reason":"lookup request safety limit exceeded",
                "page":page,
                "request_limit":MAX_LOOKUP_REQUESTS,
            }));
        }
        *request_count += 1;
        let path = format!("{base_path}?filter={encoded}&page={page}&page_size={LOOKUP_PAGE_SIZE}");
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
            Err(mut rejected) => {
                if *config_recorded {
                    remove_duplicate_config(&mut rejected);
                }
                findings.append(&mut rejected);
                return Err(json!({"reason":"lookup failed","page":page}));
            }
        };
        if !*config_recorded {
            findings.push(reply.config);
            *config_recorded = true;
        }
        let parsed = reply.parsed.as_ref().and_then(Value::as_object);
        let items = parsed
            .and_then(|object| object.get("items"))
            .and_then(Value::as_array);
        if reply.oversized
            || !reply.output.success
            || reply.http_status != Some(200)
            || items.is_none()
        {
            return Err(json!({
                "reason":"lookup failed",
                "http_status":reply.http_status,
                "page":page,
            }));
        }
        let items = items.expect("checked array");
        if items.len() > LOOKUP_PAGE_SIZE {
            return Err(json!({
                "reason":"lookup page exceeded item limit",
                "page":page,
                "item_count":items.len(),
                "item_limit":LOOKUP_PAGE_SIZE,
            }));
        }
        for item in items {
            let Some(object) = item.as_object() else {
                continue;
            };
            if object.get("name").and_then(Value::as_str) != Some(name) {
                continue;
            }
            if let Some(allowed_types) = allowed_types {
                let credential_type = object.get("credential_type").and_then(Value::as_str);
                if !credential_type.is_some_and(|value| allowed_types.contains(&value)) {
                    continue;
                }
            }
            matches.push(item.clone());
            if matches.len() > MAX_LOOKUP_ITEMS {
                return Err(json!({
                    "reason":"lookup match safety limit exceeded",
                    "page":page,
                    "item_limit":MAX_LOOKUP_ITEMS,
                }));
            }
        }
        let page_info = parsed
            .and_then(|object| object.get("page"))
            .and_then(Value::as_object);
        let total = page_info
            .and_then(|page| page.get("total"))
            .and_then(Value::as_u64)
            .unwrap_or(items.len() as u64);
        let observed_page = page_info
            .and_then(|info| info.get("page"))
            .and_then(Value::as_u64)
            .unwrap_or(page as u64);
        let observed_page_size = page_info
            .and_then(|info| info.get("page_size"))
            .and_then(Value::as_u64)
            .unwrap_or(LOOKUP_PAGE_SIZE as u64);
        if observed_page != page as u64
            || !(1..=LOOKUP_PAGE_SIZE as u64).contains(&observed_page_size)
            || total > MAX_LOOKUP_ITEMS as u64
            || expected_total.is_some_and(|expected| expected != total)
            || expected_page_size.is_some_and(|expected| expected != observed_page_size)
            || observed_page
                .saturating_sub(1)
                .saturating_mul(observed_page_size)
                .saturating_add(items.len() as u64)
                > total
        {
            return Err(json!({
                "reason":"lookup pagination contract was invalid",
                "page":page,
                "observed_page":observed_page,
                "observed_page_size":observed_page_size,
                "total":total,
            }));
        }
        expected_total = Some(total);
        expected_page_size = Some(observed_page_size);
        if observed_page.saturating_mul(observed_page_size) >= total || items.is_empty() {
            return Ok(matches);
        }
    }
    Err(json!({
        "reason":"lookup pagination exceeded safety limit",
        "page":MAX_LOOKUP_PAGES + 1,
    }))
}

fn preflight_failure(
    row: &TargetCsvRow,
    credential: Option<&str>,
    field: Option<&str>,
    failure: Value,
) -> Value {
    let mut value = json!({
        "row":row.row_number,
        "name":row.name,
    });
    if let Some(credential) = credential {
        value["credential"] = json!(credential);
    }
    if let Some(field) = field {
        value["field"] = json!(field);
    }
    if let (Some(target), Some(source)) = (value.as_object_mut(), failure.as_object()) {
        target.extend(source.clone());
    }
    value
}

fn remove_duplicate_config(findings: &mut Vec<Finding>) {
    findings.retain(|finding| finding.check != format!("{COMMAND}.direct-config-shape"));
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
        "row_count": details.get("row_count").and_then(Value::as_u64).unwrap_or(0),
        "dry_run": details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        "port_list_id": details.get("port_list_id"),
        "skipped_existing_target_count": details.get("skipped_existing_target_count").and_then(Value::as_u64).unwrap_or(0),
        "created_target_count": details.get("created_target_count").and_then(Value::as_u64).unwrap_or(0),
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.status-only"),
            "Native CSV target creation passed; details summarized.".into(),
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::resource_import::ApiReply;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::Mutex;
    use std::time::UNIX_EPOCH;

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
        calls: Mutex<Vec<(String, String, Option<Value>)>>,
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
            self.calls
                .lock()
                .unwrap()
                .push((path.into(), method.into(), body.cloned()));
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
                "page":{"page":page,"page_size":LOOKUP_PAGE_SIZE,"total":total},
                "items":items,
            }),
        )
    }

    fn rows() -> Vec<TargetCsvRow> {
        parse_rows(b"CSV target,192.0.2.10,smb-one,ssh-one,,,ICMP Ping\n").unwrap()
    }

    #[test]
    fn securely_loads_bounded_csv_rows() {
        let parsed = parse_rows(b"CSV target,192.0.2.10,smb-one,ssh-one,,,ICMP Ping\n\n").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "CSV target");
        assert_eq!(parsed[0].alive_test, "ICMP Ping");
        assert!(parse_rows(b"too,few,columns\n").is_err());
        assert!(
            parse_rows(format!("target,host,,,,,{}\n", "x".repeat(MAX_FIELD_BYTES + 1)).as_bytes())
                .unwrap_err()
                .contains("at most 4096 bytes")
        );

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "yafvsctl-target-csv-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("targets.csv");
        fs::write(&path, "target,host,,,,,\n").unwrap();
        assert_eq!(load_rows(&path).unwrap().len(), 1);
        let link = directory.join("link.csv");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_rows(&link).unwrap_err().contains("failed to read"));
        assert!(
            load_rows(&directory)
                .unwrap_err()
                .contains("not a regular file")
        );
        let oversized = directory.join("oversized.csv");
        fs::write(&oversized, vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
        assert!(load_rows(&oversized).unwrap_err().contains("byte limit"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dry_run_and_write_refusal_never_call_api() {
        let api = FakeApi::new(Vec::new());
        let dry_run = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.csv"),
            rows(),
            None,
            false,
            true,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(dry_run.status, "pass");
        let body = &dry_run.details.as_ref().unwrap()["planned_targets"][0];
        assert_eq!(body["name"], "CSV target");
        assert_eq!(body["hosts"], json!(["192.0.2.10"]));
        assert_eq!(body["alive_tests"], json!(["ICMP Ping"]));
        assert!(body.get("credentials").is_none());
        let refused = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.csv"),
            rows(),
            None,
            false,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(refused.status, "fail");
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn resolves_credentials_skips_duplicates_and_existing_targets() {
        let rows = parse_rows(
            b"CSV target,192.0.2.10,smb-one,ssh-one,,,ICMP Ping\nCSV target,192.0.2.12,,,,,\nExisting target,192.0.2.11,,,,,\n",
        )
        .unwrap();
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(
                1,
                1,
                json!([{"id":"44444444-4444-4444-8444-444444444444","name":"smb-one","credential_type":"up"}]),
            ),
            page(
                1,
                1,
                json!([{"id":"55555555-5555-4555-8555-555555555555","name":"ssh-one","credential_type":"usk"}]),
            ),
            page(
                1,
                1,
                json!([{"id":"33333333-3333-4333-8333-333333333333","name":"Existing target"}]),
            ),
            reply(201, json!({"id":"66666666-6666-4666-8666-666666666666"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.csv"),
            rows,
            None,
            true,
            false,
            true,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["created_target_count"], 1);
        assert_eq!(
            result.details.as_ref().unwrap()["skipped_existing_target_count"],
            2
        );
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        let posted = calls.last().unwrap().2.as_ref().unwrap();
        assert_eq!(
            posted["credentials"]["smb"]["id"],
            "44444444-4444-4444-8444-444444444444"
        );
        assert_eq!(
            posted["credentials"]["ssh"]["id"],
            "55555555-5555-4555-8555-555555555555"
        );
    }

    #[test]
    fn exact_lookup_pages_and_rejects_malformed_pagination() {
        let api = FakeApi::new(vec![
            page(
                1,
                200,
                json!([{"id":"11111111-1111-4111-8111-111111111111","name":"near miss"}]),
            ),
            page(
                2,
                200,
                json!([{"id":"22222222-2222-4222-8222-222222222222","name":"needle","credential_type":"up"}]),
            ),
        ]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        let matches = lookup_exact(
            Path::new("/srv/YAFVS"),
            "/api/v1/credentials",
            "needle",
            Some(&["up"]),
            &Runner,
            &api,
            &mut findings,
            &mut config,
            &mut requests,
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(requests, 2);

        let malformed = FakeApi::new(vec![reply(
            200,
            json!({"page":{"page":2,"page_size":100,"total":200},"items":[]}),
        )]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        assert!(
            lookup_exact(
                Path::new("/srv/YAFVS"),
                "/api/v1/targets",
                "needle",
                None,
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
    fn preflight_failure_prevents_every_post() {
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            page(1, 0, json!([])),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.csv"),
            rows(),
            None,
            true,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "fail");
        assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "native-targets-from-csv.preflight")
        );
    }

    #[test]
    fn creation_stops_at_first_failure_and_retains_prior_success() {
        let rows = parse_rows(b"One,192.0.2.10,,,,,\nTwo,192.0.2.11,,,,,\nThree,192.0.2.12,,,,,\n")
            .unwrap();
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            reply(201, json!({"id":"66666666-6666-4666-8666-666666666661"})),
            reply(500, json!({"secret":"do-not-retain"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.csv"),
            rows,
            None,
            true,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["created_target_count"], 1);
        assert_eq!(api.calls.lock().unwrap().len(), 5);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-retain")
        );
    }
}
