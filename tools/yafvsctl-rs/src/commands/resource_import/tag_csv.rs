// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{GuardedApi, TargetApi, acknowledged_id};
use crate::commands::native_runtime::percent_encode_component;
use crate::commands::{common::iso_system_time, common::metadata};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::SystemTime;

const COMMAND: &str = "native-tags-from-csv";
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 4095;
const MAX_FIELD_BYTES: usize = 4096;
const MAX_RESOURCE_COLUMNS: usize = 10;
const LOOKUP_PAGE_SIZE: usize = 100;
const MAX_LOOKUP_PAGES: usize = 1000;
const MAX_LOOKUP_ITEMS: usize = LOOKUP_PAGE_SIZE * MAX_LOOKUP_PAGES;
const MAX_LOOKUP_REQUESTS: usize = 4095;
const MAX_REPORTED_FAILURES: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TagCsvRow {
    row_number: usize,
    resource_type: &'static str,
    value: String,
    tag_name: String,
    resource_names: Vec<String>,
}

#[derive(Clone, Debug)]
struct ResolvedTag {
    row: TagCsvRow,
    resource_ids: Vec<String>,
}

pub fn command_native_tags_from_csv(
    root: &Path,
    csv_file: &Path,
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
                    "Native CSV tag creation rejected before runtime access.",
                    vec![
                        Finding::new("fail", &format!("{COMMAND}.rows"), error)
                            .with_details(json!({"csv_file": csv_file})),
                    ],
                    base_details(csv_file, dry_run),
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

fn base_details(csv_file: &Path, dry_run: bool) -> Value {
    json!({
        "csv_file": csv_file, "row_count": 0, "dry_run": dry_run,
        "skipped_existing_tag_count": 0, "created_tag_count": 0,
        "created_tag_ids": [], "assigned_resource_count": 0,
    })
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read tag CSV file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read tag CSV file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("failed to read tag CSV file: path is not a regular file".into());
    }
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(format!(
            "failed to read tag CSV file: file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_FILE_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read tag CSV file: {error}"))?;
    if input.len() > MAX_FILE_BYTES {
        return Err(format!(
            "failed to read tag CSV file: file exceeds the {MAX_FILE_BYTES} byte limit"
        ));
    }
    Ok(input)
}

fn load_rows(path: &Path) -> Result<Vec<TagCsvRow>, String> {
    parse_rows(&read_bounded_file(path)?)
}

fn resource_type(inherited_type: &str) -> Option<&'static str> {
    match inherited_type {
        "ALERT" => Some("alert"),
        "CONFIG" => Some("config"),
        "CREDENTIAL" => Some("credential"),
        "REPORT" => Some("report"),
        "SCANNER" => Some("scanner"),
        "SCHEDULE" => Some("schedule"),
        "TARGET" => Some("target"),
        "TASK" => Some("task"),
        _ => None,
    }
}

fn parse_rows(input: &[u8]) -> Result<Vec<TagCsvRow>, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(input);
    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let row_number = index + 1;
        let record = record.map_err(|error| format!("failed to read tag CSV file: {error}"))?;
        if record.is_empty() || record.iter().all(|field| field.trim().is_empty()) {
            return Err(format!("row {row_number} must not be blank"));
        }
        if record.len() < 3 {
            return Err(format!(
                "row {row_number} must include tag type, tag value, and description"
            ));
        }
        if record.len() > 3 + MAX_RESOURCE_COLUMNS {
            return Err(format!(
                "row {row_number} must contain at most {MAX_RESOURCE_COLUMNS} resource columns"
            ));
        }
        for field in &record {
            if field.len() > MAX_FIELD_BYTES {
                return Err(format!(
                    "row {row_number} fields must be at most {MAX_FIELD_BYTES} bytes"
                ));
            }
        }
        let inherited_type = record[0].trim().to_ascii_uppercase();
        let value = record[1].trim();
        if inherited_type.is_empty() || value.is_empty() {
            return Err(format!(
                "row {row_number} must include tag type and tag value"
            ));
        }
        let Some(resource_type) = resource_type(&inherited_type) else {
            return Err(format!(
                "row {row_number} has unsupported tag type {inherited_type}; supported native-safe types: ALERT, CONFIG, CREDENTIAL, REPORT, SCANNER, SCHEDULE, TARGET, TASK"
            ));
        };
        let resource_names = record
            .iter()
            .skip(3)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if inherited_type == "REPORT" && resource_names.is_empty() {
            return Err(format!(
                "row {row_number} uses inherited REPORT resource_filter=~tagName semantics; native REPORT rows require exact report UUID resource columns"
            ));
        }
        if inherited_type == "REPORT"
            && resource_names.iter().any(|resource| {
                super::validate_operator_uuid(resource, "report resource id").is_err()
            })
        {
            return Err(format!(
                "row {row_number} native REPORT resource columns must be exact report UUIDs"
            ));
        }
        let description = record[2].trim().to_owned();
        rows.push(TagCsvRow {
            row_number,
            tag_name: format!("{value}:{description}:{inherited_type}"),
            resource_type,
            value: value.into(),
            resource_names,
        });
        if rows.len() > MAX_ROWS {
            return Err(format!(
                "tag CSV file must contain at most {MAX_ROWS} non-empty rows"
            ));
        }
    }
    if rows.is_empty() {
        Err("tag CSV file is empty".into())
    } else {
        Ok(rows)
    }
}

fn tag_body(row: &TagCsvRow, timestamp: &str, resource_ids: &[String]) -> Value {
    let mut body = json!({
        "name": row.tag_name, "comment": format!("Created: {timestamp}"), "value": row.value,
        "resource_type": row.resource_type, "active": true,
    });
    if !resource_ids.is_empty() {
        body["resource_ids"] = json!(resource_ids);
    }
    body
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    csv_file: &Path,
    rows: Vec<TagCsvRow>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    timestamp: String,
) -> ResultEnvelope {
    let mut details = base_details(csv_file, dry_run);
    details["row_count"] = json!(rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{COMMAND}.rows"),
        format!("Loaded {} non-empty CSV row(s).", rows.len()),
    )];
    if dry_run {
        details["planned_tags"] = Value::Array(rows.iter().map(|row| json!({"tag": tag_body(row, &timestamp, &[]), "resource_names": row.resource_names})).collect());
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.dry-run"),
            "Dry run planned native tag writes without runtime access or resource-name resolution."
                .into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV tag creation dry run completed.",
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
            "Creating tags requires --allow-write-control.".into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV tag creation rejected before runtime access.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut resolved = Vec::new();
    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    let mut planned_names = HashSet::new();
    let mut config_recorded = false;
    let mut lookup_requests = 0usize;
    for row in rows {
        if planned_names.contains(&row.tag_name) {
            skipped.push(row.tag_name);
            continue;
        }
        let tag_matches = match lookup_exact(
            root,
            "/api/v1/tags",
            &row.tag_name,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut lookup_requests,
        ) {
            Ok(matches) => matches,
            Err(failure) => {
                failures.push(preflight_failure(&row, None, failure));
                continue;
            }
        };
        if !tag_matches.is_empty() {
            skipped.push(row.tag_name);
            continue;
        }
        let mut resource_ids = Vec::new();
        for resource_name in &row.resource_names {
            let path = format!(
                "/api/v1/tags/resource-names/{}",
                percent_encode_component(row.resource_type)
            );
            let matches = match lookup_exact(
                root,
                &path,
                resource_name,
                runner,
                api,
                &mut findings,
                &mut config_recorded,
                &mut lookup_requests,
            ) {
                Ok(matches) => matches,
                Err(failure) => {
                    failures.push(preflight_failure(&row, Some(resource_name), failure));
                    continue;
                }
            };
            if matches.len() != 1 {
                failures.push(json!({"row":row.row_number,"tag":row.tag_name,"resource":resource_name,"reason":"resource lookup was missing or ambiguous","match_count":matches.len()}));
                continue;
            }
            let id = matches[0].get("id").and_then(Value::as_str);
            let Some(id) =
                id.filter(|id| super::validate_operator_uuid(id, "resource response id").is_ok())
            else {
                failures.push(json!({"row":row.row_number,"tag":row.tag_name,"resource":resource_name,"reason":"resource response did not include a UUID id"}));
                continue;
            };
            resource_ids.push(id.into());
        }
        resolved.push(ResolvedTag {
            row: row.clone(),
            resource_ids,
        });
        planned_names.insert(row.tag_name);
    }
    details["lookup_request_count"] = json!(lookup_requests);
    details["skipped_existing_tag_count"] = json!(skipped.len());
    details["skipped_existing_tags"] = json!(skipped);
    if !failures.is_empty() {
        let reported = failures
            .iter()
            .take(MAX_REPORTED_FAILURES)
            .cloned()
            .collect::<Vec<_>>();
        details["preflight_failure_count"] = json!(failures.len());
        details["preflight_failures"] = json!(reported);
        findings.push(
            Finding::new(
                "fail",
                &format!("{COMMAND}.preflight"),
                "Native CSV tag creation preflight failed before creating tags.".into(),
            )
            .with_details(json!({"failure_count":failures.len(),"failures":reported})),
        );
        return finish_status(
            envelope(
                root,
                runner,
                "Native CSV tag creation rejected before tag writes.",
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
            "Preflight resolved {} tag create row(s) and skipped {} existing tag(s).",
            resolved.len(),
            skipped.len()
        ),
    ));

    let mut created_ids = Vec::new();
    let mut assigned_resource_count = 0usize;
    let mut create_failures = Vec::new();
    for resolved in resolved {
        let body = tag_body(&resolved.row, &timestamp, &resolved.resource_ids);
        let reply = match api.call(
            root,
            "/api/v1/tags",
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
                create_failures.push(json!({"row":resolved.row.row_number,"tag":resolved.row.tag_name,"stage":"create","http_status":null}));
                break;
            }
        };
        let id = acknowledged_id(&reply, 201);
        if !config_recorded {
            findings.push(reply.config);
            config_recorded = true;
        }
        let Some(id) = id else {
            create_failures.push(json!({"row":resolved.row.row_number,"tag":resolved.row.tag_name,"stage":"create","http_status":reply.http_status}));
            break;
        };
        assigned_resource_count += resolved.resource_ids.len();
        created_ids.push(id);
    }
    details["created_tag_ids"] = json!(created_ids);
    details["created_tag_count"] = json!(created_ids.len());
    details["assigned_resource_count"] = json!(assigned_resource_count);
    if create_failures.is_empty() {
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.tag-create"),
            format!(
                "Created {} tag(s) and assigned {} resource(s) through the native API.",
                created_ids.len(),
                assigned_resource_count
            ),
        ));
    } else {
        details["create_failure_count"] = json!(create_failures.len());
        details["create_failures"] = json!(create_failures);
        findings.push(
            Finding::new(
                "fail",
                &format!("{COMMAND}.tag-create"),
                "One or more native tag create requests failed.".into(),
            )
            .with_details(
                json!({"failure_count":create_failures.len(),"failures":create_failures}),
            ),
        );
    }
    let failed = findings.iter().any(|finding| finding.status == "fail");
    finish_status(
        envelope(
            root,
            runner,
            if failed {
                "Native CSV tag creation failed."
            } else {
                "Native CSV tag creation completed."
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
    value: &str,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
    request_count: &mut usize,
) -> Result<Vec<Value>, Value> {
    let encoded = percent_encode_component(value);
    let separator = if base_path.contains('?') { '&' } else { '?' };
    let mut matches = Vec::new();
    for page in 1..=MAX_LOOKUP_PAGES {
        if *request_count >= MAX_LOOKUP_REQUESTS {
            return Err(json!({"reason":"lookup request safety limit exceeded","page":page}));
        }
        *request_count += 1;
        let path = format!(
            "{base_path}{separator}filter={encoded}&page={page}&page_size={LOOKUP_PAGE_SIZE}"
        );
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
        if reply.oversized || !reply.output.success || reply.http_status != Some(200) {
            return Err(
                json!({"reason":"lookup failed","http_status":reply.http_status,"page":page}),
            );
        }
        let Some(parsed) = reply.parsed.as_ref().and_then(Value::as_object) else {
            return Err(json!({"reason":"lookup response was malformed","page":page}));
        };
        let Some(items) = parsed.get("items").and_then(Value::as_array) else {
            return Err(json!({"reason":"lookup response was malformed","page":page}));
        };
        let Some(page_info) = parsed.get("page").and_then(Value::as_object) else {
            return Err(json!({"reason":"lookup pagination contract was invalid","page":page}));
        };
        let (Some(total), Some(observed_page), Some(page_size)) = (
            page_info.get("total").and_then(Value::as_u64),
            page_info.get("page").and_then(Value::as_u64),
            page_info.get("page_size").and_then(Value::as_u64),
        ) else {
            return Err(json!({"reason":"lookup pagination contract was invalid","page":page}));
        };
        let offset = (page - 1).saturating_mul(LOOKUP_PAGE_SIZE) as u64;
        let expected_items = total
            .checked_sub(offset)
            .map(|remaining| remaining.min(LOOKUP_PAGE_SIZE as u64) as usize);
        if total > MAX_LOOKUP_ITEMS as u64
            || observed_page != page as u64
            || page_size != LOOKUP_PAGE_SIZE as u64
            || expected_items != Some(items.len())
        {
            return Err(
                json!({"reason":"lookup pagination contract was invalid","page":page,"total":total,"observed_page":observed_page,"observed_page_size":page_size}),
            );
        }
        for item in items {
            let Some(object) = item.as_object() else {
                return Err(json!({"reason":"lookup item was malformed","page":page}));
            };
            if object.get("name").and_then(Value::as_str) == Some(value)
                || object.get("id").and_then(Value::as_str) == Some(value)
            {
                matches.push(item.clone());
            }
        }
        if offset + items.len() as u64 >= total {
            return Ok(matches);
        }
    }
    Err(json!({"reason":"lookup pagination exceeded safety limit","page":MAX_LOOKUP_PAGES + 1}))
}

fn preflight_failure(row: &TagCsvRow, resource: Option<&str>, failure: Value) -> Value {
    let mut value = json!({"row":row.row_number,"tag":row.tag_name});
    if let Some(resource) = resource {
        value["resource"] = json!(resource);
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
        "csv_file":details.get("csv_file"), "row_count":details.get("row_count").and_then(Value::as_u64).unwrap_or(0),
        "dry_run":details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        "skipped_existing_tag_count":details.get("skipped_existing_tag_count").and_then(Value::as_u64).unwrap_or(0),
        "created_tag_count":details.get("created_tag_count").and_then(Value::as_u64).unwrap_or(0),
        "assigned_resource_count":details.get("assigned_resource_count").and_then(Value::as_u64).unwrap_or(0),
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.status-only"),
            "Native CSV tag creation passed; details summarized.".into(),
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
            json!({"page":{"page":page,"page_size":LOOKUP_PAGE_SIZE,"total":total},"items":items}),
        )
    }
    fn rows() -> Vec<TagCsvRow> {
        parse_rows(b"TARGET,ops,managed,target-one\n").unwrap()
    }

    #[test]
    fn parsing_report_rule_and_bounds() {
        let parsed = parse_rows(b"target,ops,managed,target-one,,target-two\n").unwrap();
        assert_eq!(parsed[0].resource_type, "target");
        assert_eq!(parsed[0].tag_name, "ops:managed:TARGET");
        assert!(parse_rows(b",,\n").unwrap_err().contains("blank"));
        assert!(parse_rows(b"TARGET,ops\n").is_err());
        assert!(
            parse_rows(b"OTHER,ops,description\n")
                .unwrap_err()
                .contains("unsupported")
        );
        assert!(
            parse_rows(b"REPORT,ops,description\n")
                .unwrap_err()
                .contains("exact report UUID")
        );
        assert!(
            parse_rows(b"REPORT,ops,description,not-a-uuid\n")
                .unwrap_err()
                .contains("exact report UUID")
        );
        assert!(parse_rows(b"TARGET,ops,description,a,b,c,d,e,f,g,h,i,j,k\n").is_err());
        assert!(
            parse_rows(
                format!("TARGET,{},description\n", "x".repeat(MAX_FIELD_BYTES + 1)).as_bytes()
            )
            .is_err()
        );
        let too_many_rows = "TASK,ops,description\n".repeat(MAX_ROWS + 1);
        assert!(
            parse_rows(too_many_rows.as_bytes())
                .unwrap_err()
                .contains("at most 4095")
        );
    }

    #[test]
    fn securely_loads_bounded_tag_csv_rows() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("yafvsctl-tag-csv-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("tags.csv");
        fs::write(&path, "TARGET,ops,managed,target-one\n").unwrap();
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
    fn dry_run_and_refusal_never_call_api() {
        let api = FakeApi::new(Vec::new());
        let dry_run = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tags.csv"),
            rows(),
            false,
            true,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(dry_run.status, "pass");
        assert_eq!(
            dry_run.details.as_ref().unwrap()["planned_tags"][0]["tag"]["name"],
            "ops:managed:TARGET"
        );
        let refused = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tags.csv"),
            rows(),
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
    fn resolves_resources_and_skips_existing_and_duplicate_tags() {
        let rows = parse_rows(
            b"TARGET,ops,managed,target-one\nTARGET,ops,managed,target-one\nTASK,old,legacy\n",
        )
        .unwrap();
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(
                1,
                1,
                json!([{"id":"11111111-1111-4111-8111-111111111111","name":"target-one"}]),
            ),
            page(
                1,
                1,
                json!([{"id":"22222222-2222-4222-8222-222222222222","name":"old:legacy:TASK"}]),
            ),
            reply(201, json!({"id":"33333333-3333-4333-8333-333333333333"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tags.csv"),
            rows,
            true,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "pass");
        let details = result.details.unwrap();
        assert_eq!(details["created_tag_count"], 1);
        assert_eq!(details["skipped_existing_tag_count"], 2);
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[3].2.as_ref().unwrap()["resource_ids"],
            json!(["11111111-1111-4111-8111-111111111111"])
        );
    }
    #[test]
    fn lookup_pagination_and_malformed_contracts_are_bounded() {
        let api = FakeApi::new(vec![
            page(
                1,
                101,
                json!(vec![
                    json!({"id":"00000000-0000-4000-8000-000000000000","name":"near"});
                    100
                ]),
            ),
            page(
                2,
                101,
                json!([{"id":"11111111-1111-4111-8111-111111111111","name":"needle"}]),
            ),
        ]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        assert_eq!(
            lookup_exact(
                Path::new("/srv/YAFVS"),
                "/api/v1/tags",
                "needle",
                &Runner,
                &api,
                &mut findings,
                &mut config,
                &mut requests
            )
            .unwrap()
            .len(),
            1
        );
        assert_eq!(requests, 2);
        let malformed = FakeApi::new(vec![reply(
            200,
            json!({"page":{"page":1,"page_size":99,"total":0},"items":[]}),
        )]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        assert!(
            lookup_exact(
                Path::new("/srv/YAFVS"),
                "/api/v1/tags",
                "needle",
                &Runner,
                &malformed,
                &mut findings,
                &mut config,
                &mut requests
            )
            .unwrap_err()["reason"]
                .as_str()
                .unwrap()
                .contains("pagination")
        );
        let limited = FakeApi::new(Vec::new());
        let mut requests = MAX_LOOKUP_REQUESTS;
        assert!(
            lookup_exact(
                Path::new("/srv/YAFVS"),
                "/api/v1/tags",
                "x",
                &Runner,
                &limited,
                &mut findings,
                &mut config,
                &mut requests
            )
            .unwrap_err()["reason"]
                .as_str()
                .unwrap()
                .contains("safety limit")
        );
    }
    #[test]
    fn malformed_ids_request_cap_partial_success_and_status_only() {
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(1, 1, json!([{"id":"not-a-uuid","name":"target-one"}])),
        ]);
        let rejected = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tags.csv"),
            rows(),
            true,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(rejected.status, "fail");
        assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));
        let huge = TagCsvRow {
            row_number: 1,
            resource_type: "target",
            value: "x".repeat(MAX_FILE_BYTES),
            tag_name: "x".repeat(MAX_FILE_BYTES),
            resource_names: Vec::new(),
        };
        assert!(super::super::serialize_request_body(&tag_body(&huge, "now", &[])).is_err());
        let rows =
            parse_rows(b"TARGET,one,first\nTARGET,two,second\nTARGET,three,third\n").unwrap();
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            reply(201, json!({"id":"11111111-1111-4111-8111-111111111111"})),
            reply(201, json!({"id":"not-a-uuid"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("tags.csv"),
            rows,
            true,
            false,
            true,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["created_tag_count"], 1);
        assert!(
            result
                .details
                .as_ref()
                .unwrap()
                .get("created_tag_ids")
                .is_none()
        );
        assert_eq!(api.calls.lock().unwrap().len(), 5);
    }
}
