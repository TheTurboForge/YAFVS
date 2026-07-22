// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Private, bounded CSV alert import with complete metadata preflight.

#[cfg(test)]
use super::ApiReply;
use super::{GuardedApi, TargetApi};
use crate::commands::common::metadata;
use crate::commands::direct_api::{
    OPERATOR_UUID_ENV, direct_runtime_environment, environment_value, validate_operator_uuid,
};
use crate::commands::native_runtime::percent_encode_component;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::OnceLock;

const COMMAND: &str = "native-alerts-from-csv";
const COMMENT: &str = "Created by YAFVS native-alerts-from-csv";
const MAX_FILE_BYTES: usize = 1_048_576;
const MAX_ROWS: usize = 1000;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_SUBJECT_BYTES: usize = 80;
const MAX_MESSAGE_BYTES: usize = 2000;
const MAX_REPORTED: usize = 10;
const LOOKUP_PAGE_SIZE: usize = 100;
const MAX_LOOKUP_PAGES: usize = 200;
const MAX_LOOKUP_ITEMS: usize = LOOKUP_PAGE_SIZE * MAX_LOOKUP_PAGES;
const MAX_API_REQUESTS: usize = 4095;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Email,
    Smb,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::Smb => "SMB",
        }
    }
}

struct AlertRow {
    row_number: usize,
    name: String,
    method: Method,
    status: String,
    report_format_name: String,
    from_address: String,
    to_address: String,
    subject: String,
    message: String,
    notice: String,
    credential_name: String,
    share_path: String,
    file_path: String,
    report_format_id: String,
    credential_id: String,
}

pub fn command_native_alerts_from_csv(
    root: &Path,
    csv_file: &Path,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    if dry_run && allow_write_control {
        return finish(
            envelope(
                root,
                &SystemCommandRunner,
                "Native alert CSV operation rejected before runtime access.",
                vec![Finding::new(
                    "fail",
                    &format!("{COMMAND}.arguments"),
                    "--dry-run and --allow-write-control cannot be used together.".into(),
                )],
                base_details(allow_write_control),
            ),
            status_only,
        );
    }
    let rows = match load_rows(csv_file) {
        Ok(rows) => rows,
        Err(error) => {
            return finish(
                envelope(
                    root,
                    &SystemCommandRunner,
                    "Native alert CSV operation rejected before runtime access.",
                    vec![Finding::new("fail", &format!("{COMMAND}.rows"), error)],
                    base_details(allow_write_control),
                ),
                status_only,
            );
        }
    };
    command_with(
        root,
        rows,
        allow_write_control,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
        None,
    )
}

fn base_details(allow_write_control: bool) -> Value {
    json!({"row_count":0,"email_row_count":0,"smb_row_count":0,"dry_run":!allow_write_control,"skipped_existing_alert_count":0,"preflight_failure_count":0,"created_alert_count":0,"create_failure_count":0,"indeterminate_alert_count":0,"unattempted_alert_count":0})
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

fn is_control(value: char) -> bool {
    matches!(value as u32, 0..=31 | 127..=159)
}

fn text(row: usize, label: &str, value: &str, max: usize) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(is_control) {
        return Err(format!(
            "row {row} {label} must be non-empty printable text"
        ));
    }
    Ok(value.into())
}

fn message(row: usize, value: &str) -> Result<String, String> {
    if value.len() > MAX_MESSAGE_BYTES
        || value
            .chars()
            .any(|c| is_control(c) && !matches!(c, '\r' | '\n' | '\t'))
    {
        return Err(format!(
            "row {row} message must be UTF-8 text up to {MAX_MESSAGE_BYTES} bytes"
        ));
    }
    Ok(value.into())
}

fn share_path(row: usize, value: &str) -> Result<String, String> {
    let value = text(row, "SMB share path", value, MAX_TEXT_BYTES)?;
    static UNC: OnceLock<Regex> = OnceLock::new();
    if !UNC
        .get_or_init(|| {
            Regex::new(r"^(?:\\\\|//)[^:?<>|]+(?:\\|/)[^:?<>|]+$").expect("static UNC regex")
        })
        .is_match(&value)
    {
        return Err(format!(
            "row {row} SMB share path must be exactly a network host/share without invalid characters"
        ));
    }
    Ok(value)
}

fn smb_file_path(row: usize, folder: &str, name: &str) -> Result<String, String> {
    let folder = text(row, "SMB report folder", folder, MAX_TEXT_BYTES)?;
    let name = text(row, "SMB report name", name, MAX_TEXT_BYTES)?;
    if matches!(name.as_str(), "." | "..")
        || name.contains(['/', '\\'])
        || name.ends_with('.')
        || name.chars().any(|c| ":?<>|".contains(c))
    {
        return Err(format!("row {row} SMB report name must be a file name"));
    }
    if folder.split(['/', '\\']).any(|part| {
        matches!(part, "" | "." | "..")
            || part.ends_with('.')
            || part.chars().any(|c| ":?<>|".contains(c))
    }) {
        return Err(format!(
            "row {row} SMB report folder must not contain empty, traversal, terminal-dot, or invalid-character segments"
        ));
    }
    Ok(format!("{}/{}", folder.trim_end_matches('/'), name))
}

fn parse_row(number: usize, record: &csv::StringRecord) -> Result<AlertRow, String> {
    if record.len() != 9 {
        return Err(format!(
            "row {number} must have exactly 9 positional columns"
        ));
    }
    let name = text(number, "alert name", &record[0], MAX_TEXT_BYTES)?;
    let method = match record[1].trim() {
        "EMAIL" => Method::Email,
        "SMB" => Method::Smb,
        _ => {
            return Err(format!(
                "row {number} alert method must be exactly EMAIL or SMB"
            ));
        }
    };
    let status = record[8].trim();
    if !matches!(
        status,
        "Delete Requested"
            | "Ultimate Delete Requested"
            | "Ultimate Delete Waiting"
            | "Delete Waiting"
            | "Done"
            | "New"
            | "Requested"
            | "Running"
            | "Queued"
            | "Stop Requested"
            | "Stop Waiting"
            | "Stopped"
            | "Processing"
            | "Interrupted"
    ) {
        return Err(format!("row {number} alert status is not supported"));
    }
    let report_format_name = text(number, "report format name", &record[7], MAX_TEXT_BYTES)?;
    let mut row = AlertRow {
        row_number: number,
        name,
        method,
        status: status.into(),
        report_format_name,
        from_address: String::new(),
        to_address: String::new(),
        subject: String::new(),
        message: String::new(),
        notice: String::new(),
        credential_name: String::new(),
        share_path: String::new(),
        file_path: String::new(),
        report_format_id: String::new(),
        credential_id: String::new(),
    };
    match method {
        Method::Email => {
            row.from_address = text(number, "EMAIL sender", &record[2], MAX_TEXT_BYTES)?;
            row.to_address = text(number, "EMAIL recipient", &record[3], MAX_TEXT_BYTES)?;
            row.subject = text(number, "EMAIL subject", &record[4], MAX_SUBJECT_BYTES)?;
            row.message = message(number, &record[5])?;
            row.notice = match record[6].trim() {
                "0" => "include",
                "1" => "simple",
                "2" => "attach",
                _ => {
                    return Err(format!(
                        "row {number} EMAIL notice must be exactly 0, 1, or 2"
                    ));
                }
            }
            .into();
        }
        Method::Smb => {
            row.credential_name = text(number, "SMB credential name", &record[2], MAX_TEXT_BYTES)?;
            row.share_path = share_path(number, &record[3])?;
            row.file_path = smb_file_path(number, &record[5], &record[4])?;
        }
    }
    Ok(row)
}

fn load_rows(path: &Path) -> Result<Vec<AlertRow>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "failed to read alert CSV file as UTF-8".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "failed to read alert CSV file as UTF-8".to_string())?;
    if !metadata.file_type().is_file() {
        return Err("alert CSV file must be a regular file".into());
    }
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(format!("alert CSV file exceeds {MAX_FILE_BYTES} bytes"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_FILE_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| "failed to read alert CSV file as UTF-8".to_string())?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!("alert CSV file exceeds {MAX_FILE_BYTES} bytes"));
    }
    std::str::from_utf8(&bytes)
        .map_err(|_| "failed to read alert CSV file as UTF-8".to_string())?;
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(bytes.as_slice());
    let mut rows = Vec::new();
    let mut names = HashMap::new();
    for (index, record) in reader.records().enumerate() {
        let number = index + 1;
        if number > MAX_ROWS {
            return Err(format!("alert CSV file exceeds {MAX_ROWS} rows"));
        }
        let record = record.map_err(|_| "failed to read alert CSV file as UTF-8".to_string())?;
        if record.is_empty() || record.iter().all(|value| value.trim().is_empty()) {
            return Err(format!("row {number} must not be empty"));
        }
        let row = parse_row(number, &record)?;
        if let Some(first) = names.insert(row.name.clone(), number) {
            return Err(format!("duplicate alert name in rows {first} and {number}"));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        Err("alert CSV file is empty".into())
    } else {
        Ok(rows)
    }
}

fn operator_id(root: &Path, runner: &dyn CommandRunner) -> Result<String, String> {
    let environment = direct_runtime_environment(root, runner)
        .map_err(|_| "direct native API runtime configuration is unavailable".to_string())?;
    let value = environment_value(&environment, OPERATOR_UUID_ENV).unwrap_or_default();
    validate_operator_uuid(value.trim(), OPERATOR_UUID_ENV)
        .map_err(|_| "active operator metadata is unavailable or malformed".to_string())
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    mut rows: Vec<AlertRow>,
    allow_write_control: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    supplied_operator: Option<&str>,
) -> ResultEnvelope {
    let mut details = base_details(allow_write_control);
    details["row_count"] = json!(rows.len());
    details["email_row_count"] = json!(
        rows.iter()
            .filter(|row| row.method == Method::Email)
            .count()
    );
    details["smb_row_count"] = json!(rows.iter().filter(|row| row.method == Method::Smb).count());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{COMMAND}.rows"),
        format!(
            "Preflight loaded {} alert row(s) without runtime access.",
            rows.len()
        ),
    )];
    if !allow_write_control {
        findings.push(Finding::new("pass", &format!("{COMMAND}.dry-run"), "Dry run completed strict local alert preflight without runtime access or delivery payload output.".into()));
        return finish(
            envelope(
                root,
                runner,
                "Native alert CSV dry run completed.",
                findings,
                details,
            ),
            status_only,
        );
    }
    let operator = match supplied_operator
        .map(str::to_string)
        .or_else(|| operator_id(root, runner).ok())
    {
        Some(value) => value,
        None => {
            increment(&mut details, "preflight_failure_count");
            findings.push(Finding::new("fail", &format!("{COMMAND}.preflight"), "Native metadata resolution was incomplete, ambiguous, or incompatible; no alert writes were attempted.".into()));
            return finish(
                envelope(
                    root,
                    runner,
                    "Native alert CSV operation rejected before alert writes.",
                    findings,
                    details,
                ),
                status_only,
            );
        }
    };
    let mut selected = Vec::new();
    let mut failures = Vec::new();
    let mut config_recorded = false;
    let mut requests = 0usize;
    for (index, row) in rows.iter_mut().enumerate() {
        let alerts = fetch_exact(
            root,
            "/api/v1/alerts",
            &row.name,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut requests,
        );
        let formats = fetch_exact(
            root,
            "/api/v1/report-formats",
            &row.report_format_name,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut requests,
        );
        let credentials = if row.method == Method::Smb {
            Some(fetch_exact(
                root,
                "/api/v1/credentials",
                &row.credential_name,
                runner,
                api,
                &mut findings,
                &mut config_recorded,
                &mut requests,
            ))
        } else {
            None
        };
        let valid = match (alerts, formats, credentials) {
            (Ok(alerts), Ok(formats), None) => prepare(row, alerts, formats, None, &operator),
            (Ok(alerts), Ok(formats), Some(Ok(credentials))) => {
                prepare(row, alerts, formats, Some(credentials), &operator)
            }
            _ => false,
        };
        if !valid {
            increment(&mut details, "preflight_failure_count");
            if failures.len() < MAX_REPORTED {
                failures.push(json!({"row":row.row_number,"reason":"metadata lookup was incomplete, ambiguous, or incompatible"}));
            }
        } else if row.report_format_id.is_empty() {
            increment(&mut details, "skipped_existing_alert_count");
        } else {
            selected.push(index);
        }
    }
    if count(&details, "preflight_failure_count") != 0 {
        details["preflight_failures"] = Value::Array(failures);
        findings.push(Finding::new("fail", &format!("{COMMAND}.preflight"), "Native metadata resolution was incomplete, ambiguous, or incompatible; no alert writes were attempted.".into()));
        return finish(
            envelope(
                root,
                runner,
                "Native alert CSV operation rejected before alert writes.",
                findings,
                details,
            ),
            status_only,
        );
    }
    findings.push(Finding::new("pass", &format!("{COMMAND}.preflight"), "Resolved all alert and report-format references and confirmed every SMB credential is operator-owned and SMB-compatible before writes.".into()));
    for (position, index) in selected.iter().copied().enumerate() {
        let row = &rows[index];
        let body = body(row);
        let reply = api.call(
            root,
            "/api/v1/alerts",
            "POST",
            Some(&body),
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        );
        let mut http_status = None;
        let mut accepted = false;
        let mut indeterminate = false;
        match reply {
            Ok(reply) => {
                http_status = reply.http_status;
                if !config_recorded {
                    findings.push(reply.config);
                    config_recorded = true;
                }
                accepted = reply.output.success
                    && !reply.oversized
                    && reply.http_status == Some(201)
                    && acknowledgement_is_safe(reply.parsed.as_ref(), row);
                if !accepted {
                    indeterminate = !reply.output.success
                        || reply.http_status.is_none()
                        || reply
                            .http_status
                            .is_some_and(|status| status >= 500 || (200..300).contains(&status));
                }
            }
            Err(rejected) => {
                append_rejection(&mut findings, rejected, &mut config_recorded);
                indeterminate = true;
            }
        }
        if accepted {
            increment(&mut details, "created_alert_count");
            continue;
        }
        increment(&mut details, "create_failure_count");
        if indeterminate {
            increment(&mut details, "indeterminate_alert_count");
        }
        details["unattempted_alert_count"] = json!(selected.len() - position - 1);
        let message = if http_status == Some(405) {
            "Direct native API write control is disabled; no alert was created and later rows were not attempted."
        } else if indeterminate {
            "A native alert create request failed with an indeterminate server outcome; later rows were not attempted and prior writes remain committed."
        } else {
            "A native alert create request failed; later rows were not attempted and prior writes remain committed."
        };
        findings.push(Finding::new("fail", &format!("{COMMAND}.create"), message.into()).with_details(json!({"row":row.row_number,"http_status":http_status,"outcome":if indeterminate {"indeterminate"} else {"rejected"}})));
        break;
    }
    if count(&details, "create_failure_count") == 0 {
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.create"),
            format!(
                "Created {} alert(s) through the native API.",
                count(&details, "created_alert_count")
            ),
        ));
    }
    let failed = count(&details, "create_failure_count") != 0;
    finish(
        envelope(
            root,
            runner,
            if failed {
                "Native alert CSV operation failed."
            } else {
                "Native alert CSV operation completed."
            },
            findings,
            details,
        ),
        status_only,
    )
}

fn prepare(
    row: &mut AlertRow,
    alerts: Vec<Value>,
    formats: Vec<Value>,
    credentials: Option<Vec<Value>>,
    operator: &str,
) -> bool {
    if alerts.len() > 1 || formats.len() != 1 {
        return false;
    }
    if alerts.len() == 1 {
        return true;
    }
    let Some(format_id) = formats[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| validate_operator_uuid(id, "report format id").is_ok())
    else {
        return false;
    };
    row.report_format_id = format_id.into();
    if row.method == Method::Smb {
        let Some(credentials) = credentials else {
            return false;
        };
        if credentials.len() != 1 {
            return false;
        }
        let credential = &credentials[0];
        let Some(id) = credential
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| validate_operator_uuid(id, "credential id").is_ok())
        else {
            return false;
        };
        if credential.get("credential_type").and_then(Value::as_str) != Some("up")
            || credential.get("owner_id").and_then(Value::as_str) != Some(operator)
            || credential.get("smb_compatible").and_then(Value::as_bool) != Some(true)
        {
            return false;
        }
        row.credential_id = id.into();
    }
    true
}

fn body(row: &AlertRow) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("method".into(), json!(row.method.name()));
    object.insert("name".into(), json!(row.name));
    object.insert("comment".into(), json!(COMMENT));
    object.insert("active".into(), json!(true));
    object.insert("status".into(), json!(row.status));
    match row.method {
        Method::Email => {
            object.insert("to_address".into(), json!(row.to_address));
            object.insert("from_address".into(), json!(row.from_address));
            object.insert("subject".into(), json!(row.subject));
            object.insert("notice".into(), json!(row.notice));
            object.insert("message".into(), json!(row.message));
            if row.notice != "simple" {
                object.insert("report_format_id".into(), json!(row.report_format_id));
            }
        }
        Method::Smb => {
            object.insert("smb_credential_id".into(), json!(row.credential_id));
            object.insert("smb_share_path".into(), json!(row.share_path));
            object.insert("smb_file_path".into(), json!(row.file_path));
            object.insert("report_format_id".into(), json!(row.report_format_id));
            object.insert("smb_max_protocol".into(), json!("default"));
        }
    }
    Value::Object(object)
}

#[allow(clippy::too_many_arguments)]
fn fetch_exact(
    root: &Path,
    endpoint: &str,
    name: &str,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
    requests: &mut usize,
) -> Result<Vec<Value>, String> {
    let encoded = percent_encode_component(name);
    let mut matches = Vec::new();
    let mut expected_total = None;
    for page in 1..=MAX_LOOKUP_PAGES {
        if *requests >= MAX_API_REQUESTS {
            return Err("lookup request safety limit exceeded".into());
        }
        *requests += 1;
        let path = format!("{endpoint}?filter={encoded}&page={page}&page_size={LOOKUP_PAGE_SIZE}");
        let reply = api
            .call(
                root,
                &path,
                "GET",
                None,
                &format!("{COMMAND}.request-body"),
                &format!("{COMMAND}.direct-config-shape"),
                &format!("{COMMAND}.direct-token-strength"),
                runner,
            )
            .map_err(|rejected| {
                append_rejection(findings, rejected, config_recorded);
                "lookup failed".to_string()
            })?;
        if !*config_recorded {
            findings.push(reply.config);
            *config_recorded = true;
        }
        if !reply.output.success || reply.oversized || reply.http_status != Some(200) {
            return Err("lookup failed".into());
        }
        let Some(object) = reply.parsed.as_ref().and_then(Value::as_object) else {
            return Err("lookup response was malformed".into());
        };
        let (Some(items), Some(info)) = (
            object.get("items").and_then(Value::as_array),
            object.get("page").and_then(Value::as_object),
        ) else {
            return Err("lookup response was malformed".into());
        };
        let (Some(total), Some(actual_page), Some(actual_size)) = (
            info.get("total").and_then(Value::as_u64),
            info.get("page").and_then(Value::as_u64),
            info.get("page_size").and_then(Value::as_u64),
        ) else {
            return Err("lookup pagination was malformed".into());
        };
        let offset = (page - 1).saturating_mul(LOOKUP_PAGE_SIZE) as u64;
        let expected = total
            .checked_sub(offset)
            .map(|left| left.min(LOOKUP_PAGE_SIZE as u64) as usize);
        if total > MAX_LOOKUP_ITEMS as u64
            || expected_total.is_some_and(|value| value != total)
            || actual_page != page as u64
            || actual_size != LOOKUP_PAGE_SIZE as u64
            || expected != Some(items.len())
        {
            return Err("lookup pagination contract was invalid".into());
        }
        expected_total = Some(total);
        for item in items {
            if !item.is_object() {
                return Err("lookup item was malformed".into());
            }
            if item.get("name").and_then(Value::as_str) == Some(name) {
                matches.push(item.clone());
            }
        }
        if offset + items.len() as u64 >= total {
            return Ok(matches);
        }
    }
    Err("lookup pagination exceeded safety limit".into())
}

fn append_rejection(findings: &mut Vec<Finding>, mut rejected: Vec<Finding>, recorded: &mut bool) {
    let config = format!("{COMMAND}.direct-config-shape");
    if *recorded {
        rejected.retain(|finding| finding.check != config);
    } else if rejected.iter().any(|finding| finding.check == config) {
        *recorded = true;
    }
    findings.extend(rejected.into_iter().take(MAX_REPORTED));
}

fn acknowledgement_is_safe(parsed: Option<&Value>, row: &AlertRow) -> bool {
    let Some(object) = parsed.and_then(Value::as_object) else {
        return false;
    };
    if object
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|id| validate_operator_uuid(id, "alert id").is_err())
        || object.get("name").and_then(Value::as_str) != Some(row.name.as_str())
    {
        return false;
    }
    let method = object
        .get("method")
        .and_then(Value::as_object)
        .and_then(|value| value.get("type"))
        .or_else(|| object.get("method_type"))
        .and_then(Value::as_str);
    if method.is_none_or(|value| !value.eq_ignore_ascii_case(row.method.name())) {
        return false;
    }
    let values = [
        &row.from_address,
        &row.to_address,
        &row.subject,
        &row.message,
        &row.credential_name,
        &row.share_path,
        &row.file_path,
    ];
    !contains_delivery(object, &values, false)
}

fn contains_delivery(
    object: &serde_json::Map<String, Value>,
    values: &[&String],
    method_object: bool,
) -> bool {
    object.iter().any(|(key, value)| {
        let lower = key.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "from_address"
                | "to_address"
                | "subject"
                | "message"
                | "email_from_address"
                | "email_to_address"
                | "email_subject"
                | "email_message"
                | "smb_credential"
                | "smb_credential_name"
                | "smb_credential_id"
                | "smb_share_path"
                | "smb_file_path"
        ) {
            return true;
        }
        if key == "method" {
            return value
                .as_object()
                .is_some_and(|nested| contains_delivery(nested, values, true));
        }
        let permitted_method_type = ((method_object && key == "type")
            || (!method_object && key == "method_type"))
            && value.as_str().is_some_and(|value| {
                value.eq_ignore_ascii_case("SMB") || value.eq_ignore_ascii_case("EMAIL")
            });
        if !permitted_method_type && value_has_delivery(value, values) {
            return true;
        }
        match value {
            Value::Object(nested) => contains_delivery(nested, values, false),
            Value::Array(items) => items.iter().any(|item| value_has_delivery(item, values)),
            _ => false,
        }
    })
}

fn value_has_delivery(value: &Value, values: &[&String]) -> bool {
    match value {
        Value::String(value) => values
            .iter()
            .any(|submitted| !submitted.is_empty() && value.contains(submitted.as_str())),
        Value::Array(items) => items.iter().any(|item| value_has_delivery(item, values)),
        Value::Object(object) => contains_delivery(object, values, false),
        _ => false,
    }
}

fn increment(details: &mut Value, key: &str) {
    details[key] = json!(count(details, key) + 1);
}
fn count(details: &Value, key: &str) -> u64 {
    details.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn finish(mut result: ResultEnvelope, status_only: bool) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    result.metadata.repo_root.clear();
    let details = result
        .details
        .as_ref()
        .cloned()
        .unwrap_or_else(|| json!({}));
    result.details = Some(
        json!({"row_count":count(&details,"row_count"),"email_row_count":count(&details,"email_row_count"),"smb_row_count":count(&details,"smb_row_count"),"dry_run":details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),"skipped_existing_alert_count":count(&details,"skipped_existing_alert_count"),"preflight_failure_count":count(&details,"preflight_failure_count"),"created_alert_count":count(&details,"created_alert_count"),"create_failure_count":count(&details,"create_failure_count"),"indeterminate_alert_count":count(&details,"indeterminate_alert_count"),"unattempted_alert_count":count(&details,"unattempted_alert_count")}),
    );
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.status-only"),
            "Native alert CSV operation passed; details summarized.".into(),
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
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
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
            _: &Path,
            path: &str,
            method: &str,
            body: Option<&Value>,
            _: &str,
            _: &str,
            _: &str,
            _: &dyn CommandRunner,
        ) -> Result<ApiReply, Vec<Finding>> {
            self.calls.lock().unwrap().push((
                path.into(),
                method.into(),
                body.cloned().unwrap_or(Value::Null),
            ));
            self.replies.lock().unwrap().pop_front().unwrap()
        }
    }
    fn reply(status: i64, parsed: Value) -> Result<ApiReply, Vec<Finding>> {
        Ok(ApiReply {
            output: ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            },
            parsed: Some(parsed),
            http_status: Some(status),
            oversized: false,
            config: Finding::new("pass", "config", "ok".into()),
        })
    }
    fn list(items: Value) -> Result<ApiReply, Vec<Finding>> {
        let total = items.as_array().map(Vec::len).unwrap_or(0);
        reply(
            200,
            json!({"items":items,"page":{"page":1,"page_size":100,"total":total}}),
        )
    }
    fn row(number: usize, name: &str, method: Method) -> AlertRow {
        AlertRow {
            row_number: number,
            name: name.into(),
            method,
            status: "Done".into(),
            report_format_name: "CSV Results".into(),
            from_address: "from@example.invalid".into(),
            to_address: "to@example.invalid".into(),
            subject: "subject".into(),
            message: "message".into(),
            notice: "simple".into(),
            credential_name: "SMB".into(),
            share_path: "//server/share".into(),
            file_path: "reports/report.csv".into(),
            report_format_id: String::new(),
            credential_id: String::new(),
        }
    }
    fn temp() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("yafvs-alert-{}-{unique}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn secure_parsing_and_smb_controls_are_strict() {
        let dir = temp();
        let csv = dir.join("alerts.csv");
        fs::write(&csv, "A,EMAIL,a,b,s,m,1,CSV Results,Done\n").unwrap();
        assert_eq!(load_rows(&csv).unwrap().len(), 1);
        for value in [
            "\n",
            "A,OTHER,a,b,s,m,1,CSV Results,Done\n",
            "A,SMB,c,//server/share,r,f,,CSV Results,Done\nA,SMB,c,//server/share,r,f,,CSV Results,Done\n",
            "A,EMAIL,a,b,s,visible\u{85},1,CSV Results,Done\n",
        ] {
            fs::write(&csv, value).unwrap();
            assert!(load_rows(&csv).is_err());
        }
        assert!(share_path(1, "//server/sha?re").is_err());
        assert!(smb_file_path(1, "reports.", "r").is_err());
        fs::write(&csv, vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
        assert!(load_rows(&csv).is_err());
        fs::remove_file(&csv).unwrap();
        std::os::unix::fs::symlink("/dev/null", &csv).unwrap();
        assert!(load_rows(&csv).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn dry_run_and_contradictory_flags_are_offline_and_redacted() {
        let api = FakeApi::new(vec![]);
        let mut input = row(1, "A", Method::Email);
        input.subject = "private subject".into();
        input.message = "private message".into();
        let result = command_with(
            Path::new("/private/root"),
            vec![input],
            false,
            true,
            &Runner,
            &api,
            Some("00000000-0000-4000-8000-000000000002"),
        );
        assert_eq!(result.status, "pass");
        assert!(api.calls.lock().unwrap().is_empty());
        let rendered = serde_json::to_string(&result).unwrap();
        for secret in [
            "from@example.invalid",
            "to@example.invalid",
            "private subject",
            "private message",
            "/private/root",
        ] {
            assert!(!rendered.contains(secret));
        }
        let result = command_native_alerts_from_csv(
            Path::new("/root"),
            Path::new("/missing"),
            true,
            true,
            true,
        );
        assert_eq!(result.findings[0].check, format!("{COMMAND}.arguments"));
    }
    #[test]
    fn exact_email_and_smb_bodies_follow_complete_preflight() {
        let id = "00000000-0000-4000-8000-000000000001";
        let operator = "00000000-0000-4000-8000-000000000002";
        let api = FakeApi::new(vec![
            list(json!([])),
            list(json!([{ "id":id,"name":"CSV Results"}])),
            list(json!([])),
            list(json!([{ "id":id,"name":"CSV Results"}])),
            list(
                json!([{ "id":id,"name":"SMB","credential_type":"up","owner_id":operator,"smb_compatible":true}]),
            ),
            reply(
                201,
                json!({"id":id,"name":"Mail","method":{"type":"EMAIL"}}),
            ),
            reply(201, json!({"id":id,"name":"Share","method":{"type":"SMB"}})),
        ]);
        let mut mail = row(1, "Mail", Method::Email);
        mail.notice = "attach".into();
        let share = row(2, "Share", Method::Smb);
        let result = command_with(
            Path::new("/root"),
            vec![mail, share],
            true,
            false,
            &Runner,
            &api,
            Some(operator),
        );
        assert_eq!(result.status, "pass");
        let calls = api.calls.lock().unwrap();
        assert_eq!(
            calls[5].2,
            json!({
                "method":"EMAIL",
                "name":"Mail",
                "comment":COMMENT,
                "active":true,
                "status":"Done",
                "to_address":"to@example.invalid",
                "from_address":"from@example.invalid",
                "subject":"subject",
                "notice":"attach",
                "message":"message",
                "report_format_id":id,
            })
        );
        assert_eq!(
            calls[6].2,
            json!({
                "method":"SMB",
                "name":"Share",
                "comment":COMMENT,
                "active":true,
                "status":"Done",
                "smb_credential_id":id,
                "smb_share_path":"//server/share",
                "smb_file_path":"reports/report.csv",
                "report_format_id":id,
                "smb_max_protocol":"default",
            })
        );
    }
    #[test]
    fn email_notice_modes_control_report_format_shape_exactly() {
        let id = "00000000-0000-4000-8000-000000000001";
        let mut simple = row(1, "Simple", Method::Email);
        simple.report_format_id = id.into();
        assert!(body(&simple).get("report_format_id").is_none());
        let mut include = row(2, "Include", Method::Email);
        include.notice = "include".into();
        include.report_format_id = id.into();
        assert_eq!(body(&include)["report_format_id"], id);
        let mut attach = row(3, "Attach", Method::Email);
        attach.notice = "attach".into();
        attach.report_format_id = id.into();
        assert_eq!(body(&attach)["report_format_id"], id);
    }
    #[test]
    fn metadata_failure_blocks_all_posts_and_paging_is_strict() {
        let api = FakeApi::new(vec![
            list(json!([])),
            list(json!([{ "id":"bad","name":"CSV Results"}])),
        ]);
        let result = command_with(
            Path::new("/root"),
            vec![row(1, "Mail", Method::Email)],
            true,
            false,
            &Runner,
            &api,
            Some("00000000-0000-4000-8000-000000000002"),
        );
        assert_eq!(result.status, "fail");
        assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));

        let malformed = FakeApi::new(vec![
            reply(200, json!({"items":[],"page":{}})),
            reply(200, json!({"items":[],"page":{}})),
        ]);
        let result = command_with(
            Path::new("/root"),
            vec![row(1, "Malformed", Method::Email)],
            true,
            false,
            &Runner,
            &malformed,
            Some("00000000-0000-4000-8000-000000000002"),
        );
        assert_eq!(result.status, "fail");
        assert!(
            malformed
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.1 == "GET")
        );
    }
    #[test]
    fn incompatible_smb_credential_metadata_blocks_every_post() {
        let id = "00000000-0000-4000-8000-000000000001";
        let operator = "00000000-0000-4000-8000-000000000002";
        for credentials in [
            json!([{ "id":id,"name":"SMB","credential_type":"usk","owner_id":operator,"smb_compatible":true}]),
            json!([{ "id":id,"name":"SMB","credential_type":"up","owner_id":"00000000-0000-4000-8000-000000000003","smb_compatible":true}]),
            json!([{ "id":id,"name":"SMB","credential_type":"up","owner_id":operator,"smb_compatible":false}]),
            json!([
                { "id":id,"name":"SMB","credential_type":"up","owner_id":operator,"smb_compatible":true},
                { "id":"00000000-0000-4000-8000-000000000004","name":"SMB","credential_type":"up","owner_id":operator,"smb_compatible":true}
            ]),
        ] {
            let api = FakeApi::new(vec![
                list(json!([])),
                list(json!([{ "id":id,"name":"CSV Results"}])),
                list(credentials),
            ]);
            let result = command_with(
                Path::new("/root"),
                vec![row(1, "Share", Method::Smb)],
                true,
                false,
                &Runner,
                &api,
                Some(operator),
            );
            assert_eq!(result.status, "fail");
            assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));
        }
    }
    #[test]
    fn acknowledgement_rejects_nested_echoes_but_permits_credential_named_smb() {
        let mut smb = row(1, "Share", Method::Smb);
        smb.credential_name = "SMB".into();
        let valid = json!({"id":"00000000-0000-4000-8000-000000000001","name":"Share","method":{"type":"SMB"}});
        assert!(acknowledgement_is_safe(Some(&valid), &smb));
        let flat =
            json!({"id":"00000000-0000-4000-8000-000000000001","name":"Share","method_type":"SMB"});
        assert!(acknowledgement_is_safe(Some(&flat), &smb));
        let email = row(2, "Mail", Method::Email);
        let title_case = json!({"id":"00000000-0000-4000-8000-000000000001","name":"Mail","method":{"type":"Email"}});
        assert!(acknowledgement_is_safe(Some(&title_case), &email));
        let echoed = json!({"id":"00000000-0000-4000-8000-000000000001","name":"Share","method":{"type":"SMB"},"nested":{"smb_share_path":"redacted"}});
        assert!(!acknowledgement_is_safe(Some(&echoed), &smb));
    }
    #[test]
    fn create_failure_is_sequential_and_indeterminate() {
        let id = "00000000-0000-4000-8000-000000000001";
        let api = FakeApi::new(vec![
            list(json!([])),
            list(json!([{ "id":id,"name":"CSV Results"}])),
            list(json!([])),
            list(json!([{ "id":id,"name":"CSV Results"}])),
            list(json!([])),
            list(json!([{ "id":id,"name":"CSV Results"}])),
            reply(
                201,
                json!({"id":id,"name":"First","method":{"type":"EMAIL"}}),
            ),
            reply(
                201,
                json!({"id":id,"name":"Second","method":{"type":"EMAIL"},"nested":{"message":"redacted"}}),
            ),
        ]);
        let result = command_with(
            Path::new("/root"),
            vec![
                row(1, "First", Method::Email),
                row(2, "Second", Method::Email),
                row(3, "Last", Method::Email),
            ],
            true,
            true,
            &Runner,
            &api,
            Some("00000000-0000-4000-8000-000000000002"),
        );
        let details = result.details.unwrap();
        assert_eq!(details["created_alert_count"], 1);
        assert_eq!(details["indeterminate_alert_count"], 1);
        assert_eq!(details["unattempted_alert_count"], 1);
        assert!(
            !serde_json::to_string(&details)
                .unwrap()
                .contains("from@example.invalid")
        );
    }
}
