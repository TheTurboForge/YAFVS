// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Private, bounded CSV credential import with complete preflight.

use super::{ApiReply, GuardedApi, TargetApi};
use crate::commands::common::metadata;
use crate::commands::native_runtime::percent_encode_component;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Take};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const COMMAND: &str = "native-credentials-from-csv";
const COMMENT: &str = "Created by YAFVS native-credentials-from-csv";
const MAX_TEXT_BYTES: usize = 4096;
const MAX_SECRET_BYTES: usize = 4096;
const MAX_PRIVATE_KEY_BYTES: usize = 32_768;
const MAX_DECODED_BYTES: usize = 48_800;
const MAX_FILE_BYTES: usize = 1_048_576;
const MAX_ROWS: usize = 1000;
const MAX_AGGREGATE_SECRET_BYTES: usize = 8_388_608;
const MAX_REPORTED: usize = 10;
const LOOKUP_PAGE_SIZE: usize = 100;
const MAX_LOOKUP_PAGES: usize = 200;
const MAX_LOOKUP_ITEMS: usize = LOOKUP_PAGE_SIZE * MAX_LOOKUP_PAGES;
const MAX_API_REQUESTS: usize = 4095;
const REDACTED_KEY_PATH: &str = "<redacted-local-key-path>";

#[derive(Clone, Copy, PartialEq, Eq)]
enum CredentialKind {
    Up,
    Ssh,
}

impl CredentialKind {
    fn csv_name(self) -> &'static str {
        match self {
            Self::Up => "UP",
            Self::Ssh => "SSH",
        }
    }

    fn api_name(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Ssh => "usk",
        }
    }
}

struct CredentialRow {
    row_number: usize,
    name: String,
    kind: CredentialKind,
    login: String,
    secret: String,
    private_key: String,
}

impl Drop for CredentialRow {
    fn drop(&mut self) {
        self.secret.clear();
        self.private_key.clear();
    }
}

pub fn command_native_credentials_from_csv(
    root: &Path,
    csv_file: &Path,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    if dry_run && allow_write_control {
        return finish_status(
            envelope(
                root,
                &SystemCommandRunner,
                "Native credential CSV operation rejected before runtime access.",
                vec![Finding::new(
                    "fail",
                    &format!("{COMMAND}.arguments"),
                    "--dry-run and --allow-write-control cannot be used together.".into(),
                )],
                base_details(csv_file, allow_write_control),
            ),
            status_only,
        );
    }
    let rows = match load_rows(csv_file) {
        Ok(rows) => rows,
        Err(error) => {
            return finish_status(
                envelope(
                    root,
                    &SystemCommandRunner,
                    "Native credential CSV operation rejected before runtime access.",
                    vec![
                        Finding::new("fail", &format!("{COMMAND}.rows"), error)
                            .with_details(json!({"csv_file": safe_file_name(csv_file)})),
                    ],
                    base_details(csv_file, allow_write_control),
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

fn base_details(csv_file: &Path, allow_write_control: bool) -> Value {
    json!({
        "csv_file": safe_file_name(csv_file),
        "row_count": 0,
        "dry_run": !allow_write_control,
        "skipped_existing_credential_count": 0,
        "preflight_failure_count": 0,
        "created_credential_count": 0,
        "create_failure_count": 0,
        "indeterminate_credential_count": 0,
        "unattempted_credential_count": 0,
    })
}

fn safe_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("<redacted-local-file>")
        .to_string()
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

fn c_name(name: &OsStr) -> Result<CString, String> {
    CString::new(name.as_bytes()).map_err(|_| "path contains a NUL byte".into())
}

fn open_at(directory: &File, name: &OsStr, flags: i32) -> Result<File, String> {
    let name = c_name(name)?;
    let raw = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn open_parent(path: &Path) -> Result<File, String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| "could not safely open credential CSV directory".into())
}

fn read_bounded(mut file: File, limit: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = file
        .metadata()
        .map_err(|_| format!("could not inspect {label}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular file"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!("{label} has unsafe group or world permissions"));
    }
    if metadata.len() > limit as u64 {
        return Err(format!("{label} exceeds {limit} bytes"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = (&mut file).take((limit + 1) as u64);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| format!("could not safely read {label}"))?;
    if bytes.len() > limit {
        return Err(format!("{label} exceeds {limit} bytes"));
    }
    Ok(bytes)
}

fn read_csv_bytes(csv_file: &Path, parent: &File) -> Result<Vec<u8>, String> {
    let name = csv_file
        .file_name()
        .ok_or_else(|| "credential CSV file name is invalid".to_string())?;
    let file = open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
    .map_err(|error| format!("could not safely read credential CSV file: {error}"))?;
    read_bounded(file, MAX_FILE_BYTES, "credential CSV file")
}

fn read_private_key(row: usize, parent: &File, value: &str) -> Result<String, String> {
    let path = Path::new(value.trim());
    if value.trim().is_empty() {
        return Err(format!("row {row} must include an SSH key path"));
    }
    if path.is_absolute() {
        return Err(format!(
            "row {row} SSH key path must stay within the credential CSV directory"
        ));
    }
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::Normal(name) => parts.push(name),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "row {row} SSH key path must stay within the credential CSV directory"
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(format!(
            "row {row} SSH key path must stay within the credential CSV directory"
        ));
    }
    let mut directory = parent
        .try_clone()
        .map_err(|_| format!("row {row} could not safely read SSH key {REDACTED_KEY_PATH}"))?;
    for part in &parts[..parts.len() - 1] {
        directory = open_at(
            &directory,
            part,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .map_err(|_| {
            format!("row {row} SSH key path must not contain symlinks or non-directory components")
        })?;
    }
    let file = open_at(
        &directory,
        parts[parts.len() - 1],
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    )
    .map_err(|_| format!("row {row} could not safely read SSH key {REDACTED_KEY_PATH}"))?;
    let bytes = read_bounded(
        file,
        MAX_PRIVATE_KEY_BYTES,
        &format!("row {row} SSH key {REDACTED_KEY_PATH}"),
    )?;
    let key = String::from_utf8(bytes)
        .map_err(|_| format!("row {row} SSH key {REDACTED_KEY_PATH} must be UTF-8 text"))?;
    if key.is_empty()
        || key.contains('\0')
        || key
            .chars()
            .any(|character| is_control(character) && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(format!(
            "row {row} SSH key {REDACTED_KEY_PATH} must be non-empty key text without unsupported control characters"
        ));
    }
    Ok(key)
}

fn validate_text(row: usize, label: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("row {row} must include a {label}"));
    }
    if value.len() > MAX_TEXT_BYTES || value.chars().any(is_control) {
        return Err(format!(
            "row {row} {label} must be printable text up to {MAX_TEXT_BYTES} bytes"
        ));
    }
    Ok(value.into())
}

fn validate_secret(row: usize, label: &str, value: &str, required: bool) -> Result<String, String> {
    if (required && value.is_empty()) || value.len() > MAX_SECRET_BYTES || value.contains('\0') {
        let requirement = if required { "non-empty " } else { "" };
        return Err(format!(
            "row {row} {label} must be {requirement}UTF-8 text up to {MAX_SECRET_BYTES} bytes without NUL bytes"
        ));
    }
    Ok(value.into())
}

fn is_control(character: char) -> bool {
    matches!(character as u32, 0..=31 | 127..=159)
}

fn load_rows(csv_file: &Path) -> Result<Vec<CredentialRow>, String> {
    let parent = open_parent(csv_file)?;
    let bytes = read_csv_bytes(csv_file, &parent)?;
    std::str::from_utf8(&bytes)
        .map_err(|_| "failed to read credential CSV file as UTF-8".to_string())?;
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes.as_slice());
    let mut rows = Vec::new();
    let mut names = HashMap::new();
    let mut aggregate_secret_bytes = 0usize;
    for (index, record) in reader.records().enumerate() {
        let row_number = index + 1;
        if row_number > MAX_ROWS {
            return Err(format!("credential CSV file exceeds {MAX_ROWS} rows"));
        }
        let record =
            record.map_err(|_| "failed to read credential CSV file as UTF-8".to_string())?;
        if record.is_empty() || record.iter().all(|field| field.trim().is_empty()) {
            return Err(format!("row {row_number} must not be empty"));
        }
        if record.len() < 2 {
            return Err(format!(
                "row {row_number} must include name and credential type"
            ));
        }
        let kind = match record[1].trim() {
            "UP" => CredentialKind::Up,
            "SSH" => CredentialKind::Ssh,
            "SNMP" | "ESX" => {
                return Err(format!(
                    "row {row_number} credential type {} is explicitly unsupported because the inherited branch was incomplete",
                    record[1].trim()
                ));
            }
            _ => {
                return Err(format!(
                    "row {row_number} credential type must be exactly UP or SSH"
                ));
            }
        };
        let expected = if kind == CredentialKind::Up { 4 } else { 5 };
        if record.len() != expected {
            let shape = if kind == CredentialKind::Up {
                "name,type,login,password"
            } else {
                "name,type,login,passphrase,key-path"
            };
            return Err(format!(
                "row {row_number} must have exactly {expected} positional columns: {shape}"
            ));
        }
        let name = validate_text(row_number, "credential name", &record[0])?;
        if let Some(first) = names.insert(name.clone(), row_number) {
            return Err(format!(
                "duplicate credential name in rows {first} and {row_number}"
            ));
        }
        let login = validate_text(row_number, "credential login", &record[2])?;
        let (secret, private_key) = if kind == CredentialKind::Up {
            (
                validate_secret(row_number, "password", &record[3], true)?,
                String::new(),
            )
        } else {
            (
                validate_secret(row_number, "passphrase", &record[3], false)?,
                read_private_key(row_number, &parent, &record[4])?,
            )
        };
        let decoded = name.len() + COMMENT.len() + login.len() + secret.len() + private_key.len();
        if decoded > MAX_DECODED_BYTES {
            return Err(format!(
                "row {row_number} combined credential fields exceed {MAX_DECODED_BYTES} decoded bytes"
            ));
        }
        aggregate_secret_bytes = aggregate_secret_bytes
            .checked_add(secret.len() + private_key.len())
            .ok_or_else(|| "credential CSV secret material byte count overflowed".to_string())?;
        if aggregate_secret_bytes > MAX_AGGREGATE_SECRET_BYTES {
            return Err(format!(
                "credential CSV secret material exceeds {MAX_AGGREGATE_SECRET_BYTES} bytes"
            ));
        }
        rows.push(CredentialRow {
            row_number,
            name,
            kind,
            login,
            secret,
            private_key,
        });
    }
    if rows.is_empty() {
        Err("credential CSV file is empty".into())
    } else {
        Ok(rows)
    }
}

fn safe_summary(row: &CredentialRow) -> Value {
    json!({
        "row": row.row_number,
        "credential_type": row.kind.csv_name(),
        "private_key_bytes": row.private_key.len(),
        "has_passphrase": if row.kind == CredentialKind::Ssh {
            Some(!row.secret.is_empty())
        } else {
            None
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    csv_file: &Path,
    mut rows: Vec<CredentialRow>,
    allow_write_control: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
) -> ResultEnvelope {
    let mut details = base_details(csv_file, allow_write_control);
    details["row_count"] = json!(rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{COMMAND}.rows"),
        format!(
            "Preflight loaded {} credential row(s) without runtime access.",
            rows.len()
        ),
    )];
    if !allow_write_control {
        details["planned_credential_count"] = json!(rows.len());
        details["planned_credentials"] =
            Value::Array(rows.iter().take(MAX_REPORTED).map(safe_summary).collect());
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.dry-run"),
            "Dry run completed strict local credential preflight without runtime access or secret output."
                .into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native credential CSV dry run completed.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut selected = Vec::new();
    let mut config_recorded = false;
    let mut request_count = 0usize;
    let mut failures = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        match fetch_existing(
            root,
            &row.name,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut request_count,
        ) {
            Ok(matches) if matches.len() > 1 => {
                increment(&mut details, "preflight_failure_count");
                if failures.len() < MAX_REPORTED {
                    failures.push(json!({
                        "row": row.row_number,
                        "reason": "credential name lookup was ambiguous",
                        "match_count": matches.len(),
                    }));
                }
            }
            Ok(matches) if matches.len() == 1 => {
                increment(&mut details, "skipped_existing_credential_count");
            }
            Ok(_) => selected.push(index),
            Err(failure) => {
                increment(&mut details, "preflight_failure_count");
                if failures.len() < MAX_REPORTED {
                    failures.push(json!({"row": row.row_number, "reason": failure}));
                }
            }
        }
    }
    if count(&details, "preflight_failure_count") != 0 {
        details["preflight_failures"] = Value::Array(failures);
        findings.push(Finding::new(
            "fail",
            &format!("{COMMAND}.preflight"),
            "Existing credential lookup failed before credential writes.".into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native credential CSV operation rejected before credential writes.",
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
            "Resolved all credential names before writes; selected {} row(s) and skipped {} existing credential(s).",
            selected.len(),
            count(&details, "skipped_existing_credential_count")
        ),
    ));

    for (position, row_index) in selected.iter().copied().enumerate() {
        let row = &mut rows[row_index];
        let body = if row.kind == CredentialKind::Up {
            json!({
                "name": row.name,
                "comment": COMMENT,
                "login": row.login,
                "type": row.kind.api_name(),
                "password": row.secret,
            })
        } else {
            json!({
                "name": row.name,
                "comment": COMMENT,
                "login": row.login,
                "type": row.kind.api_name(),
                "passphrase": row.secret,
                "private_key": row.private_key,
            })
        };
        let reply = api.call(
            root,
            "/api/v1/credentials",
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
                    && response_is_redacted(
                        reply.parsed.as_ref(),
                        row,
                        &row.secret,
                        &row.private_key,
                    );
                if !accepted {
                    indeterminate = !reply.output.success
                        || reply.http_status.is_none()
                        || reply.http_status.is_some_and(|status| status >= 500)
                        || reply
                            .http_status
                            .is_some_and(|status| (200..300).contains(&status));
                }
            }
            Err(mut rejected) => {
                if config_recorded {
                    rejected.retain(|finding| {
                        finding.check != format!("{COMMAND}.direct-config-shape")
                    });
                }
                findings.extend(rejected.into_iter().take(MAX_REPORTED));
                indeterminate = true;
            }
        }
        row.secret.clear();
        row.private_key.clear();
        if accepted {
            increment(&mut details, "created_credential_count");
            continue;
        }
        increment(&mut details, "create_failure_count");
        if indeterminate {
            increment(&mut details, "indeterminate_credential_count");
        }
        details["unattempted_credential_count"] = json!(selected.len() - position - 1);
        let message = if http_status == Some(405) {
            "Direct native API write control is disabled; no credential was created and later rows were not attempted."
        } else if indeterminate {
            "A native credential create request failed with an indeterminate server outcome; later rows were not attempted and prior writes remain committed."
        } else {
            "A native credential create request failed; later rows were not attempted and prior writes remain committed."
        };
        findings.push(
            Finding::new("fail", &format!("{COMMAND}.create"), message.into()).with_details(
                json!({
                    "row": row.row_number,
                    "http_status": http_status,
                    "outcome": if indeterminate {"indeterminate"} else {"rejected"},
                }),
            ),
        );
        break;
    }
    if count(&details, "create_failure_count") == 0 {
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.create"),
            format!(
                "Created {} credential(s) through the native API.",
                count(&details, "created_credential_count")
            ),
        ));
    }
    let failed = count(&details, "create_failure_count") != 0;
    finish_status(
        envelope(
            root,
            runner,
            if failed {
                "Native credential CSV operation failed."
            } else {
                "Native credential CSV operation completed."
            },
            findings,
            details,
        ),
        status_only,
    )
}

#[allow(clippy::too_many_arguments)]
fn fetch_existing(
    root: &Path,
    name: &str,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
    request_count: &mut usize,
) -> Result<Vec<Value>, String> {
    let encoded = percent_encode_component(name);
    let mut matches = Vec::new();
    let mut expected_total = None;
    for page in 1..=MAX_LOOKUP_PAGES {
        if *request_count >= MAX_API_REQUESTS {
            return Err("lookup request safety limit exceeded".into());
        }
        *request_count += 1;
        let path = format!(
            "/api/v1/credentials?filter={encoded}&page={page}&page_size={LOOKUP_PAGE_SIZE}"
        );
        let reply = api.call(
            root,
            &path,
            "GET",
            None,
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        );
        let ApiReply {
            output,
            parsed,
            http_status,
            oversized,
            config,
        } = match reply {
            Ok(reply) => reply,
            Err(rejected) => {
                append_rejection(findings, rejected, config_recorded);
                return Err("lookup failed".into());
            }
        };
        if !*config_recorded {
            findings.push(config);
            *config_recorded = true;
        }
        if !output.success || oversized || http_status != Some(200) {
            return Err("lookup failed".into());
        }
        let Some(object) = parsed.as_ref().and_then(Value::as_object) else {
            return Err("lookup response was malformed".into());
        };
        let Some(items) = object.get("items").and_then(Value::as_array) else {
            return Err("lookup response was malformed".into());
        };
        let Some(page_info) = object.get("page").and_then(Value::as_object) else {
            return Err("lookup pagination was malformed".into());
        };
        let (Some(total), Some(observed_page), Some(observed_size)) = (
            page_info.get("total").and_then(Value::as_u64),
            page_info.get("page").and_then(Value::as_u64),
            page_info.get("page_size").and_then(Value::as_u64),
        ) else {
            return Err("lookup pagination was malformed".into());
        };
        let offset = (page - 1).saturating_mul(LOOKUP_PAGE_SIZE) as u64;
        let expected_items = total
            .checked_sub(offset)
            .map(|remaining| remaining.min(LOOKUP_PAGE_SIZE as u64) as usize);
        if total > MAX_LOOKUP_ITEMS as u64
            || expected_total.is_some_and(|expected| expected != total)
            || observed_page != page as u64
            || observed_size != LOOKUP_PAGE_SIZE as u64
            || expected_items != Some(items.len())
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

fn append_rejection(
    findings: &mut Vec<Finding>,
    mut rejected: Vec<Finding>,
    config_recorded: &mut bool,
) {
    let config_check = format!("{COMMAND}.direct-config-shape");
    if *config_recorded {
        rejected.retain(|finding| finding.check != config_check);
    } else if rejected.iter().any(|finding| finding.check == config_check) {
        *config_recorded = true;
    }
    findings.extend(rejected.into_iter().take(MAX_REPORTED));
}

fn response_is_redacted(
    parsed: Option<&Value>,
    row: &CredentialRow,
    submitted_secret: &str,
    submitted_private_key: &str,
) -> bool {
    let Some(object) = parsed.and_then(Value::as_object) else {
        return false;
    };
    let valid_id = object
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| super::validate_operator_uuid(id, "credential id").is_ok());
    if !valid_id
        || object.get("name").and_then(Value::as_str) != Some(row.name.as_str())
        || object.get("credential_type").and_then(Value::as_str) != Some(row.kind.api_name())
    {
        return false;
    }
    !contains_sensitive(object, submitted_secret, submitted_private_key)
}

fn contains_sensitive(
    object: &serde_json::Map<String, Value>,
    submitted_secret: &str,
    submitted_private_key: &str,
) -> bool {
    object.iter().any(|(key, value)| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "password" | "passphrase" | "private_key" | "secret"
        ) || value_contains_sensitive(value, submitted_secret, submitted_private_key)
    })
}

fn value_contains_sensitive(value: &Value, secret: &str, private_key: &str) -> bool {
    match value {
        Value::String(value) => {
            (!secret.is_empty() && value.contains(secret))
                || (!private_key.is_empty() && value.contains(private_key))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_sensitive(value, secret, private_key)),
        Value::Object(object) => contains_sensitive(object, secret, private_key),
        _ => false,
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
        "dry_run": details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        "skipped_existing_credential_count": count(&details, "skipped_existing_credential_count"),
        "preflight_failure_count": count(&details, "preflight_failure_count"),
        "created_credential_count": count(&details, "created_credential_count"),
        "create_failure_count": count(&details, "create_failure_count"),
        "indeterminate_credential_count": count(&details, "indeterminate_credential_count"),
        "unattempted_credential_count": count(&details, "unattempted_credential_count"),
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.status-only"),
            "Native credential CSV operation passed; details summarized.".into(),
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
    use std::os::unix::fs::PermissionsExt;
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
            config: Finding::new("pass", "direct-config", "ok".into()),
        })
    }

    fn list(items: Value) -> Result<ApiReply, Vec<Finding>> {
        let total = items.as_array().map(Vec::len).unwrap_or_default();
        reply(
            200,
            json!({
                "items": items,
                "page": {"page": 1, "page_size": 100, "total": total},
            }),
        )
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "yafvsctl-credential-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn private_write(path: &Path, content: impl AsRef<[u8]>) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn load_error(path: &Path) -> String {
        match load_rows(path) {
            Ok(_) => panic!("credential input unexpectedly passed"),
            Err(error) => error,
        }
    }

    fn up(row: usize, name: &str, secret: &str) -> CredentialRow {
        CredentialRow {
            row_number: row,
            name: name.into(),
            kind: CredentialKind::Up,
            login: "operator".into(),
            secret: secret.into(),
            private_key: String::new(),
        }
    }

    #[test]
    fn securely_loads_private_up_and_ssh_rows() {
        let directory = temp_dir("load");
        fs::create_dir(directory.join("keys")).unwrap();
        let key = directory.join("keys/id");
        private_write(&key, "-----BEGIN PRIVATE KEY-----\nvalue\n");
        let csv = directory.join("credentials.csv");
        private_write(
            &csv,
            "Password,UP,operator,pw\nKey,SSH,operator,phrase,./keys/id\n",
        );
        let rows = load_rows(&csv).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind.csv_name(), "UP");
        assert_eq!(rows[1].kind.csv_name(), "SSH");
        assert!(rows[1].private_key.contains("PRIVATE KEY"));

        fs::set_permissions(&csv, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_error(&csv).contains("unsafe group or world"));
        fs::set_permissions(&csv, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&key, directory.join("key-link")).unwrap();
        private_write(&csv, "Key,SSH,operator,phrase,key-link\n");
        assert!(load_error(&csv).contains(REDACTED_KEY_PATH));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_shapes_duplicates_controls_traversal_and_bounds() {
        let directory = temp_dir("reject");
        let csv = directory.join("credentials.csv");
        for (content, expected) in [
            ("\n", "credential CSV file is empty"),
            ("Name,SNMP,operator,secret\n", "explicitly unsupported"),
            ("Name,up,operator,secret\n", "exactly UP or SSH"),
            ("Name,UP,operator\n", "exactly 4 positional"),
            (
                "Name,UP,operator,one\nName,UP,operator,two\n",
                "duplicate credential name",
            ),
            ("Bad\u{7f},UP,operator,secret\n", "printable text"),
            ("Name,SSH,operator,,../key\n", "must stay within"),
        ] {
            private_write(&csv, content);
            let error = load_error(&csv);
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
        private_write(
            &csv,
            format!("Name,UP,operator,{}\n", "x".repeat(MAX_SECRET_BYTES + 1)),
        );
        assert!(load_error(&csv).contains("without NUL"));
        private_write(&csv, vec![b'x'; MAX_FILE_BYTES + 1]);
        assert!(load_error(&csv).contains("exceeds"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn argument_and_dry_run_paths_make_no_api_calls_or_secret_output() {
        let api = FakeApi::new(vec![]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("/private/credentials.csv"),
            vec![up(1, "Name", "do-not-print")],
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "pass");
        assert!(api.calls.lock().unwrap().is_empty());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-print")
        );

        let result = command_native_credentials_from_csv(
            Path::new("/srv/YAFVS"),
            Path::new("/missing"),
            true,
            true,
            false,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.findings[0].check,
            "native-credentials-from-csv.arguments"
        );
    }

    #[test]
    fn complete_preflight_skips_existing_and_posts_exact_secret_bodies() {
        let ssh_key = "-----BEGIN PRIVATE KEY-----\nkey\n";
        let mut ssh = up(2, "SSH", "phrase");
        ssh.kind = CredentialKind::Ssh;
        ssh.private_key = ssh_key.into();
        let api = FakeApi::new(vec![
            list(json!([{"id":"11111111-1111-4111-8111-111111111111","name":"Existing"}])),
            list(json!([])),
            list(json!([])),
            reply(
                201,
                json!({
                    "id":"22222222-2222-4222-8222-222222222222",
                    "name":"UP",
                    "credential_type":"up",
                }),
            ),
            reply(
                201,
                json!({
                    "id":"33333333-3333-4333-8333-333333333333",
                    "name":"SSH",
                    "credential_type":"usk",
                }),
            ),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("credentials.csv"),
            vec![up(1, "Existing", "skip"), up(2, "UP", "password"), ssh],
            true,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "pass");
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["skipped_existing_credential_count"], 1);
        assert_eq!(details["created_credential_count"], 2);
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[3].2["password"], "password");
        assert_eq!(calls[4].2["passphrase"], "phrase");
        assert_eq!(calls[4].2["private_key"], ssh_key);
        assert!(!serde_json::to_string(&result).unwrap().contains("password"));
        assert!(!serde_json::to_string(&result).unwrap().contains(ssh_key));
    }

    #[test]
    fn lookup_ambiguity_blocks_every_post() {
        let api = FakeApi::new(vec![
            list(json!([
                {"id":"11111111-1111-4111-8111-111111111111","name":"Duplicate"},
                {"id":"22222222-2222-4222-8222-222222222222","name":"Duplicate"},
            ])),
            list(json!([])),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("credentials.csv"),
            vec![up(1, "Duplicate", "one"), up(2, "Other", "two")],
            true,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.details.as_ref().unwrap()["preflight_failure_count"],
            1
        );
        assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));
    }

    #[test]
    fn strict_acknowledgement_rejects_echoed_nested_and_sensitive_fields() {
        let row = up(1, "Created", "päss\\word");
        let valid = json!({
            "id":"11111111-1111-4111-8111-111111111111",
            "name":"Created",
            "credential_type":"up",
            "owner":"admin",
        });
        assert!(response_is_redacted(Some(&valid), &row, &row.secret, ""));
        let echoed = json!({
            "id":"11111111-1111-4111-8111-111111111111",
            "name":"Created",
            "credential_type":"up",
            "diagnostic":{"echo":format!("value {}", row.secret)},
        });
        assert!(!response_is_redacted(Some(&echoed), &row, &row.secret, ""));
        let named = json!({
            "id":"11111111-1111-4111-8111-111111111111",
            "name":"Created",
            "credential_type":"up",
            "nested":{"password":"redacted"},
        });
        assert!(!response_is_redacted(Some(&named), &row, &row.secret, ""));
    }

    #[test]
    fn rejected_and_indeterminate_create_stop_later_rows_without_leakage() {
        for (reply_value, indeterminate) in [
            (reply(405, json!({"error":"disabled"})), false),
            (
                reply(
                    201,
                    json!({
                        "id":"11111111-1111-4111-8111-111111111111",
                        "name":"First",
                        "credential_type":"up",
                        "diagnostic":"first-secret",
                    }),
                ),
                true,
            ),
        ] {
            let api = FakeApi::new(vec![list(json!([])), list(json!([])), reply_value]);
            let result = command_with(
                Path::new("/srv/YAFVS"),
                Path::new("credentials.csv"),
                vec![
                    up(1, "First", "first-secret"),
                    up(2, "Second", "second-secret"),
                ],
                true,
                false,
                &Runner,
                &api,
            );
            assert_eq!(result.status, "fail");
            let details = result.details.as_ref().unwrap();
            assert_eq!(details["create_failure_count"], 1);
            assert_eq!(details["unattempted_credential_count"], 1);
            assert_eq!(
                details["indeterminate_credential_count"],
                u64::from(indeterminate)
            );
            assert_eq!(api.calls.lock().unwrap().len(), 3);
            let serialized = serde_json::to_string(&result).unwrap();
            assert!(!serialized.contains("first-secret"));
            assert!(!serialized.contains("second-secret"));
        }
    }

    #[test]
    fn status_only_is_count_only_and_non_disclosing() {
        let api = FakeApi::new(vec![
            list(json!([])),
            reply(
                201,
                json!({
                    "id":"11111111-1111-4111-8111-111111111111",
                    "name":"Created",
                    "credential_type":"up",
                }),
            ),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("/private/credentials.csv"),
            vec![up(1, "Created", "secret-value")],
            true,
            true,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].check,
            "native-credentials-from-csv.status-only"
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("/private/"));
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("Created"));
    }
}
