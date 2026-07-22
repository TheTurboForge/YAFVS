// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const COMMAND: &str = "native-bulk-modify-schedules";
const MAX_LIMIT: usize = 500;
const PAGE_SIZE: usize = 500;
const MAX_PAGES: usize = 1_000;
const MAX_TIMEZONE_BYTES: usize = 256;
const MAX_ICALENDAR_BYTES: usize = 32_768;
#[cfg(test)]
const DEFAULT_MAX: usize = 100;

#[derive(Serialize)]
struct PatchRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icalendar: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
pub fn command_native_bulk_modify_schedules(
    root: &Path,
    filter: &str,
    timezone: Option<&str>,
    icalendar_file: Option<&Path>,
    max_schedules: usize,
    dry_run: bool,
    allow_write_control: bool,
    confirm_snapshot: Option<&str>,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        root,
        filter,
        timezone,
        icalendar_file,
        max_schedules,
        dry_run,
        allow_write_control,
        confirm_snapshot,
        status_only,
        &SystemCommandRunner,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_with_runner(
    root: &Path,
    filter: &str,
    timezone: Option<&str>,
    icalendar_file: Option<&Path>,
    max_schedules: usize,
    dry_run: bool,
    allow_write_control: bool,
    confirm_snapshot: Option<&str>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let (filter, timezone, icalendar) = match validate_arguments(
        filter,
        timezone,
        icalendar_file,
        max_schedules,
        dry_run,
        allow_write_control,
        confirm_snapshot,
    ) {
        Ok(values) => values,
        Err(message) => {
            return result(
                root,
                runner,
                "Native bulk schedule mutation rejected before runtime access.",
                vec![Finding::new(
                    "fail",
                    "native-bulk-modify-schedules.arguments",
                    message,
                )],
                default_details(max_schedules, dry_run),
                status_only,
            );
        }
    };
    let mut call = |path: &str, method: &str, body: Option<&str>| {
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            body,
            "native-bulk-modify-schedules.direct-config-shape",
            "native-bulk-modify-schedules.direct-token-strength",
            runner,
        )
    };
    execute(
        root,
        &filter,
        timezone.as_deref(),
        icalendar.as_deref(),
        icalendar_file,
        max_schedules,
        dry_run,
        confirm_snapshot,
        status_only,
        runner,
        &mut call,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_arguments(
    filter: &str,
    timezone: Option<&str>,
    icalendar_file: Option<&Path>,
    max_schedules: usize,
    dry_run: bool,
    allow_write_control: bool,
    confirm_snapshot: Option<&str>,
) -> Result<(String, Option<String>, Option<String>), String> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Err(
            "--filter must be non-empty; broad unfiltered schedule mutation is refused".into(),
        );
    }
    if filter.len() > 1_024 || !printable_line(filter) {
        return Err("--filter must be one printable line up to 1024 bytes".into());
    }
    let timezone = timezone
        .map(str::trim)
        .map(|value| {
            if value.is_empty() {
                Err("--timezone must be non-empty when supplied".to_string())
            } else if value.len() > MAX_TIMEZONE_BYTES || !printable_line(value) {
                Err(format!(
                    "--timezone must be one printable line up to {MAX_TIMEZONE_BYTES} bytes"
                ))
            } else {
                Ok(value.to_string())
            }
        })
        .transpose()?;
    let icalendar = icalendar_file.map(load_icalendar).transpose()?;
    if timezone.is_none() && icalendar.is_none() {
        return Err("supply at least one of --timezone or --icalendar-file".into());
    }
    if !(1..=MAX_LIMIT).contains(&max_schedules) {
        return Err(format!("--max-schedules must be between 1 and {MAX_LIMIT}"));
    }
    if !dry_run && !allow_write_control {
        return Err("modifying schedules requires --allow-write-control".into());
    }
    if !dry_run && !confirm_snapshot.is_some_and(is_sha256) {
        return Err(
            "modifying schedules requires --confirm-snapshot with the SHA-256 from a fresh --dry-run"
                .into(),
        );
    }
    Ok((filter.to_string(), timezone, icalendar))
}

fn printable_line(value: &str) -> bool {
    value
        .chars()
        .all(|character| !character.is_control() && !matches!(character, '\u{2028}' | '\u{2029}'))
}

fn load_icalendar(path: &Path) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read iCalendar file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read iCalendar file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("--icalendar-file must name a readable regular file".into());
    }
    if metadata.len() > MAX_ICALENDAR_BYTES as u64 {
        return Err(format!(
            "--icalendar-file exceeds {MAX_ICALENDAR_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_ICALENDAR_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read iCalendar file: {error}"))?;
    if bytes.len() > MAX_ICALENDAR_BYTES {
        return Err(format!(
            "--icalendar-file exceeds {MAX_ICALENDAR_BYTES} bytes"
        ));
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| "failed to read iCalendar file: input is not UTF-8".to_string())?;
    if value.trim().is_empty() {
        return Err("--icalendar-file must not be empty".into());
    }
    if value.chars().any(|character| {
        let code = character as u32;
        (code < 32 || (127..=159).contains(&code)) && !matches!(character, '\r' | '\n' | '\t')
    }) {
        return Err("--icalendar-file contains unsupported control characters".into());
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn execute<F>(
    root: &Path,
    filter: &str,
    timezone: Option<&str>,
    icalendar: Option<&str>,
    icalendar_file: Option<&Path>,
    max_schedules: usize,
    dry_run: bool,
    confirm_snapshot: Option<&str>,
    status_only: bool,
    runner: &dyn CommandRunner,
    call: &mut F,
) -> ResultEnvelope
where
    F: FnMut(&str, &str, Option<&str>) -> Result<GuardedDirectApiCall, Vec<Finding>>,
{
    let mut details = default_details(max_schedules, dry_run);
    let (schedule_ids, config) = match fetch_snapshot(filter, max_schedules, call) {
        Ok(snapshot) => snapshot,
        Err((findings, reason)) => {
            return result(
                root,
                runner,
                "Native bulk schedule mutation stopped during snapshot collection.",
                findings
                    .into_iter()
                    .chain([Finding::new(
                        "fail",
                        "native-bulk-modify-schedules.snapshot",
                        "Native schedule snapshot failed; no PATCH requests were attempted.".into(),
                    )
                    .with_details(reason)])
                    .collect(),
                details,
                status_only,
            );
        }
    };
    let (filter_sha256, icalendar_sha256, snapshot_sha256) =
        snapshot_hashes(filter, &schedule_ids, timezone, icalendar);
    details["filter"] = json!(filter);
    details["filter_sha256"] = json!(filter_sha256);
    details["icalendar_file"] = json!(icalendar_file);
    details["icalendar_sha256"] = json!(icalendar_sha256);
    details["snapshot_sha256"] = json!(snapshot_sha256);
    details["matched_count"] = json!(schedule_ids.len());
    details["schedule_ids"] = json!(schedule_ids);
    details["timezone"] = json!(timezone);
    let mut findings = vec![
        config,
        Finding::new(
            "pass",
            "native-bulk-modify-schedules.snapshot",
            format!(
                "Snapshotted {} schedule UUID(s) deterministically.",
                schedule_ids.len()
            ),
        )
        .with_details(json!({
            "matched_count": schedule_ids.len(),
            "filter_sha256": filter_sha256,
            "icalendar_sha256": icalendar_sha256,
            "snapshot_sha256": snapshot_sha256,
        })),
    ];
    if dry_run {
        return result(
            root,
            runner,
            "Native bulk schedule mutation dry run completed; no PATCH requests were attempted.",
            findings,
            details,
            status_only,
        );
    }
    if !confirm_snapshot.is_some_and(|value| value.eq_ignore_ascii_case(&snapshot_sha256)) {
        findings.push(
            Finding::new(
                "fail",
                "native-bulk-modify-schedules.snapshot-confirmation",
                "Confirmed snapshot does not match the fresh native schedule snapshot; no PATCH requests were attempted.".into(),
            )
            .with_details(json!({"expected_snapshot_sha256": snapshot_sha256})),
        );
        return result(
            root,
            runner,
            "Native bulk schedule mutation rejected because the snapshot changed.",
            findings,
            details,
            status_only,
        );
    }
    findings.push(Finding::new(
        "pass",
        "native-bulk-modify-schedules.snapshot-confirmation",
        "Confirmed snapshot matches the fresh native schedule snapshot.".into(),
    ));
    let body = serde_json::to_string(&PatchRequest {
        timezone,
        icalendar,
    })
    .expect("validated schedule patch is serializable");

    for schedule_id in &schedule_ids {
        details["attempted_count"] = json!(count(&details, "attempted_count") + 1);
        let response = match call(
            &format!("/api/v1/schedules/{schedule_id}"),
            "PATCH",
            Some(&body),
        ) {
            Ok(response) => response,
            Err(_) => {
                return failed_patch(
                    root,
                    runner,
                    schedule_id,
                    "rejected-before-execution",
                    None,
                    &schedule_ids,
                    findings,
                    details,
                    status_only,
                );
            }
        };
        if confirmed_patch(&response, schedule_id) {
            details["succeeded_count"] = json!(count(&details, "succeeded_count") + 1);
            details["rows"].as_array_mut().expect("rows").push(
                json!({"schedule_id": schedule_id, "status": "succeeded", "http_status": 200}),
            );
            continue;
        }
        let outcome = if confirmed_rejection(&response) {
            "rejected"
        } else {
            "indeterminate"
        };
        return failed_patch(
            root,
            runner,
            schedule_id,
            outcome,
            response.http_status,
            &schedule_ids,
            findings,
            details,
            status_only,
        );
    }
    findings.push(Finding::new(
        "pass",
        "native-bulk-modify-schedules.patch",
        format!(
            "Patched {} schedule(s) sequentially through the native API.",
            count(&details, "succeeded_count")
        ),
    ));
    result(
        root,
        runner,
        &format!(
            "Native bulk schedule mutation patched all {} selected schedule(s).",
            count(&details, "succeeded_count")
        ),
        findings,
        details,
        status_only,
    )
}

#[allow(clippy::too_many_arguments)]
fn failed_patch(
    root: &Path,
    runner: &dyn CommandRunner,
    schedule_id: &str,
    outcome: &str,
    http_status: Option<i64>,
    schedule_ids: &[String],
    mut findings: Vec<Finding>,
    mut details: Value,
    status_only: bool,
) -> ResultEnvelope {
    details["failed_count"] = json!(1);
    details["unattempted_count"] = json!(
        schedule_ids
            .len()
            .saturating_sub(count(&details, "attempted_count") as usize)
    );
    details["rows"].as_array_mut().expect("rows").push(json!({
        "schedule_id": schedule_id,
        "status": outcome,
        "http_status": http_status,
    }));
    findings.push(
        Finding::new(
            "fail",
            &format!("native-bulk-modify-schedules.schedule.{schedule_id}"),
            if outcome == "indeterminate" {
                "Native API schedule PATCH outcome is indeterminate; it was not retried, prior successes remain committed, and remaining schedules were not attempted.".into()
            } else {
                "Native API schedule PATCH was rejected; it was not retried, prior successes remain committed, and remaining schedules were not attempted.".into()
            },
        )
        .with_details(json!({
            "schedule_id": schedule_id,
            "outcome": outcome,
            "http_status": http_status,
            "attempted_count": count(&details, "attempted_count"),
            "succeeded_count": count(&details, "succeeded_count"),
            "failed_count": 1,
            "unattempted_count": count(&details, "unattempted_count"),
        })),
    );
    result(
        root,
        runner,
        "Native bulk schedule mutation stopped after its first failed PATCH; prior successes remain committed and no rollback was attempted.",
        findings,
        details,
        status_only,
    )
}

fn fetch_snapshot<F>(
    filter: &str,
    max_schedules: usize,
    call: &mut F,
) -> Result<(Vec<String>, Finding), (Vec<Finding>, Value)>
where
    F: FnMut(&str, &str, Option<&str>) -> Result<GuardedDirectApiCall, Vec<Finding>>,
{
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    let mut expected_total = None;
    let mut config = None;
    for page in 1..=MAX_PAGES {
        let path = format!(
            "/api/v1/schedules?filter={}&page={page}&page_size={PAGE_SIZE}&sort=id",
            percent_encode(filter)
        );
        let response = match call(&path, "GET", None) {
            Ok(response) => response,
            Err(findings) => {
                return Err((
                    findings,
                    json!({"reason": "direct API guard rejected snapshot request", "page": page}),
                ));
            }
        };
        if config.is_none() {
            config = Some(response.config);
        }
        let object = response.parsed.as_ref().and_then(Value::as_object);
        let items = object
            .and_then(|value| value.get("items"))
            .and_then(Value::as_array);
        let page_info = object
            .and_then(|value| value.get("page"))
            .and_then(Value::as_object);
        let total = page_info
            .and_then(|value| value.get("total"))
            .and_then(Value::as_u64);
        let actual_page = page_info
            .and_then(|value| value.get("page"))
            .and_then(Value::as_u64);
        let page_ids = items.and_then(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_object()
                        .and_then(|value| value.get("id"))
                        .and_then(Value::as_str)
                        .filter(|id| validate_operator_uuid(id, "schedule id").is_ok())
                        .map(str::to_string)
                })
                .collect::<Option<Vec<_>>>()
        });
        let valid = response.output.success
            && !response.oversized
            && response.http_status == Some(200)
            && total.is_some()
            && actual_page == Some(page as u64)
            && page_ids.is_some()
            && expected_total.is_none_or(|expected| total == Some(expected));
        if !valid {
            return Err((
                config.into_iter().collect(),
                json!({
                    "reason": "schedule snapshot page was invalid, duplicated, or changed during pagination",
                    "page": page,
                    "http_status": response.http_status,
                    "expected_total": expected_total,
                    "observed_total": total,
                }),
            ));
        }
        let total = total.expect("validated total");
        let page_ids = page_ids.expect("validated ids");
        if expected_total.is_none() {
            if total > max_schedules as u64 {
                return Err((
                    config.into_iter().collect(),
                    json!({"reason": "matched schedule count exceeds safety cap", "total": total, "max_schedules": max_schedules}),
                ));
            }
            expected_total = Some(total);
        }
        if page_ids.len() != page_ids.iter().collect::<BTreeSet<_>>().len()
            || page_ids.iter().any(|id| seen.contains(id))
        {
            return Err((
                config.into_iter().collect(),
                json!({"reason": "schedule snapshot page was invalid, duplicated, or changed during pagination", "page": page}),
            ));
        }
        if page_ids.is_empty() && ids.len() as u64 != total {
            return Err((
                config.into_iter().collect(),
                json!({"reason": "schedule snapshot ended before declared total", "page": page, "total": total}),
            ));
        }
        seen.extend(page_ids.iter().cloned());
        ids.extend(page_ids);
        if ids.len() as u64 == total {
            ids.sort();
            return Ok((ids, config.expect("successful API call has config")));
        }
        if ids.len() as u64 > total {
            return Err((
                config.into_iter().collect(),
                json!({"reason": "schedule snapshot exceeded declared total", "page": page, "total": total}),
            ));
        }
    }
    Err((
        config.into_iter().collect(),
        json!({"reason": "schedule snapshot pagination exceeded safety limit", "total": expected_total}),
    ))
}

fn snapshot_hashes(
    filter: &str,
    schedule_ids: &[String],
    timezone: Option<&str>,
    icalendar: Option<&str>,
) -> (String, Option<String>, String) {
    let filter_sha256 = hex_sha256(filter.as_bytes());
    let icalendar_sha256 = icalendar.map(|value| hex_sha256(value.as_bytes()));
    let mut ids = schedule_ids.to_vec();
    ids.sort();
    let ids = ids
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(",");
    let calendar = icalendar_sha256
        .as_deref()
        .map(python_json_string)
        .unwrap_or_else(|| "null".into());
    let timezone_json = timezone
        .map(python_json_string)
        .unwrap_or_else(|| "null".into());
    let payload = format!(
        "{{\"filter_sha256\":\"{filter_sha256}\",\"icalendar_sha256\":{calendar},\"schedule_ids\":[{ids}],\"timezone\":{timezone_json}}}"
    );
    let snapshot_sha256 = hex_sha256(payload.as_bytes());
    (filter_sha256, icalendar_sha256, snapshot_sha256)
}

fn python_json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character if character.is_ascii() => output.push(character),
            character if (character as u32) <= 0xffff => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => {
                let code = character as u32 - 0x1_0000;
                output.push_str(&format!(
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (code >> 10),
                    0xdc00 + (code & 0x3ff)
                ));
            }
        }
    }
    output.push('"');
    output
}

fn confirmed_patch(call: &GuardedDirectApiCall, schedule_id: &str) -> bool {
    !call.oversized
        && call.output.success
        && call.http_status == Some(200)
        && call
            .parsed
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            == Some(schedule_id)
}

fn confirmed_rejection(call: &GuardedDirectApiCall) -> bool {
    !call.oversized
        && call.output.success
        && call
            .http_status
            .is_some_and(|status| (400..500).contains(&status))
        && call
            .parsed
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|value| value.get("error"))
            .is_some_and(Value::is_object)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn percent_encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
                (*byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn count(details: &Value, key: &str) -> u64 {
    details[key].as_u64().unwrap_or(0)
}

fn default_details(max_schedules: usize, dry_run: bool) -> Value {
    json!({
        "filter_sha256": null,
        "icalendar_sha256": null,
        "snapshot_sha256": null,
        "matched_count": 0,
        "max_schedules": max_schedules,
        "dry_run": dry_run,
        "attempted_count": 0,
        "succeeded_count": 0,
        "failed_count": 0,
        "unattempted_count": 0,
        "rows": [],
    })
}

fn result(
    root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
    status_only: bool,
) -> ResultEnvelope {
    let mut result = make_result(metadata(root, COMMAND, runner), summary.into(), findings)
        .with_details(details);
    if status_only {
        let details = result.details.as_ref().expect("details");
        let compact = json!({
            "filter_sha256": details["filter_sha256"],
            "icalendar_sha256": details["icalendar_sha256"],
            "snapshot_sha256": details["snapshot_sha256"],
            "matched_count": details["matched_count"],
            "max_schedules": details["max_schedules"],
            "dry_run": details["dry_run"],
            "attempted_count": details["attempted_count"],
            "succeeded_count": details["succeeded_count"],
            "failed_count": details["failed_count"],
            "unattempted_count": details["unattempted_count"],
        });
        result.details = Some(compact);
        result.findings = result
            .findings
            .iter()
            .filter(|finding| finding.status != "pass")
            .map(compact_finding)
            .collect();
        if result.findings.is_empty() {
            result.findings.push(Finding::new(
                "pass",
                "native-bulk-modify-schedules.status-only",
                "Native schedule mutation snapshot/result summarized.".into(),
            ));
        }
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

    #[derive(Default)]
    struct Runner(Mutex<Vec<String>>);

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            self.0.lock().unwrap().push(program.into());
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }
    }

    fn api_call(body: Value, status: i64) -> GuardedDirectApiCall {
        GuardedDirectApiCall {
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
                "native-bulk-modify-schedules.direct-config-shape",
                "ok".into(),
            ),
        }
    }

    fn page(ids: &[&str], page: u64, total: u64) -> Value {
        json!({
            "items": ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
            "page": {"page": page, "page_size": 500, "total": total},
        })
    }

    const ID1: &str = "11111111-1111-4111-8111-111111111111";
    const ID2: &str = "22222222-2222-4222-8222-222222222222";
    const ID3: &str = "33333333-3333-4333-8333-333333333333";
    const CALENDAR: &str = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";

    #[test]
    fn arguments_and_calendar_fail_before_runtime() {
        let runner = Runner::default();
        for (filter, timezone, max, dry, allow, confirm) in [
            (" ", Some("UTC"), DEFAULT_MAX, true, false, None),
            ("nightly", None, DEFAULT_MAX, true, false, None),
            ("nightly", Some("UTC"), 0, true, false, None),
            ("nightly", Some("UTC"), DEFAULT_MAX, false, false, None),
            ("nightly", Some("UTC"), DEFAULT_MAX, false, true, None),
        ] {
            let result = command_with_runner(
                Path::new("/tmp"),
                filter,
                timezone,
                None,
                max,
                dry,
                allow,
                confirm,
                false,
                &runner,
            );
            assert_eq!(result.status, "fail");
        }
        assert!(!runner.0.lock().unwrap().iter().any(|call| call == "curl"));
    }

    #[test]
    fn calendar_loader_is_bounded_utf8_regular_and_control_safe() {
        let root = std::env::temp_dir().join(format!("yafvsctl-schedule-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let valid = root.join("valid.ics");
        fs::write(&valid, CALENDAR).unwrap();
        assert_eq!(load_icalendar(&valid).unwrap(), CALENDAR);
        let invalid = root.join("invalid.ics");
        fs::write(&invalid, b"BEGIN:VCALENDAR\xff").unwrap();
        assert!(load_icalendar(&invalid).unwrap_err().contains("UTF-8"));
        fs::write(&invalid, "BEGIN:VCALENDAR\r\nX:\u{85}\r\n").unwrap();
        assert!(load_icalendar(&invalid).unwrap_err().contains("control"));
        let link = root.join("link.ics");
        std::os::unix::fs::symlink(&valid, &link).unwrap();
        assert!(load_icalendar(&link).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_hash_matches_python_contract_and_unicode_escaping() {
        let (filter_hash, calendar_hash, snapshot_hash) = snapshot_hashes(
            "nightly",
            &[ID1.into()],
            Some("Europe/Berlin"),
            Some(CALENDAR),
        );
        assert_eq!(
            filter_hash,
            "2a3b62b53ddb9f167b63d22202a360811ba78df015021f704d01ee9abad4169c"
        );
        assert_eq!(
            calendar_hash.as_deref(),
            Some("215efae54e34ac5657da47b49c8d1bd8ea12649ee1efa838c9a47d7233f18afb")
        );
        assert_eq!(
            snapshot_hash,
            "5b02fa789ce1eb5a5a8ac33ee80b79820ecfc91e820abd77a3ddfc050db53c50"
        );
        assert_eq!(
            python_json_string("Zürich😀"),
            "\"Z\\u00fcrich\\ud83d\\ude00\""
        );
    }

    #[test]
    fn dry_run_paginates_and_redacts_calendar() {
        let runner = Runner::default();
        let mut responses = VecDeque::from([
            api_call(page(&[ID2], 1, 2), 200),
            api_call(page(&[ID1], 2, 2), 200),
        ]);
        let mut methods = Vec::new();
        let mut call = |_: &str, method: &str, body: Option<&str>| {
            methods.push((method.to_string(), body.is_some()));
            Ok(responses.pop_front().unwrap())
        };
        let result = execute(
            Path::new("/tmp"),
            "nightly",
            Some("UTC"),
            Some(CALENDAR),
            None,
            DEFAULT_MAX,
            true,
            None,
            false,
            &runner,
            &mut call,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.details.as_ref().unwrap()["schedule_ids"],
            json!([ID1, ID2])
        );
        assert_eq!(methods, [("GET".into(), false), ("GET".into(), false)]);
        assert!(!serde_json::to_string(&result).unwrap().contains(CALENDAR));
    }

    #[test]
    fn snapshot_mismatch_makes_no_patch() {
        let runner = Runner::default();
        let mut methods = Vec::new();
        let mut call = |_: &str, method: &str, _: Option<&str>| {
            methods.push(method.to_string());
            Ok(api_call(page(&[ID1], 1, 1), 200))
        };
        let result = execute(
            Path::new("/tmp"),
            "nightly",
            Some("UTC"),
            None,
            None,
            DEFAULT_MAX,
            false,
            Some(&"0".repeat(64)),
            false,
            &runner,
            &mut call,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(methods, ["GET"]);
    }

    #[test]
    fn patch_body_preserves_omitted_fields() {
        let runner = Runner::default();
        let (_, _, snapshot) = snapshot_hashes("nightly", &[ID1.into()], Some("UTC"), None);
        let mut bodies = Vec::new();
        let mut call = |_: &str, method: &str, body: Option<&str>| {
            if method == "GET" {
                Ok(api_call(page(&[ID1], 1, 1), 200))
            } else {
                bodies.push(body.unwrap().to_string());
                Ok(api_call(json!({"id": ID1}), 200))
            }
        };
        let result = execute(
            Path::new("/tmp"),
            "nightly",
            Some("UTC"),
            None,
            None,
            DEFAULT_MAX,
            false,
            Some(&snapshot),
            false,
            &runner,
            &mut call,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            serde_json::from_str::<Value>(&bodies[0]).unwrap(),
            json!({"timezone": "UTC"})
        );
    }

    #[test]
    fn first_failed_patch_stops_without_retry_or_calendar_disclosure() {
        let runner = Runner::default();
        let ids = vec![ID1.into(), ID2.into(), ID3.into()];
        let (_, _, snapshot) = snapshot_hashes("nightly", &ids, None, Some(CALENDAR));
        let mut responses = VecDeque::from([
            api_call(page(&[ID1, ID2, ID3], 1, 3), 200),
            api_call(json!({"id": ID1}), 200),
            api_call(json!({"error": {"code": "forbidden"}}), 403),
        ]);
        let mut methods = Vec::new();
        let mut call = |_: &str, method: &str, _: Option<&str>| {
            methods.push(method.to_string());
            Ok(responses.pop_front().unwrap())
        };
        let result = execute(
            Path::new("/tmp"),
            "nightly",
            None,
            Some(CALENDAR),
            None,
            DEFAULT_MAX,
            false,
            Some(&snapshot),
            true,
            &runner,
            &mut call,
        );
        assert_eq!(result.status, "fail");
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["attempted_count"], 2);
        assert_eq!(details["succeeded_count"], 1);
        assert_eq!(details["unattempted_count"], 1);
        assert_eq!(methods, ["GET", "PATCH", "PATCH"]);
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(!rendered.contains(CALENDAR));
        assert!(!rendered.contains(ID1));
    }
}
