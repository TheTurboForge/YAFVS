// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::path::Path;

const COMMAND: &str = "native-verify-scanners";
const MAX_PAGES: usize = 1_000;

pub fn command_native_verify_scanners(
    root: &Path,
    scanner_ids: &[String],
    page_size: usize,
    allow: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        root,
        scanner_ids,
        page_size,
        allow,
        status_only,
        &SystemCommandRunner,
    )
}

pub(crate) fn command_with_runner(
    root: &Path,
    scanner_ids: &[String],
    page_size: usize,
    allow: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let selected = match scanner_ids
        .iter()
        .map(|id| validate_operator_uuid(id, "--scanner-id"))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(message) => {
            return envelope(
                root,
                runner,
                "Native scanner verification rejected before runtime access.",
                vec![Finding::new(
                    "fail",
                    "native-verify-scanners.arguments",
                    message,
                )],
            );
        }
    };
    if !(1..=500).contains(&page_size) {
        return envelope(
            root,
            runner,
            "Native scanner verification rejected before runtime access.",
            vec![Finding::new(
                "fail",
                "native-verify-scanners.arguments",
                "--page-size must be between 1 and 500".into(),
            )],
        );
    }
    if !allow {
        return envelope(root, runner, "Native scanner verification rejected before runtime access.", vec![Finding::new("fail", "native-verify-scanners.write-control-intent", "Scanner verification requires --allow-write-control because it invokes scanner verification.".into())]);
    }
    let mut call = |path: &str, method: &str| {
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            None,
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        )
    };
    verify(root, &selected, page_size, status_only, runner, &mut call)
}

fn envelope(
    root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(metadata(root, COMMAND, runner), summary.into(), findings)
}

fn verify<F>(
    root: &Path,
    selected: &[String],
    page_size: usize,
    status_only: bool,
    runner: &dyn CommandRunner,
    call: &mut F,
) -> ResultEnvelope
where
    F: FnMut(&str, &str) -> Result<GuardedDirectApiCall, Vec<Finding>>,
{
    let mut findings = Vec::new();
    let mut rows = Vec::new();
    let mut config = None;
    let metadata_rows = if selected.is_empty() {
        let mut collected = Vec::new();
        let mut page = 1usize;
        loop {
            let response = match call(
                &format!("/api/v1/scanners?page={page}&page_size={page_size}&sort=name"),
                "GET",
            ) {
                Ok(value) => value,
                Err(items) => {
                    return collection_failure(
                        root,
                        runner,
                        selected,
                        collected.len(),
                        findings,
                        items,
                        status_only,
                    );
                }
            };
            let object = valid_object(&response).cloned();
            config.get_or_insert(response.config);
            let object = match object {
                Some(value) => value,
                None => {
                    let mut errors = Vec::new();
                    if let Some(config) = config.take() {
                        errors.push(config);
                    }
                    errors.push(
                        Finding::new(
                            "fail",
                            &format!("native-verify-scanners.scanner-list.page-{page}"),
                            "Direct native API failed to return scanner metadata for verification."
                                .into(),
                        )
                        .with_details(json!({
                            "http_status": response.http_status,
                            "page": page,
                            "oversized": response.oversized,
                        })),
                    );
                    return collection_failure(
                        root,
                        runner,
                        selected,
                        collected.len(),
                        findings,
                        errors,
                        status_only,
                    );
                }
            };
            let items = match object.get("items").and_then(Value::as_array) {
                Some(value) => value,
                None => {
                    return collection_failure(
                        root,
                        runner,
                        selected,
                        collected.len(),
                        findings,
                        vec![Finding::new(
                            "fail",
                            &format!("native-verify-scanners.scanner-list.page-{page}"),
                            "Scanner collection did not return an items list.".into(),
                        )],
                        status_only,
                    );
                }
            };
            let total = object
                .get("page")
                .and_then(Value::as_object)
                .and_then(|page| page.get("total"))
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok());
            collected.extend(items.iter().cloned());
            if total.is_none()
                || total.is_some_and(|total| collected.len() >= total)
                || items.is_empty()
            {
                break collected;
            }
            if page >= MAX_PAGES {
                return collection_failure(
                    root,
                    runner,
                    selected,
                    collected.len(),
                    findings,
                    vec![Finding::new(
                        "fail",
                        "native-verify-scanners.scanner-list.page-limit",
                        format!("Scanner pagination exceeded the {MAX_PAGES}-page safety limit."),
                    )],
                    status_only,
                );
            }
            page += 1;
        }
    } else {
        let mut collected = Vec::new();
        for id in selected {
            let response = match call(&format!("/api/v1/scanners/{id}"), "GET") {
                Ok(value) => value,
                Err(items) => {
                    return collection_failure(
                        root,
                        runner,
                        selected,
                        collected.len(),
                        findings,
                        items,
                        status_only,
                    );
                }
            };
            let object = valid_object(&response).cloned();
            config.get_or_insert(response.config);
            match object {
                Some(value) => collected.push(Value::Object(value)),
                None => {
                    let mut errors = Vec::new();
                    if let Some(config) = config.take() {
                        errors.push(config);
                    }
                    errors.push(
                        Finding::new(
                            "fail",
                            &format!("native-verify-scanners.scanner-detail.{id}"),
                            "Direct native API failed to return selected scanner metadata.".into(),
                        )
                        .with_details(json!({
                            "http_status": response.http_status,
                            "scanner_id": id,
                            "oversized": response.oversized,
                        })),
                    );
                    return collection_failure(
                        root,
                        runner,
                        selected,
                        collected.len(),
                        findings,
                        errors,
                        status_only,
                    );
                }
            }
        }
        collected
    };
    if let Some(config) = config {
        findings.push(config);
    }
    for item in metadata_rows {
        let number = rows.len() + 1;
        let object = match item.as_object() {
            Some(value) => value,
            None => {
                findings.push(Finding::new(
                    "fail",
                    &format!("native-verify-scanners.scanner-id.{number}"),
                    "Scanner metadata row was not an object; refusing to probe it.".into(),
                ));
                rows.push(failed_metadata_row(number, "", "", "local scanner"));
                continue;
            }
        };
        let raw_id = object.get("id").and_then(Value::as_str).unwrap_or("");
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let host = object
            .get("host")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("local scanner")
            .to_string();
        let id = match validate_operator_uuid(raw_id, "scanner id") {
            Ok(value) => value,
            Err(_) => {
                findings.push(
                    Finding::new(
                        "fail",
                        &format!("native-verify-scanners.scanner-id.{number}"),
                        "Scanner metadata row did not contain a valid UUID; refusing to probe it."
                            .into(),
                    )
                    .with_details(json!({"scanner_id": raw_id})),
                );
                rows.push(failed_metadata_row(number, &name, raw_id, &host));
                continue;
            }
        };
        let response = match call(&format!("/api/v1/scanners/{id}/verify"), "POST") {
            Ok(value) => value,
            Err(items) => {
                findings.extend(items);
                findings.push(Finding::new(
                    "fail",
                    &format!("native-verify-scanners.verify.{id}"),
                    "Native API scanner verification request was rejected before execution.".into(),
                ));
                rows.push(failed_request_row(number, &name, &id, &host));
                continue;
            }
        };
        let object_response = response.parsed.as_ref().and_then(Value::as_object);
        let verified = !response.oversized
            && response.output.success
            && response.http_status == Some(200)
            && object_response
                .and_then(|value| value.get("verified"))
                .and_then(Value::as_bool)
                == Some(true);
        let status = if verified {
            "pass"
        } else if response.http_status == Some(409) {
            "warn"
        } else {
            "fail"
        };
        let error_code = object_response
            .and_then(|value| value.get("error"))
            .and_then(Value::as_object)
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .map(String::from);
        let verification_mode = object_response
            .and_then(|value| value.get("verification_mode"))
            .and_then(Value::as_str)
            .map(String::from);
        let row_name = if name.is_empty() {
            object_response
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        } else {
            name
        };
        let version = object_response
            .and_then(|value| {
                value
                    .get("version")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        value
                            .get("scanner_version")
                            .and_then(Value::as_str)
                            .filter(|value| !value.is_empty())
                    })
            })
            .map(String::from)
            .unwrap_or_else(|| {
                if status == "fail" {
                    format!(
                        "*HTTP {}*",
                        response
                            .http_status
                            .map_or_else(|| "failed".to_string(), |value| value.to_string())
                    )
                } else {
                    "*No Response*".into()
                }
            });
        findings.push(Finding::new(
            status,
            &format!("native-verify-scanners.verify.{id}"),
            if verified {
                "Native API verified scanner availability.".into()
            } else {
                "Native API could not verify this scanner through the currently supported native path.".into()
            },
        )
        .with_details(json!({
            "http_status": response.http_status,
            "scanner_id": id,
            "error_code": error_code,
            "oversized": response.oversized,
        })));
        rows.push(json!({"number": number, "name": row_name, "id": id, "host": host, "verified": verified, "version": version, "verification_mode": verification_mode, "status": status, "error_code": error_code}));
    }
    if rows.is_empty() {
        findings.push(Finding::new(
            "warn",
            "native-verify-scanners.rows",
            "No scanner rows were available for verification.".into(),
        ));
    }
    finish(root, runner, selected, rows, findings, status_only)
}

fn valid_object(call: &GuardedDirectApiCall) -> Option<&serde_json::Map<String, Value>> {
    (!call.oversized && call.output.success && call.http_status == Some(200)).then_some(())?;
    call.parsed.as_ref()?.as_object()
}
fn failed_metadata_row(number: usize, name: &str, id: &str, host: &str) -> Value {
    json!({"number": number, "name": name, "id": id, "host": host, "verified": false, "version": "*Invalid scanner id*", "verification_mode": null, "status": "fail", "error_code": null})
}
fn failed_request_row(number: usize, name: &str, id: &str, host: &str) -> Value {
    json!({"number": number, "name": name, "id": id, "host": host, "verified": false, "version": "*HTTP failed*", "verification_mode": null, "status": "fail", "error_code": null})
}
fn collection_failure(
    root: &Path,
    runner: &dyn CommandRunner,
    selected: &[String],
    scanner_count: usize,
    mut findings: Vec<Finding>,
    mut errors: Vec<Finding>,
    status_only: bool,
) -> ResultEnvelope {
    findings.append(&mut errors);
    let mut result = envelope(
        root,
        runner,
        "Native scanner verification stopped before scanner probes.",
        findings,
    )
    .with_details(json!({
        "selected_scanner_ids": selected,
        "scanner_count": scanner_count,
    }));
    if status_only {
        compact_status_only(&mut result);
    }
    result
}
fn finish(
    root: &Path,
    runner: &dyn CommandRunner,
    selected: &[String],
    rows: Vec<Value>,
    findings: Vec<Finding>,
    status_only: bool,
) -> ResultEnvelope {
    let verified = rows.iter().filter(|row| row["status"] == "pass").count();
    let warnings = rows.iter().filter(|row| row["status"] == "warn").count();
    let failures = rows.iter().filter(|row| row["status"] == "fail").count();
    let details = json!({"selected_scanner_ids": selected, "scanner_count": rows.len(), "verified_count": verified, "warning_count": warnings, "failure_count": failures, "rows": rows});
    let mut result = envelope(
        root,
        runner,
        &format!(
            "Native scanner verification checked {} scanner(s); {verified} verified.",
            details["scanner_count"]
        ),
        findings,
    )
    .with_details(details);
    if status_only {
        compact_status_only(&mut result);
    }
    result
}

fn compact_status_only(result: &mut ResultEnvelope) {
    result.findings = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect();
    let details = result.details.as_mut().expect("details");
    let rows = details["rows"].as_array().cloned().unwrap_or_default();
    details
        .as_object_mut()
        .expect("details object")
        .remove("rows");
    details["rows_sample"] = Value::Array(rows.into_iter().take(5).collect());
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            "native-verify-scanners.status-only",
            "Native scanner verification passed; rows summarized.".into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
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
    fn call(body: Value, status: i64) -> GuardedDirectApiCall {
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
                "native-verify-scanners.direct-config-shape",
                "ok".into(),
            ),
        }
    }
    #[test]
    fn refusals_do_not_make_runtime_calls() {
        let runner = Runner::default();
        let result = command_with_runner(Path::new("/tmp"), &[], 500, false, false, &runner);
        assert_eq!(
            result.findings[0].check,
            "native-verify-scanners.write-control-intent"
        );
        assert_eq!(*runner.0.lock().unwrap(), vec!["git"]);
        let result = command_with_runner(
            Path::new("/tmp"),
            &["bad".into()],
            500,
            true,
            false,
            &runner,
        );
        assert_eq!(result.findings[0].check, "native-verify-scanners.arguments");
        let result = command_with_runner(Path::new("/tmp"), &[], 0, true, false, &runner);
        assert_eq!(result.findings[0].check, "native-verify-scanners.arguments");
        let result = command_with_runner(Path::new("/tmp"), &[], 501, true, false, &runner);
        assert_eq!(result.findings[0].check, "native-verify-scanners.arguments");
        assert!(
            runner
                .0
                .lock()
                .unwrap()
                .iter()
                .all(|program| program == "git")
        );
    }
    #[test]
    fn paginated_verification_preserves_order_and_redacts_tokens() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let mut responses = vec![
            call(json!({"items":[{"id":"11111111-1111-4111-8111-111111111111","name":"local","host":""},{"id":"22222222-2222-4222-8222-222222222222","name":"remote","host":"scanner.example"}],"page":{"total":2}}), 200),
            call(json!({"verified":true,"version":"1.2"}), 200),
            call(json!({"error":{"code":"busy"}}), 409),
        ].into_iter();
        let result = verify(
            Path::new("/tmp"),
            &[],
            500,
            false,
            &runner,
            &mut |path, method| {
                calls.lock().unwrap().push(format!("{method} {path}"));
                Ok(responses.next().unwrap())
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                "GET /api/v1/scanners?page=1&page_size=500&sort=name",
                "POST /api/v1/scanners/11111111-1111-4111-8111-111111111111/verify",
                "POST /api/v1/scanners/22222222-2222-4222-8222-222222222222/verify"
            ]
        );
        assert_eq!(result.status, "warn");
        assert_eq!(result.details.as_ref().unwrap()["verified_count"], 1);
        assert_eq!(result.details.as_ref().unwrap()["warning_count"], 1);
        assert_eq!(
            result.details.as_ref().unwrap()["rows"][0]["verification_mode"],
            Value::Null
        );
        assert_eq!(
            result.details.as_ref().unwrap()["rows"][1]["error_code"],
            "busy"
        );
        assert!(!serde_json::to_string(&result).unwrap().contains("Bearer"));
    }
    #[test]
    fn selected_scanner_ids_use_detail_paths_and_preserve_selection() {
        let runner = Runner::default();
        let scanner_id = "33333333-3333-4333-8333-333333333333";
        let selected = vec![scanner_id.to_string()];
        let calls = Mutex::new(Vec::new());
        let mut responses = vec![
            call(json!({"id":scanner_id,"name":"","host":""}), 200),
            call(
                json!({
                    "verified": true,
                    "name": "OpenVAS Default",
                    "scanner_version": "23.1",
                    "verification_mode": "osp-unix-socket"
                }),
                200,
            ),
        ]
        .into_iter();
        let result = verify(
            Path::new("/tmp"),
            &selected,
            500,
            false,
            &runner,
            &mut |path, method| {
                calls.lock().unwrap().push(format!("{method} {path}"));
                Ok(responses.next().unwrap())
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                format!("GET /api/v1/scanners/{scanner_id}"),
                format!("POST /api/v1/scanners/{scanner_id}/verify"),
            ]
        );
        assert_eq!(
            result.details.as_ref().unwrap()["selected_scanner_ids"],
            json!([scanner_id])
        );
        assert_eq!(
            result.details.as_ref().unwrap()["rows"][0]["name"],
            "OpenVAS Default"
        );
        assert_eq!(
            result.details.as_ref().unwrap()["rows"][0]["version"],
            "23.1"
        );
        assert_eq!(
            result.details.as_ref().unwrap()["rows"][0]["verification_mode"],
            "osp-unix-socket"
        );
    }
    #[test]
    fn malformed_rows_skip_probes_and_status_only_samples_rows() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let mut responses = vec![call(
            json!({"items":[{"id":"invalid"}],"page":{"total":1}}),
            200,
        )]
        .into_iter();
        let result = verify(
            Path::new("/tmp"),
            &[],
            500,
            true,
            &runner,
            &mut |path, method| {
                calls.lock().unwrap().push(format!("{method} {path}"));
                Ok(responses.next().unwrap())
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["GET /api/v1/scanners?page=1&page_size=500&sort=name"]
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["failure_count"], 1);
        assert!(result.details.as_ref().unwrap().get("rows").is_none());
        assert_eq!(
            result.details.as_ref().unwrap()["rows_sample"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            result.findings[0].check,
            "native-verify-scanners.scanner-id.1"
        );
    }

    #[test]
    fn malformed_collection_stops_before_probes_and_preserves_selection_shape() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let result = verify(
            Path::new("/tmp"),
            &[],
            25,
            true,
            &runner,
            &mut |path, method| {
                calls.lock().unwrap().push(format!("{method} {path}"));
                Ok(call(json!({"page":{"total":1}}), 200))
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["GET /api/v1/scanners?page=1&page_size=25&sort=name"]
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["scanner_count"], 0);
        assert_eq!(
            result.details.as_ref().unwrap()["selected_scanner_ids"],
            json!([])
        );
        assert_eq!(result.details.as_ref().unwrap()["rows_sample"], json!([]));
    }

    #[test]
    fn status_only_limits_row_samples_and_replaces_all_pass_findings() {
        let runner = Runner::default();
        let rows = (1..=6)
            .map(|number| {
                json!({
                    "number": number,
                    "name": format!("scanner-{number}"),
                    "id": format!("00000000-0000-4000-8000-{number:012}"),
                    "host": "local scanner",
                    "verified": true,
                    "version": "1",
                    "verification_mode": "cve-builtin",
                    "status": "pass",
                    "error_code": null
                })
            })
            .collect();
        let result = finish(
            Path::new("/tmp"),
            &runner,
            &[],
            rows,
            vec![Finding::new(
                "pass",
                "native-verify-scanners.verify",
                "ok".into(),
            )],
            true,
        );
        assert_eq!(
            result.details.as_ref().unwrap()["rows_sample"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        assert!(result.details.as_ref().unwrap().get("rows").is_none());
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].check,
            "native-verify-scanners.status-only"
        );
    }
}
