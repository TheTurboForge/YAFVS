// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{ArtifactCommit, begin_secure_artifact_transaction};
use super::common::{compact_finding, expand_home, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::{Terminator, WriterBuilder};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const COMMAND: &str = "native-export-report-csv";
const PAGE_SIZE: usize = 500;
pub(crate) const DEFAULT_MAX_RESULTS: usize = 100_000;
pub(crate) const MAX_RESULTS_LIMIT: usize = 1_000_000;
const CSV_FIELDS: [&str; 35] = [
    "id",
    "source_report_id",
    "report_id",
    "report_name",
    "task_id",
    "task_name",
    "host",
    "host_asset_id",
    "hostname",
    "port",
    "severity",
    "threat",
    "qod",
    "nvt_oid",
    "name",
    "nvt_family",
    "cves",
    "cert_refs",
    "xrefs",
    "max_epss",
    "max_severity",
    "created_at",
    "scan_nvt_version",
    "description",
    "description_excerpt",
    "summary",
    "insight",
    "affected",
    "impact",
    "detection",
    "solution_type",
    "solution",
    "raw_evidence_href",
    "user_tags",
    "overrides",
];

pub fn command_native_export_report_csv(
    repo_root: &Path,
    report_id: &str,
    output: Option<&Path>,
    max_results: usize,
    overwrite: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        repo_root,
        report_id,
        output,
        max_results,
        overwrite,
        status_only,
        &SystemCommandRunner,
    )
}

pub(crate) fn report_csv_bytes_for_bundle(rows: &[Value]) -> Result<Vec<u8>, String> {
    let mut writer = WriterBuilder::new()
        .terminator(Terminator::Any(b'\n'))
        .from_writer(Vec::new());
    writer
        .write_record(CSV_FIELDS)
        .map_err(|error| format!("report CSV header could not be encoded: {error}"))?;
    for row in rows {
        writer
            .write_record(bundle_csv_row(row))
            .map_err(|error| format!("report CSV row could not be encoded: {error}"))?;
    }
    writer
        .into_inner()
        .map_err(|error| format!("report CSV could not be completed: {}", error.error()))
}

fn bundle_csv_row(row: &Value) -> Vec<String> {
    let object = row.as_object();
    let report = object
        .and_then(|value| value.get("report"))
        .and_then(Value::as_object);
    let task = object
        .and_then(|value| value.get("task"))
        .and_then(Value::as_object);
    let get = |field| object.and_then(|value| value.get(field));
    let severity = bundle_json_float(get("severity"));
    vec![
        csv_cell(get("id"), true),
        csv_cell(get("source_report_id"), true),
        csv_cell(report.and_then(|value| value.get("id")), true),
        csv_cell(report.and_then(|value| value.get("name")), true),
        csv_cell(task.and_then(|value| value.get("id")), true),
        csv_cell(task.and_then(|value| value.get("name")), true),
        csv_cell(get("host"), true),
        csv_cell(get("host_asset_id"), true),
        csv_cell(get("hostname"), true),
        csv_cell(get("port"), true),
        csv_cell(get("severity"), false),
        spreadsheet_safe(threat(severity)),
        csv_cell(get("qod"), false),
        csv_cell(get("nvt_oid"), true),
        csv_cell(get("name"), true),
        csv_cell(get("nvt_family"), true),
        bundle_collection_cell(get("cves")),
        bundle_collection_cell(get("cert_refs")),
        bundle_collection_cell(get("xrefs")),
        csv_cell(get("max_epss"), true),
        csv_cell(get("max_severity"), true),
        csv_cell(get("created_at"), true),
        csv_cell(get("scan_nvt_version"), true),
        csv_cell(get("description"), true),
        csv_cell(get("description_excerpt"), true),
        csv_cell(get("summary"), true),
        csv_cell(get("insight"), true),
        csv_cell(get("affected"), true),
        csv_cell(get("impact"), true),
        csv_cell(get("detection"), true),
        csv_cell(get("solution_type"), true),
        csv_cell(get("solution"), true),
        csv_cell(get("raw_evidence_href"), true),
        bundle_collection_cell(get("user_tags")),
        bundle_collection_cell(get("overrides")),
    ]
}

fn bundle_json_float(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(value)) => value.as_f64().unwrap_or(0.0),
        Some(Value::String(value)) => value.parse().unwrap_or(0.0),
        Some(Value::Bool(value)) => f64::from(u8::from(*value)),
        _ => 0.0,
    }
}

fn bundle_collection_cell(value: Option<&Value>) -> String {
    match value {
        None => "[]".into(),
        Some(value) => csv_cell(Some(value), true),
    }
}

fn envelope(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
}

fn initial_details(report_id: &str, max_results: usize) -> Value {
    json!({
        "report_id": report_id,
        "output": Value::Null,
        "max_results": max_results,
        "row_count": 0,
        "total": Value::Null,
        "page_count": 0,
        "byte_count": Value::Null,
        "sha256": Value::Null,
    })
}

fn argument_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    report_id: &str,
    max_results: usize,
    message: String,
    status_only: bool,
) -> ResultEnvelope {
    finish(
        repo_root,
        runner,
        "Native CSV report export rejected before runtime access.",
        vec![
            Finding::new("fail", "native-export-report-csv.arguments", message)
                .with_details(json!({"report_id": report_id, "max_results": max_results})),
        ],
        initial_details(report_id, max_results),
        None,
        status_only,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_with_runner(
    repo_root: &Path,
    report_id: &str,
    output: Option<&Path>,
    max_results: usize,
    overwrite: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let report_id = match validate_operator_uuid(report_id, "--report-id") {
        Ok(value) => value,
        Err(message) => {
            return argument_failure(
                repo_root,
                runner,
                report_id,
                max_results,
                message,
                status_only,
            );
        }
    };
    if !(1..=MAX_RESULTS_LIMIT).contains(&max_results) {
        return argument_failure(
            repo_root,
            runner,
            &report_id,
            max_results,
            format!("--max-results must be between 1 and {MAX_RESULTS_LIMIT}"),
            status_only,
        );
    }
    let output = expand_home(
        output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(format!("{report_id}.csv"))),
    );
    let output_text = output.display().to_string();
    let mut details = initial_details(&report_id, max_results);
    details["output"] = Value::String(output_text.clone());
    let mut transaction = match begin_secure_artifact_transaction(&output, overwrite) {
        Ok(transaction) => transaction,
        Err(message) => {
            return finish(
                repo_root,
                runner,
                "Native CSV report export rejected before runtime access.",
                vec![
                    Finding::new("fail", "native-export-report-csv.arguments", message)
                        .with_details(json!({"output": output_text, "overwrite": overwrite})),
                ],
                details,
                None,
                status_only,
            );
        }
    };

    let detail_path = format!("/api/v1/reports/{report_id}");
    let detail_call = match direct_json(repo_root, &detail_path, runner) {
        Ok(call) => call,
        Err(findings) => {
            return finish(
                repo_root,
                runner,
                "Direct native API CSV export rejected or failed at report preflight.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let detail_ok = detail_call.value.as_object().is_some_and(|object| {
        object.get("id").and_then(Value::as_str) == Some(report_id.as_str())
            && object.get("name").is_some_and(Value::is_string)
    });
    let mut findings = vec![detail_call.config];
    findings.push(
        Finding::new(
            if detail_ok { "pass" } else { "fail" },
            "native-export-report-csv.report-preflight",
            if detail_ok {
                "Direct native API returned the exact report metadata.".into()
            } else {
                "Direct native API report preflight returned the wrong report or an invalid shape."
                    .into()
            },
        )
        .with_details(json!({"http_status": 200, "report_id": report_id})),
    );
    if !detail_ok {
        return finish(
            repo_root,
            runner,
            "Native CSV report export stopped at report preflight.",
            findings,
            details,
            None,
            status_only,
        );
    }

    let mut writer = WriterBuilder::new()
        .terminator(Terminator::CRLF)
        .from_writer(transaction.file_mut());
    if let Err(error) = writer.write_record(CSV_FIELDS) {
        findings.push(Finding::new(
            "fail",
            "native-export-report-csv.output",
            format!("Private CSV header could not be written: {error}"),
        ));
        return finish(
            repo_root,
            runner,
            "Native CSV report export could not write its private output.",
            findings,
            details,
            None,
            status_only,
        );
    }

    let mut seen_ids = BTreeSet::<String>::new();
    let mut expected_total = None::<usize>;
    let mut row_count = 0_usize;
    let mut page = 1_usize;
    loop {
        let path = format!(
            "/api/v1/reports/{report_id}/results?page={page}&page_size={PAGE_SIZE}&sort=-severity"
        );
        let page_call = match direct_json(repo_root, &path, runner) {
            Ok(call) => call,
            Err(mut request_findings) => {
                findings.append(&mut request_findings);
                return finish(
                    repo_root,
                    runner,
                    "Native CSV report export failed while reading result pages; no output was replaced.",
                    findings,
                    details,
                    None,
                    status_only,
                );
            }
        };
        let page_payload = match validate_page(
            &page_call.value,
            &report_id,
            page,
            expected_total,
            &seen_ids,
        ) {
            Ok(page_payload) => page_payload,
            Err(message) => {
                findings.push(
                    Finding::new(
                        "fail",
                        "native-export-report-csv.result-page",
                        "Direct native API returned an invalid, drifting, duplicate, or incomplete result page."
                            .into(),
                    )
                    .with_details(json!({
                        "page": page,
                        "expected_total": expected_total,
                        "error": message,
                    })),
                );
                return finish(
                    repo_root,
                    runner,
                    "Native CSV report export failed while reading result pages; no output was replaced.",
                    findings,
                    details,
                    None,
                    status_only,
                );
            }
        };
        if expected_total.is_none() {
            expected_total = Some(page_payload.total);
            details["total"] = Value::from(page_payload.total);
            if page_payload.total > max_results {
                findings.push(
                    Finding::new(
                        "fail",
                        "native-export-report-csv.max-results",
                        format!(
                            "Report contains {} results, exceeding --max-results {max_results}.",
                            page_payload.total
                        ),
                    )
                    .with_details(json!({"total": page_payload.total, "max_results": max_results})),
                );
                return finish(
                    repo_root,
                    runner,
                    "Native CSV report export stopped at the result safety cap.",
                    findings,
                    details,
                    None,
                    status_only,
                );
            }
        }
        if page_payload.items.is_empty() && row_count != page_payload.total {
            findings.push(
                Finding::new(
                    "fail",
                    "native-export-report-csv.incomplete",
                    "Result pagination ended before the declared total was reached.".into(),
                )
                .with_details(
                    json!({"page": page, "row_count": row_count, "total": page_payload.total}),
                ),
            );
            return finish(
                repo_root,
                runner,
                "Native CSV report export ended before all results were read; no output was replaced.",
                findings,
                details,
                None,
                status_only,
            );
        }
        for item in page_payload.items {
            let id = item
                .get("id")
                .and_then(Value::as_str)
                .expect("validated result id");
            if !seen_ids.insert(id.to_string()) {
                unreachable!("page validation rejects duplicate result ids");
            }
            let row = csv_row(item);
            if let Err(error) = writer.write_record(row) {
                findings.push(Finding::new(
                    "fail",
                    "native-export-report-csv.output",
                    format!("Private CSV row could not be written: {error}"),
                ));
                return finish(
                    repo_root,
                    runner,
                    "Native CSV report export could not write its private output.",
                    findings,
                    details,
                    None,
                    status_only,
                );
            }
            row_count = match row_count.checked_add(1) {
                Some(count) => count,
                None => {
                    findings.push(Finding::new(
                        "fail",
                        "native-export-report-csv.total-overrun",
                        "Result row count overflowed.".into(),
                    ));
                    return finish(
                        repo_root,
                        runner,
                        "Native CSV report export exceeded the declared result total; no output was replaced.",
                        findings,
                        details,
                        None,
                        status_only,
                    );
                }
            };
            if row_count > page_payload.total {
                findings.push(
                    Finding::new(
                        "fail",
                        "native-export-report-csv.total-overrun",
                        "Result pages exceeded the declared total.".into(),
                    )
                    .with_details(
                        json!({"page": page, "row_count": row_count, "total": page_payload.total}),
                    ),
                );
                return finish(
                    repo_root,
                    runner,
                    "Native CSV report export exceeded the declared result total; no output was replaced.",
                    findings,
                    details,
                    None,
                    status_only,
                );
            }
        }
        details["page_count"] = Value::from(page);
        if row_count == page_payload.total {
            break;
        }
        page = page
            .checked_add(1)
            .expect("bounded report pagination page count");
    }
    if let Err(error) = writer.flush() {
        findings.push(Finding::new(
            "fail",
            "native-export-report-csv.output",
            format!("Private CSV output could not be flushed: {error}"),
        ));
        return finish(
            repo_root,
            runner,
            "Native CSV report export could not write its private output.",
            findings,
            details,
            None,
            status_only,
        );
    }
    drop(writer);
    details["row_count"] = Value::from(row_count);
    findings.push(
        Finding::new(
            "pass",
            "native-export-report-csv.results",
            format!(
                "Read all {row_count} report result row(s) across {} page(s).",
                details["page_count"]
            ),
        )
        .with_details(json!({
            "row_count": row_count,
            "total": expected_total,
            "page_count": details["page_count"],
        })),
    );

    let (byte_count, sha256) = match file_identity(transaction.file_mut()) {
        Ok(identity) => identity,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "native-export-report-csv.output",
                format!("Private CSV output could not be inspected: {error}"),
            ));
            return finish(
                repo_root,
                runner,
                "Native CSV report export could not validate its private output.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let commit = match transaction.commit() {
        Ok(commit) => commit,
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "native-export-report-csv.output",
                    format!("Atomic CSV output installation failed: {error}"),
                )
                .with_details(json!({"output": output_text})),
            );
            return finish(
                repo_root,
                runner,
                "Native CSV report export could not complete atomic output installation.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    details["byte_count"] = Value::from(byte_count);
    details["sha256"] = Value::String(sha256.clone());
    let (status, summary, message) = match commit {
        ArtifactCommit::Durable => (
            "pass",
            "Native report evidence CSV export completed.",
            "Native report evidence CSV was written atomically.".to_string(),
        ),
        ArtifactCommit::InstalledDurabilityUnknown(error) => (
            "warn",
            "Native CSV report export completed with an output-durability warning.",
            error,
        ),
    };
    findings.push(
        Finding::new(status, "native-export-report-csv.output", message).with_details(json!({
            "output": output_text,
            "row_count": row_count,
            "byte_count": byte_count,
            "sha256": sha256,
        })),
    );
    finish(
        repo_root,
        runner,
        summary,
        findings,
        details,
        Some(output),
        status_only,
    )
}

struct DirectJson {
    value: Value,
    config: Finding,
}

fn direct_json(
    repo_root: &Path,
    path: &str,
    runner: &dyn CommandRunner,
) -> Result<DirectJson, Vec<Finding>> {
    let call = guarded_direct_api_call(
        repo_root,
        path,
        "GET",
        None,
        None,
        "native-export-report-csv.direct-config-shape",
        "native-export-report-csv.direct-token-strength",
        runner,
    )?;
    validate_direct_json(call, path)
}

fn validate_direct_json(
    call: GuardedDirectApiCall,
    path: &str,
) -> Result<DirectJson, Vec<Finding>> {
    let ok = call.output.success
        && call.output.exit_code == Some(0)
        && !call.oversized
        && call.http_status == Some(200)
        && call.parsed.as_ref().is_some_and(Value::is_object);
    if !ok {
        return Err(vec![
            call.config,
            Finding::new(
                "fail",
                "native-export-report-csv.direct-response",
                "Direct native API request failed, exceeded its bound, returned non-200, or returned an invalid JSON object."
                    .into(),
            )
            .with_details(json!({
                "path": path,
                "exit_code": call.output.exit_code,
                "http_status": call.http_status,
                "oversized": call.oversized,
            })),
        ]);
    }
    Ok(DirectJson {
        value: call.parsed.expect("validated direct JSON object"),
        config: call.config,
    })
}

struct Page<'a> {
    total: usize,
    items: &'a [Value],
}

fn validate_page<'a>(
    value: &'a Value,
    report_id: &str,
    requested_page: usize,
    expected_total: Option<usize>,
    seen_ids: &BTreeSet<String>,
) -> Result<Page<'a>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "result page was not an object".to_string())?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "result page items were not an array".to_string())?;
    let page = object
        .get("page")
        .and_then(Value::as_object)
        .ok_or_else(|| "result page metadata was not an object".to_string())?;
    let total = exact_usize(page.get("total"))
        .ok_or_else(|| "result page total was not a non-negative integer".to_string())?;
    let observed_page = exact_usize(page.get("page"))
        .ok_or_else(|| "result page number was not a non-negative integer".to_string())?;
    if observed_page != requested_page {
        return Err("result page number did not match the request".into());
    }
    if expected_total.is_some_and(|expected| expected != total) {
        return Err("result page total changed during pagination".into());
    }
    let mut page_ids = BTreeSet::<String>::new();
    for item in items {
        let id = validate_result_row(item, report_id)?;
        if !page_ids.insert(id.to_string()) || seen_ids.contains(id) {
            return Err("result page repeated a result id".into());
        }
    }
    Ok(Page { total, items })
}

fn exact_usize(value: Option<&Value>) -> Option<usize> {
    value?
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
}

fn validate_result_row<'a>(value: &'a Value, report_id: &str) -> Result<&'a str, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "result row was not an object".to_string())?;
    let id = required_string(object, "id")?;
    if validate_operator_uuid(id, "result id").is_err() {
        return Err("result id was not a UUID".into());
    }
    if required_string(object, "source_report_id")? != report_id {
        return Err("result source_report_id did not match the requested report".into());
    }
    for field in ["host", "port", "nvt_oid", "name"] {
        required_string(object, field)?;
    }
    if !object.get("severity").is_some_and(Value::is_number) {
        return Err("result severity was not a number".into());
    }
    let qod = object
        .get("qod")
        .ok_or_else(|| "result qod was missing".to_string())?;
    if qod.as_i64().is_none() && qod.as_u64().is_none() {
        return Err("result qod was not an integer".into());
    }
    Ok(id)
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("result {field} was not a string"))
}

fn csv_row(row: &Value) -> Vec<String> {
    let object = row.as_object().expect("validated result object");
    let report = object.get("report").and_then(Value::as_object);
    let task = object.get("task").and_then(Value::as_object);
    let severity = object
        .get("severity")
        .and_then(Value::as_f64)
        .expect("validated severity");
    vec![
        csv_cell(object.get("id"), true),
        csv_cell(object.get("source_report_id"), true),
        csv_cell(report.and_then(|value| value.get("id")), true),
        csv_cell(report.and_then(|value| value.get("name")), true),
        csv_cell(task.and_then(|value| value.get("id")), true),
        csv_cell(task.and_then(|value| value.get("name")), true),
        csv_cell(object.get("host"), true),
        csv_cell(object.get("host_asset_id"), true),
        csv_cell(object.get("hostname"), true),
        csv_cell(object.get("port"), true),
        csv_cell(object.get("severity"), false),
        spreadsheet_safe(threat(severity)),
        csv_cell(object.get("qod"), false),
        csv_cell(object.get("nvt_oid"), true),
        csv_cell(object.get("name"), true),
        csv_cell(object.get("nvt_family"), true),
        csv_cell(object.get("cves"), true),
        csv_cell(object.get("cert_refs"), true),
        csv_cell(object.get("xrefs"), true),
        csv_cell(object.get("max_epss"), true),
        csv_cell(object.get("max_severity"), true),
        csv_cell(object.get("created_at"), true),
        csv_cell(object.get("scan_nvt_version"), true),
        csv_cell(object.get("description"), true),
        csv_cell(object.get("description_excerpt"), true),
        csv_cell(object.get("summary"), true),
        csv_cell(object.get("insight"), true),
        csv_cell(object.get("affected"), true),
        csv_cell(object.get("impact"), true),
        csv_cell(object.get("detection"), true),
        csv_cell(object.get("solution_type"), true),
        csv_cell(object.get("solution"), true),
        csv_cell(object.get("raw_evidence_href"), true),
        csv_cell(object.get("user_tags"), true),
        csv_cell(object.get("overrides"), true),
    ]
}

fn csv_cell(value: Option<&Value>, safe: bool) -> String {
    let text = match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Array(_) | Value::Object(_)) => {
            serde_json::to_string(value.expect("matched JSON collection")).unwrap_or_default()
        }
        Some(value) => value.to_string(),
    };
    if safe { spreadsheet_safe(&text) } else { text }
}

fn spreadsheet_safe(value: &str) -> String {
    if value.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_string()
    }
}

fn threat(score: f64) -> &'static str {
    if score >= 9.0 {
        "Critical"
    } else if score >= 7.0 {
        "High"
    } else if score >= 4.0 {
        "Medium"
    } else if score > 0.0 {
        "Low"
    } else if score == 0.0 {
        "Log"
    } else if score == -1.0 {
        "False Positive"
    } else {
        "Unknown"
    }
}

fn file_identity(file: &mut File) -> std::io::Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_count = byte_count
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("CSV byte count overflow"))?;
        digest.update(&buffer[..read]);
    }
    Ok((byte_count, format!("{:x}", digest.finalize())))
}

fn finish(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
    artifact: Option<PathBuf>,
    status_only: bool,
) -> ResultEnvelope {
    let mut outcome = envelope(repo_root, runner, summary, findings).with_details(details);
    if let Some(artifact) = artifact {
        outcome = outcome.with_artifacts(vec![artifact.display().to_string()]);
    }
    if status_only {
        outcome.findings = outcome
            .findings
            .iter()
            .filter(|finding| finding.status != "pass")
            .map(compact_finding)
            .collect();
        if outcome.findings.is_empty() {
            outcome.findings.push(Finding::new(
                "pass",
                "native-export-report-csv.status-only",
                "Native CSV report export completed; evidence content omitted.".into(),
            ));
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::os::fd::RawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    type CurlCall = (Vec<String>, BTreeMap<OsString, OsString>);

    struct Runner {
        responses: Mutex<VecDeque<ProcessOutput>>,
        calls: Mutex<Vec<CurlCall>>,
        private_header_seen: Mutex<bool>,
        race_target: Option<PathBuf>,
        race_after_call: usize,
    }

    impl Runner {
        fn new(responses: Vec<ProcessOutput>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
                private_header_seen: Mutex::new(false),
                race_target: None,
                race_after_call: usize::MAX,
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }

        #[allow(clippy::too_many_arguments)]
        fn run_with_input_and_fd(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
            _input: Option<&[u8]>,
            inherited_fd: RawFd,
        ) -> Option<ProcessOutput> {
            if program != "curl" {
                return None;
            }
            let header = std::fs::read_to_string(format!("/proc/self/fd/{inherited_fd}")).ok()?;
            *self.private_header_seen.lock().unwrap() = header
                .strip_prefix("Authorization: Bearer ")
                .and_then(|value| value.strip_suffix('\n'))
                .is_some_and(|token| token.len() >= 32);
            let mut calls = self.calls.lock().unwrap();
            calls.push((
                args.iter().map(|value| (*value).to_string()).collect(),
                env.cloned().unwrap_or_default(),
            ));
            if calls.len() == self.race_after_call
                && let Some(target) = &self.race_target
            {
                std::fs::write(target, b"raced output").ok()?;
            }
            drop(calls);
            self.responses.lock().unwrap().pop_front()
        }
    }

    fn response(value: Value, status: u16) -> ProcessOutput {
        ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: format!("{value}\n{status}"),
            stderr: String::new(),
        }
    }

    fn fixture(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-native-csv-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        std::fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn row(report_id: &str, id: &str, name: &str, severity: f64) -> Value {
        json!({
            "id": id,
            "source_report_id": report_id,
            "report": {"id": report_id, "name": "Full and fast report"},
            "task": {"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "name": "Daily scan"},
            "host": "192.0.2.10",
            "host_asset_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "hostname": "example.test",
            "port": "443/tcp",
            "severity": severity,
            "qod": 95,
            "nvt_oid": "1.3.6.1.4.1.25623.1.0.100001",
            "name": name,
            "nvt_family": "General",
            "cves": ["CVE-2026-0001"],
            "cert_refs": [],
            "xrefs": {"z": 1, "a": 2},
            "max_epss": {"score": 0.9, "percentile": 0.99},
            "max_severity": null,
            "created_at": "2026-07-10T12:00:00Z",
            "scan_nvt_version": "20260710T000000Z",
            "description": "private evidence body",
            "description_excerpt": "private evidence excerpt",
            "summary": "Summary",
            "insight": "Insight",
            "affected": "Affected",
            "impact": "Impact",
            "detection": "Detection",
            "solution_type": "VendorFix",
            "solution": "Upgrade",
            "raw_evidence_href": format!("/result/{id}"),
            "user_tags": [{"name": "Reviewed", "id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}],
            "overrides": [],
        })
    }

    fn temporary_files(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".tmp-"))
            })
            .collect()
    }

    #[test]
    fn invalid_arguments_make_no_runtime_request() {
        let (root, repo) = fixture("arguments");
        let runner = Runner::new(Vec::new());
        for result in [
            command_with_runner(
                &repo,
                "not-a-uuid",
                None,
                DEFAULT_MAX_RESULTS,
                false,
                false,
                &runner,
            ),
            command_with_runner(
                &repo,
                "11111111-1111-4111-8111-111111111111",
                None,
                0,
                false,
                false,
                &runner,
            ),
            command_with_runner(
                &repo,
                "11111111-1111-4111-8111-111111111111",
                None,
                MAX_RESULTS_LIMIT + 1,
                false,
                false,
                &runner,
            ),
        ] {
            assert_eq!(result.status, "fail");
            assert_eq!(
                result.findings[0].check,
                "native-export-report-csv.arguments"
            );
        }
        assert!(runner.calls.lock().unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_two_pages_privately_and_omits_evidence_from_status() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let first_id = "22222222-2222-4222-8222-222222222222";
        let second_id = "33333333-3333-4333-8333-333333333333";
        let first = row(report_id, first_id, "=formula", 7.5);
        let second = row(report_id, second_id, "Second", -1.0);
        let runner = Runner::new(vec![
            response(json!({"id": report_id, "name": "private report name"}), 200),
            response(
                json!({"items": [first], "page": {"page": 1, "page_size": 500, "total": 2}}),
                200,
            ),
            response(
                json!({"items": [second], "page": {"page": 2, "page_size": 500, "total": 2}}),
                200,
            ),
        ]);
        let (root, repo) = fixture("success");
        let output = root.join("report.csv");
        std::fs::write(&output, b"old output").unwrap();
        let result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            DEFAULT_MAX_RESULTS,
            true,
            true,
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(
            result.details.as_ref().unwrap()["sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert_eq!(result.details.as_ref().unwrap()["byte_count"], bytes.len());
        let mut reader = csv::Reader::from_reader(bytes.as_slice());
        let headers = reader.headers().unwrap().clone();
        assert_eq!(headers.iter().collect::<Vec<_>>(), CSV_FIELDS);
        let rows = reader.records().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(&rows[0][14], "'=formula");
        assert_eq!(&rows[0][10], "7.5");
        assert_eq!(&rows[1][10], "-1.0");
        assert_eq!(&rows[1][11], "False Positive");
        assert_eq!(&rows[0][18], "{\"a\":2,\"z\":1}");
        assert_eq!(
            &rows[0][33],
            "[{\"id\":\"cccccccc-cccc-4ccc-8ccc-cccccccccccc\",\"name\":\"Reviewed\"}]"
        );
        assert!(*runner.private_header_seen.lock().unwrap());
        for (args, env) in runner.calls.lock().unwrap().iter() {
            assert!(!args.join(" ").contains("Bearer "));
            assert!(
                !env.keys()
                    .any(|name| name.to_string_lossy().contains("TOKEN"))
            );
        }
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("private report name"));
        assert!(!encoded.contains("private evidence body"));
        assert!(!encoded.contains("formula"));
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zero_rows_is_a_complete_one_page_export() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let runner = Runner::new(vec![
            response(json!({"id": report_id, "name": "Report"}), 200),
            response(
                json!({"items": [], "page": {"page": 1, "page_size": 500, "total": 0}}),
                200,
            ),
        ]);
        let (root, repo) = fixture("empty");
        let output = root.join("report.csv");
        let result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            DEFAULT_MAX_RESULTS,
            false,
            false,
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["row_count"], 0);
        assert_eq!(result.details.as_ref().unwrap()["page_count"], 1);
        let mut reader = csv::Reader::from_path(&output).unwrap();
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            CSV_FIELDS
        );
        assert_eq!(reader.records().count(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cap_and_page_drift_preserve_existing_output() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let first_id = "22222222-2222-4222-8222-222222222222";
        for (label, responses, max_results) in [
            (
                "cap",
                vec![
                    response(json!({"id": report_id, "name": "Report"}), 200),
                    response(
                        json!({"items": [row(report_id, first_id, "First", 7.5)], "page": {"page": 1, "total": 2}}),
                        200,
                    ),
                ],
                1,
            ),
            (
                "drift",
                vec![
                    response(json!({"id": report_id, "name": "Report"}), 200),
                    response(
                        json!({"items": [row(report_id, first_id, "First", 7.5)], "page": {"page": 1, "total": 2}}),
                        200,
                    ),
                    response(json!({"items": [], "page": {"page": 2, "total": 3}}), 200),
                ],
                10,
            ),
        ] {
            let runner = Runner::new(responses);
            let (root, repo) = fixture(label);
            let output = root.join("report.csv");
            std::fs::write(&output, b"preserve").unwrap();
            let result = command_with_runner(
                &repo,
                report_id,
                Some(&output),
                max_results,
                true,
                false,
                &runner,
            );
            assert_eq!(result.status, "fail");
            assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
            assert!(temporary_files(&root).is_empty());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn typed_rows_and_duplicate_ids_fail_closed() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let id = "22222222-2222-4222-8222-222222222222";
        let seen = BTreeSet::from([id.to_string()]);
        for malformed in [
            json!({"items": [], "page": {"page": 2, "total": 0}}),
            json!({"items": []}),
            json!({"items": [], "page": {"page": 1, "total": -1}}),
        ] {
            assert!(validate_page(&malformed, report_id, 1, None, &BTreeSet::new()).is_err());
        }
        assert!(
            validate_page(
                &json!({"items": [row(report_id, id, "Duplicate", 7.5)], "page": {"page": 2, "total": 2}}),
                report_id,
                2,
                Some(2),
                &seen,
            )
            .is_err()
        );
        let mut invalid = row(report_id, id, "Invalid", 7.5);
        invalid["qod"] = Value::Bool(true);
        assert!(
            validate_page(
                &json!({"items": [invalid], "page": {"page": 1, "total": 1}}),
                report_id,
                1,
                None,
                &BTreeSet::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn no_clobber_commit_preserves_a_raced_destination() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let id = "22222222-2222-4222-8222-222222222222";
        let (root, repo) = fixture("race");
        let output = root.join("report.csv");
        let mut runner = Runner::new(vec![
            response(json!({"id": report_id, "name": "Report"}), 200),
            response(
                json!({"items": [row(report_id, id, "Finding", 7.5)], "page": {"page": 1, "total": 1}}),
                200,
            ),
        ]);
        runner.race_target = Some(output.clone());
        runner.race_after_call = 2;
        let result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            DEFAULT_MAX_RESULTS,
            false,
            false,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(std::fs::read(&output).unwrap(), b"raced output");
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
