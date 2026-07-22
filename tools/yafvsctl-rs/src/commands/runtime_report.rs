// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{prepare_secure_artifact_parent, write_secure_artifact};
use super::common::{metadata, runtime_dir};
use super::native_runtime::{
    NativeObjectPages, fetch_object_pages, native_api_get_json, native_page_finding,
    native_pages_ok, native_probe_finding, percent_encode_component,
};
use super::report_selection::latest_completed_full_test_report_id;
use super::runtime_performance_snapshot::service_running;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description;

const MAX_REPORT_RESULTS: usize = 100_000;
const MAX_TOP_RESULTS: usize = 100_000;
const MAX_REPORT_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
const REPORT_CSV_FIELDS: [&str; 13] = [
    "id",
    "host",
    "hostname",
    "port",
    "severity",
    "severity_score",
    "threat",
    "qod",
    "name",
    "nvt_oid",
    "nvt_name",
    "nvt_family",
    "description_excerpt",
];

#[derive(Clone, Copy)]
enum ReportMode {
    Summary,
    Export,
}

struct ReportPayloadInput<'a> {
    mode: ReportMode,
    report_id: &'a str,
    max_results: usize,
    top_results: usize,
    detail: &'a Map<String, Value>,
    pages: &'a NativeObjectPages,
    normalized_rows: &'a [Value],
    export_complete: bool,
}

impl ReportMode {
    fn command(self) -> &'static str {
        match self {
            Self::Summary => "runtime-report-summary",
            Self::Export => "runtime-report-export",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Export => "export",
        }
    }

    fn detail_check(self) -> &'static str {
        match self {
            Self::Summary => "runtime-report.summary-native-detail",
            Self::Export => "runtime-report.export-native-detail",
        }
    }

    fn results_check(self) -> &'static str {
        match self {
            Self::Summary => "runtime-report.summary-native-results",
            Self::Export => "runtime-report.export-native-results",
        }
    }

    fn canonical_name(self) -> &'static str {
        match self {
            Self::Summary => "summary.json",
            Self::Export => "export.json",
        }
    }

    fn failed_name(self) -> &'static str {
        match self {
            Self::Summary => "summary-failed.json",
            Self::Export => "export-failed.json",
        }
    }
}

pub fn command_runtime_report_summary(
    repo_root: &Path,
    report_id: Option<&str>,
    max_results: usize,
    top_results: usize,
) -> ResultEnvelope {
    report_command_with(
        repo_root,
        ReportMode::Summary,
        report_id,
        max_results,
        top_results,
        &SystemCommandRunner,
    )
}

pub fn command_runtime_report_export(
    repo_root: &Path,
    report_id: Option<&str>,
    max_results: usize,
    top_results: usize,
) -> ResultEnvelope {
    report_command_with(
        repo_root,
        ReportMode::Export,
        report_id,
        max_results,
        top_results,
        &SystemCommandRunner,
    )
}

pub fn command_runtime_report_metrics(repo_root: &Path, report_id: Option<&str>) -> ResultEnvelope {
    metrics_command_with(repo_root, report_id, &SystemCommandRunner)
}

fn report_command_with(
    repo_root: &Path,
    mode: ReportMode,
    report_id: Option<&str>,
    max_results: usize,
    top_results: usize,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/reports");
    let canonical = artifact_dir.join(mode.canonical_name());
    let failed = artifact_dir.join(mode.failed_name());
    let mut findings = artifact_parent_finding(
        &canonical,
        "runtime-report.artifact-dir",
        "Runtime report artifact directory is ready.",
        "Runtime report artifact directory is not usable",
    );
    if max_results == 0 || max_results > MAX_REPORT_RESULTS {
        findings.push(
            Finding::new(
                "fail",
                "runtime-report.max-results",
                format!("--max-results must be between 1 and {MAX_REPORT_RESULTS}."),
            )
            .with_details(json!({"value": max_results, "maximum": MAX_REPORT_RESULTS})),
        );
    }
    if top_results > MAX_TOP_RESULTS {
        findings.push(
            Finding::new(
                "fail",
                "runtime-report.top-results",
                format!("--top-results must be at most {MAX_TOP_RESULTS}."),
            )
            .with_details(json!({"value": top_results, "maximum": MAX_TOP_RESULTS})),
        );
    }
    let api_running = service_running(repo_root, "yafvs-api", runner);
    findings.push(Finding::new(
        if api_running { "pass" } else { "fail" },
        "native-api.container",
        if api_running {
            match mode {
                ReportMode::Summary => "yafvs-api container is running.".into(),
                ReportMode::Export => "yafvs-api container is running.".into(),
            }
        } else {
            match mode {
                ReportMode::Summary => "yafvs-api container is not running; start the app profile before reading native raw-report summaries.".into(),
                ReportMode::Export => "yafvs-api container is not running; start the app profile before exporting native raw-report data.".into(),
            }
        },
    ));
    let selected_report_id = select_report(
        repo_root,
        report_id,
        "runtime-report.report-select",
        &mut findings,
        runner,
    );
    if findings_failed(&findings) || selected_report_id.is_none() {
        let payload = report_prerequisite_payload(mode, selected_report_id.as_deref());
        return finish_result(
            repo_root,
            mode.command(),
            findings,
            &failed,
            &payload,
            None,
            runner,
        );
    }

    let selected_report_id = selected_report_id.expect("checked above");
    let encoded_report_id = percent_encode_component(&selected_report_id);
    let detail = native_api_get_json(
        repo_root,
        &format!("/api/v1/reports/{encoded_report_id}"),
        runner,
    );
    let detail_ok = detail.usable_object()
        && detail
            .object()
            .and_then(|object| object.get("id"))
            .and_then(value_text)
            .as_deref()
            == Some(selected_report_id.as_str());
    findings.push(native_probe_finding(
        if detail_ok { "pass" } else { "fail" },
        mode.detail_check(),
        if detail_ok {
            "Native raw-report detail read."
        } else {
            "Native raw-report detail response was not usable."
        },
        &detail,
        "/api/v1/reports/...",
    ));
    let pages = fetch_object_pages(
        repo_root,
        &format!("/api/v1/reports/{encoded_report_id}/results"),
        "-severity",
        max_results,
        runner,
    );
    let results_ok = native_pages_ok(&pages);
    findings.push(native_page_finding(
        if results_ok { "pass" } else { "fail" },
        mode.results_check(),
        if results_ok {
            "Native raw-report result rows read."
        } else {
            "Native raw-report result response was not usable."
        },
        &pages,
        "/api/v1/reports/.../results?...",
    ));
    if !detail_ok || !results_ok {
        let payload = json!({
            "status": "fail",
            "summary": format!(
                "Runtime report {} failed while reading native report data.",
                mode.noun()
            ),
            "generated_at": generated_at(),
            "details": {
                "source": "yafvs-api",
                "report_id": selected_report_id,
                "detail": detail.parsed,
                "results": pages.response.as_ref().and_then(|response| response.parsed.clone()),
            },
        });
        return finish_result(
            repo_root,
            mode.command(),
            findings,
            &failed,
            &payload,
            None,
            runner,
        );
    }

    let detail = detail.object().expect("validated above");
    let normalized_rows = pages.rows.iter().map(summary_row).collect::<Vec<_>>();
    let export_complete = pages
        .total
        .is_some_and(|total| normalized_rows.len() >= total);
    if !export_complete {
        findings.push(
            Finding::new(
                "warn",
                "runtime-report.completeness",
                "Runtime raw-report results were truncated by --max-results.".into(),
            )
            .with_details(json!({
                "parsed_result_count": normalized_rows.len(),
                "result_total": pages.total,
                "max_results": max_results,
            })),
        );
    }
    let mut payload = report_payload(ReportPayloadInput {
        mode,
        report_id: &selected_report_id,
        max_results,
        top_results,
        detail,
        pages: &pages,
        normalized_rows: &normalized_rows,
        export_complete,
    });
    let csv = if matches!(mode, ReportMode::Export) {
        match report_results_csv(&normalized_rows) {
            Ok(csv) => Some((artifact_dir.join("export-results.csv"), csv)),
            Err(error) => {
                findings.push(Finding::new("fail", "runtime-report.artifact-write", error));
                None
            }
        }
    } else {
        None
    };
    if findings_failed(&findings) {
        payload["status"] = Value::String("fail".into());
    }
    finish_result(
        repo_root,
        mode.command(),
        findings,
        &canonical,
        &payload,
        csv,
        runner,
    )
}

fn metrics_command_with(
    repo_root: &Path,
    report_id: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/metrics");
    let canonical = artifact_dir.join("report-metrics.json");
    let failed = artifact_dir.join("report-metrics-failed.json");
    let mut findings = artifact_parent_finding(
        &canonical,
        "runtime-metrics.artifact-dir",
        "Runtime metrics artifact directory is ready.",
        "Runtime metrics artifact directory is not usable",
    );
    let api_running = service_running(repo_root, "yafvs-api", runner);
    findings.push(Finding::new(
        if api_running { "pass" } else { "fail" },
        "native-api.container",
        if api_running {
            "yafvs-api container is running.".into()
        } else {
            "yafvs-api container is not running; start the app profile before reading native raw-report metrics.".into()
        },
    ));
    let selected_report_id = select_report(
        repo_root,
        report_id,
        "runtime-metrics.report-select",
        &mut findings,
        runner,
    );
    if findings_failed(&findings) || selected_report_id.is_none() {
        let payload = json!({
            "status": "fail",
            "summary": "Runtime report metrics stopped at native API prerequisites.",
            "generated_at": generated_at(),
            "details": {"source": "yafvs-api", "report_id": selected_report_id},
        });
        return finish_result(
            repo_root,
            "runtime-report-metrics",
            findings,
            &failed,
            &payload,
            None,
            runner,
        );
    }
    let selected_report_id = selected_report_id.expect("checked above");
    let response = native_api_get_json(
        repo_root,
        &format!(
            "/api/v1/reports/{}/metrics",
            percent_encode_component(&selected_report_id)
        ),
        runner,
    );
    let metrics_ok = response.usable_object()
        && response
            .object()
            .and_then(|object| object.get("summary"))
            .is_some_and(Value::is_object);
    let summary = if metrics_ok {
        "Runtime report metrics read through the native API."
    } else {
        "Runtime report metrics response did not include report metrics."
    };
    findings.push(native_probe_finding(
        if metrics_ok { "pass" } else { "fail" },
        "runtime-metrics.report-native",
        summary,
        &response,
        "/api/v1/reports/.../metrics",
    ));
    let payload = json!({
        "status": if metrics_ok { "pass" } else { "fail" },
        "summary": summary,
        "generated_at": generated_at(),
        "details": {
            "source": "yafvs-api",
            "report_id": selected_report_id,
            "metrics": response.parsed,
        },
    });
    finish_result(
        repo_root,
        "runtime-report-metrics",
        findings,
        if metrics_ok { &canonical } else { &failed },
        &payload,
        None,
        runner,
    )
}

fn select_report(
    repo_root: &Path,
    report_id: Option<&str>,
    check: &str,
    findings: &mut Vec<Finding>,
    runner: &dyn CommandRunner,
) -> Option<String> {
    if let Some(report_id) = report_id {
        findings.push(
            Finding::new("pass", check, "Using explicit raw report id.".into())
                .with_details(json!({"report_id": report_id})),
        );
        return Some(report_id.to_string());
    }
    match latest_completed_full_test_report_id(repo_root, runner) {
        Ok(report_id) => {
            findings.push(
                Finding::new(
                    "pass",
                    check,
                    "Selected latest completed full-test raw report from PostgreSQL.".into(),
                )
                .with_details(json!({"report_id": report_id})),
            );
            Some(report_id)
        }
        Err((message, output)) => {
            let mut finding = Finding::new("fail", check, message);
            if let Some(output) = output {
                finding =
                    finding.with_details(json!({"output_tail": tail_lines(&output.stdout, 80)}));
            }
            findings.push(finding);
            None
        }
    }
}

fn report_prerequisite_payload(mode: ReportMode, report_id: Option<&str>) -> Value {
    json!({
        "status": "fail",
        "summary": format!(
            "Runtime report {} stopped at native API prerequisites.",
            mode.noun()
        ),
        "generated_at": generated_at(),
        "details": {"source": "yafvs-api", "report_id": report_id},
    })
}

fn report_payload(input: ReportPayloadInput<'_>) -> Value {
    let ReportPayloadInput {
        mode,
        report_id,
        max_results,
        top_results,
        detail,
        pages,
        normalized_rows,
        export_complete,
    } = input;
    let task = detail.get("task").and_then(Value::as_object);
    let mut payload = json!({
        "status": if export_complete { "pass" } else { "warn" },
        "summary": format!("Runtime report {} read through the native API.", mode.noun()),
        "generated_at": generated_at(),
        "details": {"source": "yafvs-api", "report_id": report_id},
        "report": {
            "id": detail.get("id"),
            "name": detail.get("name"),
            "task_id": task.and_then(|task| task.get("id")),
            "task_name": task.and_then(|task| task.get("name")),
            "scan_run_status": detail.get("status"),
            "scan_start": detail.get("scan_start"),
            "scan_end": detail.get("scan_end"),
            "counts": {
                "hosts": json_int(detail.get("host_count")),
                "results": json_int(detail.get("result_count")),
                "vulnerabilities": json_int(detail.get("vulnerability_count")),
                "cves": json_int(detail.get("cve_count")),
                "operating_systems": Value::Null,
            },
        },
        "result_filter": format!(
            "native:/api/v1/reports/{report_id}/results?sort=-severity&max_results={max_results}"
        ),
        "parsed_result_count": normalized_rows.len(),
        "export_complete": export_complete,
        "severity_counts": severity_counts(&pages.rows),
        "affected_hosts": affected_hosts(&pages.rows),
        "top_results": normalized_rows.iter().take(top_results).cloned().collect::<Vec<_>>(),
    });
    if matches!(mode, ReportMode::Export) {
        payload["results"] = Value::Array(normalized_rows.to_vec());
    }
    payload
}

fn summary_row(row: &Map<String, Value>) -> Value {
    let severity_score = json_float(row.get("severity"));
    json!({
        "id": row.get("id"),
        "name": row.get("name"),
        "host": row.get("host"),
        "hostname": row.get("hostname"),
        "port": row.get("port"),
        "severity": python_severity_text(row.get("severity")),
        "severity_score": severity_score,
        "threat": threat(severity_score),
        "qod": json_int(row.get("qod")),
        "nvt_oid": row.get("nvt_oid"),
        "nvt_name": row.get("name"),
        "nvt_family": row.get("nvt_family"),
        "description_excerpt": row.get("description_excerpt"),
    })
}

fn severity_counts(rows: &[Map<String, Value>]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::from([
        ("Critical", 0),
        ("High", 0),
        ("Medium", 0),
        ("Low", 0),
        ("Log", 0),
        ("False Positive", 0),
        ("Unknown", 0),
    ]);
    for row in rows {
        *counts
            .entry(threat(json_float(row.get("severity"))))
            .or_default() += 1;
    }
    counts
}

#[derive(Default)]
struct HostSummary {
    hostnames: BTreeSet<String>,
    result_count: usize,
    vulnerability_count: usize,
    max_severity: f64,
    threats: BTreeSet<String>,
}

fn affected_hosts(rows: &[Map<String, Value>]) -> Vec<Value> {
    let mut hosts = BTreeMap::<String, HostSummary>::new();
    for row in rows {
        let host = row
            .get("host")
            .and_then(truthy_text)
            .unwrap_or_else(|| "unknown".into());
        let summary = hosts.entry(host).or_default();
        summary.result_count += 1;
        let severity = json_float(row.get("severity"));
        summary.max_severity = summary.max_severity.max(severity);
        if severity > 0.0 {
            summary.vulnerability_count += 1;
        }
        if let Some(hostname) = row.get("hostname").and_then(truthy_text) {
            summary.hostnames.insert(hostname);
        }
        summary.threats.insert(threat(severity).into());
    }
    let mut rows = hosts
        .into_iter()
        .map(|(host, summary)| {
            json!({
                "host": host,
                "hostnames": summary.hostnames,
                "result_count": summary.result_count,
                "vulnerability_count": summary.vulnerability_count,
                "max_severity": summary.max_severity,
                "threats": summary.threats,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right["max_severity"]
            .as_f64()
            .unwrap_or_default()
            .total_cmp(&left["max_severity"].as_f64().unwrap_or_default())
            .then_with(|| {
                left["host"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["host"].as_str().unwrap_or_default())
            })
    });
    rows
}

fn report_results_csv(rows: &[Value]) -> Result<String, String> {
    let mut csv = REPORT_CSV_FIELDS.join(",");
    csv.push_str("\r\n");
    for row in rows {
        let object = row.as_object();
        let line = REPORT_CSV_FIELDS
            .iter()
            .map(|field| csv_field(object.and_then(|object| object.get(*field))))
            .collect::<Vec<_>>()
            .join(",");
        let next_len = csv
            .len()
            .checked_add(line.len())
            .and_then(|length| length.checked_add(2))
            .ok_or_else(|| "Runtime report CSV output size overflowed.".to_string())?;
        if next_len > MAX_REPORT_ARTIFACT_BYTES {
            return Err(format!(
                "Runtime report CSV exceeded the {MAX_REPORT_ARTIFACT_BYTES} byte artifact limit."
            ));
        }
        csv.push_str(&line);
        csv.push_str("\r\n");
    }
    Ok(csv)
}

fn csv_field(value: Option<&Value>) -> String {
    let value = value.map_or_else(String::new, value_text_owned);
    let value = if value
        .chars()
        .find(|character| !character.is_whitespace() && !character.is_control())
        .is_some_and(|character| matches!(character, '=' | '+' | '-' | '@'))
    {
        format!("'{value}")
    } else {
        value
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
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

fn json_int(value: Option<&Value>) -> i64 {
    value
        .and_then(|value| match value {
            Value::Number(number) => number
                .as_i64()
                .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
                .or_else(|| number.as_f64().map(|value| value as i64)),
            Value::String(value) => value.parse::<i64>().ok(),
            Value::Bool(value) => Some(i64::from(*value)),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        })
        .unwrap_or_default()
}

fn json_float(value: Option<&Value>) -> f64 {
    value
        .and_then(|value| match value {
            Value::Number(number) => number.as_f64(),
            Value::String(value) => value.parse::<f64>().ok(),
            Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        })
        .filter(|value| value.is_finite())
        .unwrap_or_default()
}

fn python_severity_text(value: Option<&Value>) -> String {
    match value {
        None => String::new(),
        Some(Value::Null) => "None".into(),
        Some(value) => value_text_owned(value),
    }
}

fn truthy_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Bool(false) => None,
        Value::String(value) if value.is_empty() => None,
        Value::Number(value) if value.as_f64() == Some(0.0) => None,
        Value::Array(value) if value.is_empty() => None,
        Value::Object(value) if value.is_empty() => None,
        value => Some(value_text_owned(value)),
    }
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        value => Some(value_text_owned(value)),
    }
}

fn value_text_owned(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => if *value { "True" } else { "False" }.into(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn artifact_parent_finding(
    path: &Path,
    check: &str,
    pass_message: &str,
    fail_prefix: &str,
) -> Vec<Finding> {
    let parent = path.parent().unwrap_or(path);
    match prepare_secure_artifact_parent(path) {
        Ok(()) => vec![
            Finding::new("pass", check, pass_message.into())
                .with_path(&parent.display().to_string()),
        ],
        Err(error) => vec![
            Finding::new("fail", check, format!("{fail_prefix}: {error}"))
                .with_path(&parent.display().to_string()),
        ],
    }
}

fn finish_result(
    repo_root: &Path,
    command: &str,
    mut findings: Vec<Finding>,
    json_path: &Path,
    payload: &Value,
    csv: Option<(PathBuf, String)>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut artifacts = Vec::new();
    match write_bounded_json(json_path, payload) {
        Ok(()) => artifacts.push(json_path.display().to_string()),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-report.artifact-write",
                "Runtime report JSON artifact write failed closed.".into(),
            )
            .with_path(&json_path.display().to_string())
            .with_details(json!({"error": error})),
        ),
    }
    if let Some((path, contents)) = csv {
        match write_secure_artifact(&path, contents.as_bytes()) {
            Ok(()) => artifacts.push(path.display().to_string()),
            Err(error) => findings.push(
                Finding::new(
                    "fail",
                    "runtime-report.artifact-write",
                    "Runtime report CSV artifact write failed closed.".into(),
                )
                .with_path(&path.display().to_string())
                .with_details(json!({"error": error})),
            ),
        }
    }
    make_result(
        metadata(repo_root, command, runner),
        payload["summary"].as_str().unwrap_or_default().into(),
        findings,
    )
    .with_artifacts(artifacts)
}

fn write_bounded_json<T: Serialize>(path: &Path, payload: &T) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(payload).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_REPORT_ARTIFACT_BYTES {
        return Err(format!(
            "JSON artifact exceeded the {MAX_REPORT_ARTIFACT_BYTES} byte limit"
        ));
    }
    write_secure_artifact(path, &bytes)
}

fn findings_failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn generated_at() -> String {
    let format = format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second]+00:00",
    )
    .expect("static timestamp format");
    OffsetDateTime::now_utc()
        .format(&format)
        .unwrap_or_else(|_| "1970-01-01T00:00:00+00:00".into())
}

fn tail_lines(value: &str, lines: usize) -> Vec<String> {
    let rows = value.lines().collect::<Vec<_>>();
    rows[rows.len().saturating_sub(lines)..]
        .iter()
        .map(|line| (*line).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    struct Runner {
        outputs: Mutex<VecDeque<ProcessOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl Runner {
        fn new(outputs: impl IntoIterator<Item = ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            if program == "git" && args.ends_with(&["rev-parse", "--short", "HEAD"]) {
                return Some(process_output(true, "1d90f8e3\n"));
            }
            None
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            assert_eq!(program, "docker");
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|value| (*value).to_string()).collect());
            self.outputs.lock().unwrap().pop_front()
        }
    }

    fn process_output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 22 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn running_api_outputs() -> Vec<ProcessOutput> {
        vec![
            process_output(true, "api-container\n"),
            process_output(true, "true\n"),
        ]
    }

    fn temporary_repo(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "yafvsctl-runtime-report-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        repo
    }

    fn cleanup(repo: &Path) {
        if let Some(base) = repo.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }

    fn detail(report_id: &str) -> Value {
        json!({
            "id": report_id,
            "name": "Full test",
            "task": {"id": "task-1", "name": "Task"},
            "status": "Done",
            "scan_start": "2026-07-19T00:00:00Z",
            "scan_end": "2026-07-19T01:00:00Z",
            "host_count": "1",
            "result_count": 2,
            "vulnerability_count": 1,
            "cve_count": 1
        })
    }

    fn result_page(total: usize, name: &str) -> Value {
        json!({
            "items": [{
                "id": "result-1",
                "name": name,
                "host": "192.0.2.10",
                "hostname": "host.example",
                "port": "443/tcp",
                "severity": "9.1",
                "qod": "95",
                "nvt_oid": "1.3.6.1.4.1.25623.1.0.1",
                "nvt_family": "General",
                "description_excerpt": "private result evidence"
            }],
            "page": {"total": total}
        })
    }

    #[test]
    fn normalization_matches_report_contract_and_groups_hosts() {
        let rows = vec![
            json!({
                "id": "one", "name": "Critical", "host": "192.0.2.2",
                "hostname": "b.example", "severity": "9.1", "qod": "95"
            })
            .as_object()
            .unwrap()
            .clone(),
            json!({
                "id": "two", "name": "Log", "host": "192.0.2.1",
                "hostname": "a.example", "severity": 0, "qod": null
            })
            .as_object()
            .unwrap()
            .clone(),
            json!({
                "id": "three", "name": "False positive", "host": "192.0.2.2",
                "hostname": "b.example", "severity": -1
            })
            .as_object()
            .unwrap()
            .clone(),
        ];
        let normalized = summary_row(&rows[0]);
        assert_eq!(normalized["severity"], "9.1");
        assert_eq!(normalized["severity_score"], 9.1);
        assert_eq!(normalized["threat"], "Critical");
        assert_eq!(normalized["nvt_name"], "Critical");
        assert_eq!(normalized["qod"], 95);
        let counts = severity_counts(&rows);
        assert_eq!(counts["Critical"], 1);
        assert_eq!(counts["Log"], 1);
        assert_eq!(counts["False Positive"], 1);
        let hosts = affected_hosts(&rows);
        assert_eq!(hosts[0]["host"], "192.0.2.2");
        assert_eq!(hosts[0]["result_count"], 2);
        assert_eq!(hosts[0]["vulnerability_count"], 1);
        assert_eq!(hosts[0]["hostnames"], json!(["b.example"]));
        assert_eq!(hosts[1]["host"], "192.0.2.1");
    }

    #[test]
    fn csv_is_crlf_and_neutralizes_spreadsheet_formulas() {
        let csv = report_results_csv(&[json!({
            "id": "=1+1",
            "host": "192.0.2.10",
            "hostname": " host,one",
            "port": "443/tcp",
            "severity": "-1",
            "severity_score": -1.0,
            "threat": "False Positive",
            "qod": 95,
            "name": "+cmd",
            "nvt_oid": "@oid",
            "nvt_name": "safe",
            "nvt_family": "General",
            "description_excerpt": "line one\nline two"
        })])
        .unwrap();
        assert!(csv.starts_with("id,host,hostname,port,severity,severity_score,threat,qod,"));
        assert!(csv.contains("\r\n"));
        assert!(csv.ends_with("\r\n"));
        assert!(csv.contains("'=1+1"));
        assert!(csv.contains("'-1"));
        assert!(csv.contains("'+cmd"));
        assert!(csv.contains("'@oid"));
        assert!(csv.contains("\" host,one\""));
    }

    #[test]
    fn explicit_summary_writes_private_artifact_without_leaking_evidence_in_envelope() {
        let repo = temporary_repo("summary");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(true, &detail("report/one").to_string()),
            process_output(true, &result_page(1, "Private vulnerability").to_string()),
        ]);
        let runner = Runner::new(outputs);
        let result = report_command_with(
            &repo,
            ReportMode::Summary,
            Some("report/one"),
            1000,
            10,
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.artifacts.len(), 1);
        let path = repo
            .parent()
            .unwrap()
            .join("YAFVS-runtime/artifacts/reports/summary.json");
        assert_eq!(result.artifacts, vec![path.display().to_string()]);
        let payload: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(payload["status"], "pass");
        assert_eq!(payload["report"]["task_id"], "task-1");
        assert_eq!(payload["severity_counts"]["Critical"], 1);
        assert_eq!(
            payload["top_results"][0]["description_excerpt"],
            "private result evidence"
        );
        assert!(payload.get("results").is_none());
        assert!(payload.get("artifacts").is_none());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("private result evidence")
        );
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.last()
                .is_some_and(|value| value.contains("/api/v1/reports/report%2Fone/results?"))
        }));
        cleanup(&repo);
    }

    #[test]
    fn export_warns_when_capped_and_writes_formula_safe_csv() {
        let repo = temporary_repo("export");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(true, &detail("report").to_string()),
            process_output(
                true,
                &result_page(2, "=HYPERLINK(\"https://invalid\")").to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = report_command_with(&repo, ReportMode::Export, Some("report"), 1, 1, &runner);
        assert_eq!(result.status, "warn");
        assert_eq!(result.artifacts.len(), 2);
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime-report.completeness" && finding.status == "warn"
        }));
        let artifact_dir = repo
            .parent()
            .unwrap()
            .join("YAFVS-runtime/artifacts/reports");
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(artifact_dir.join("export.json")).unwrap())
                .unwrap();
        assert_eq!(payload["status"], "warn");
        assert_eq!(payload["export_complete"], false);
        assert_eq!(payload["results"].as_array().unwrap().len(), 1);
        let csv = fs::read_to_string(artifact_dir.join("export-results.csv")).unwrap();
        assert!(csv.contains("'=HYPERLINK"));
        cleanup(&repo);
    }

    #[test]
    fn unusable_detail_writes_failure_artifact_without_leaking_response() {
        let repo = temporary_repo("detail-fail");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(
                true,
                &json!({"id": "wrong-report", "private": "private detail evidence"}).to_string(),
            ),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = report_command_with(
            &repo,
            ReportMode::Summary,
            Some("report"),
            1000,
            10,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.artifacts.len(), 1);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("private detail evidence")
        );
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&result.artifacts[0]).unwrap()).unwrap();
        assert_eq!(
            payload["details"]["detail"]["private"],
            "private detail evidence"
        );
        cleanup(&repo);
    }

    #[test]
    fn metrics_writes_success_and_failure_artifacts() {
        let repo = temporary_repo("metrics");
        let mut outputs = running_api_outputs();
        outputs.push(process_output(
            true,
            &json!({"summary": {"critical": 1}, "private": "metrics evidence"}).to_string(),
        ));
        let runner = Runner::new(outputs);
        let result = metrics_command_with(&repo, Some("report/one"), &runner);
        assert_eq!(result.status, "pass");
        assert_eq!(result.artifacts.len(), 1);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("metrics evidence")
        );
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&result.artifacts[0]).unwrap()).unwrap();
        assert_eq!(payload["details"]["metrics"]["summary"]["critical"], 1);

        let mut outputs = running_api_outputs();
        outputs.push(process_output(true, &json!({"summary": null}).to_string()));
        let runner = Runner::new(outputs);
        let failed = metrics_command_with(&repo, Some("report/two"), &runner);
        assert_eq!(failed.status, "fail");
        assert!(failed.artifacts[0].ends_with("report-metrics-failed.json"));
        cleanup(&repo);
    }

    #[test]
    fn invalid_bounds_fail_before_native_reads() {
        let repo = temporary_repo("bounds");
        let runner = Runner::new([process_output(false, "")]);
        let result = report_command_with(
            &repo,
            ReportMode::Summary,
            Some("report"),
            0,
            MAX_TOP_RESULTS + 1,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime-report.max-results" && finding.status == "fail"
        }));
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime-report.top-results" && finding.status == "fail"
        }));
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        cleanup(&repo);
    }

    #[test]
    fn canonical_artifact_never_follows_existing_symlink() {
        let repo = temporary_repo("symlink");
        let artifact_dir = repo
            .parent()
            .unwrap()
            .join("YAFVS-runtime/artifacts/reports");
        fs::create_dir_all(&artifact_dir).unwrap();
        let victim = repo.join("victim.json");
        fs::write(&victim, "unchanged").unwrap();
        symlink(&victim, artifact_dir.join("summary.json")).unwrap();
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(true, &detail("report").to_string()),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = report_command_with(
            &repo,
            ReportMode::Summary,
            Some("report"),
            1000,
            10,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.artifacts.len(), 1);
        assert!(result.artifacts[0].ends_with("summary-failed.json"));
        assert!(
            fs::symlink_metadata(artifact_dir.join("summary.json"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "unchanged");
        cleanup(&repo);
    }
}
