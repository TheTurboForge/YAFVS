// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{
    prepare_secure_artifact_parent, write_secure_artifact, write_secure_json_artifact,
};
use super::common::{expand_home, metadata, runtime_dir};
use super::native_runtime::{
    NativeJsonResponse, NativeObjectPages, fetch_object_pages, native_api_display_command,
    native_api_get_json, percent_encode_component,
};
use super::report_selection::latest_completed_full_test_report_id;
use super::runtime_performance_snapshot::service_running;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description;

const MAX_REPORT_ROWS: usize = 100_000;
const MAX_ADVISORY_REQUESTS: usize = 500;
const MAX_ADVISORY_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CERTBUND_IDS: usize = 10_000;
const MAX_CERTBUND_ID_BYTES: usize = 256;
const MAX_OUTPUT_ROWS: usize = 100_000;
const MAX_OUTPUT_TEXT_BYTES: usize = 64 * 1024 * 1024;
const CSV_FIELDS: [&str; 10] = [
    "IP",
    "Port",
    "Hostname",
    "OS",
    "Vulnerability",
    "Severity",
    "CVEs",
    "CertBUND-ID",
    "CertBUND-Severity",
    "CertBUND-Title",
];

pub fn command_runtime_certbund_report(
    repo_root: &Path,
    report_id: Option<&str>,
    task_id: Option<&str>,
    max_results: usize,
    max_hosts: usize,
    output_format: &str,
    output: Option<&str>,
) -> ResultEnvelope {
    command_with(
        repo_root,
        report_id,
        task_id,
        max_results,
        max_hosts,
        output_format,
        output,
        &SystemCommandRunner,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    repo_root: &Path,
    report_id: Option<&str>,
    task_id: Option<&str>,
    max_results: usize,
    max_hosts: usize,
    output_format: &str,
    output: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/reports");
    let mut findings = Vec::new();
    match prepare_secure_artifact_parent(&artifact_dir.join("certbund-report.json")) {
        Ok(()) => findings.push(
            Finding::new(
                "pass",
                "runtime-certbund-report.artifact-dir",
                "Runtime report artifact directory is ready.".into(),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-certbund-report.artifact-dir",
                format!("Runtime report artifact directory is not usable: {error}"),
            )
            .with_path(&artifact_dir.display().to_string()),
        ),
    }
    if report_id.is_some() && task_id.is_some() {
        findings.push(Finding::new(
            "fail",
            "runtime-certbund-report.selector",
            "Use either --report-id or --task-id, not both.".into(),
        ));
    }
    if !matches!(output_format, "json" | "csv") {
        findings.push(
            Finding::new(
                "fail",
                "runtime-certbund-report.format",
                "Output format must be 'json' or 'csv'.".into(),
            )
            .with_details(json!({"format": output_format})),
        );
    }
    for (name, value) in [("max-results", max_results), ("max-hosts", max_hosts)] {
        if value == 0 || value > MAX_REPORT_ROWS {
            findings.push(
                Finding::new(
                    "fail",
                    "runtime-certbund-report.limit",
                    format!("--{name} must be between 1 and {MAX_REPORT_ROWS}."),
                )
                .with_details(
                    json!({"argument": name, "value": value, "maximum": MAX_REPORT_ROWS}),
                ),
            );
        }
    }

    let api_running = service_running(repo_root, "yafvs-api", runner);
    findings.push(Finding::new(
        if api_running { "pass" } else { "fail" },
        "native-api.container",
        if api_running {
            "yafvs-api container is running.".into()
        } else {
            "yafvs-api container is not running; start the app profile before reading native CERT-Bund report data.".into()
        },
    ));

    let mut selected_report_id = report_id.map(str::to_string);
    let mut task_json = None;
    if let Some(task_id) = task_id.filter(|_| !findings_failed(&findings)) {
        let path = format!("/api/v1/tasks/{}", percent_encode_component(task_id));
        let response = native_api_get_json(repo_root, &path, runner);
        task_json = response.object().cloned().map(Value::Object);
        selected_report_id = task_json
            .as_ref()
            .and_then(|task| task.get("last_report"))
            .and_then(Value::as_object)
            .and_then(|report| report.get("id"))
            .and_then(nonempty_text);
        findings.push(native_probe_finding(
            if selected_report_id.is_some() {
                "pass"
            } else {
                "fail"
            },
            "runtime-certbund-report.task-read",
            if selected_report_id.is_some() {
                "Native task read resolved last report."
            } else {
                "Native task read did not resolve a last report."
            },
            &response,
            "/api/v1/tasks/...",
        ));
    } else if let Some(report_id) = &selected_report_id {
        findings.push(
            Finding::new(
                "pass",
                "runtime-certbund-report.report-select",
                "Using explicit raw report id.".into(),
            )
            .with_details(json!({"report_id": report_id})),
        );
    } else if !findings_failed(&findings) {
        match latest_completed_full_test_report_id(repo_root, runner) {
            Ok(report_id) => {
                selected_report_id = Some(report_id.clone());
                findings.push(
                    Finding::new(
                        "pass",
                        "runtime-certbund-report.report-select",
                        "Selected latest completed full-test raw report from PostgreSQL.".into(),
                    )
                    .with_details(json!({"report_id": report_id})),
                );
            }
            Err((message, output)) => {
                let mut finding =
                    Finding::new("fail", "runtime-certbund-report.report-select", message);
                if let Some(output) = output {
                    finding = finding
                        .with_details(json!({"output_tail": text_tail_lines(&output.stdout, 80)}));
                }
                findings.push(finding);
            }
        }
    }

    if findings_failed(&findings) || selected_report_id.is_none() {
        let payload = prerequisite_failure_payload(selected_report_id.as_deref(), task_id);
        return result_with_payload(
            repo_root,
            findings,
            &artifact_dir.join("certbund-report-failed.json"),
            &payload,
            payload["summary"].as_str().unwrap_or_default(),
            runner,
        );
    }

    let selected_report_id = selected_report_id.expect("checked above");
    let encoded_report_id = percent_encode_component(&selected_report_id);
    let results = fetch_object_pages(
        repo_root,
        &format!("/api/v1/reports/{encoded_report_id}/results"),
        "-severity",
        max_results,
        runner,
    );
    let results_ok = pages_ok(&results);
    findings.push(page_probe_finding(
        if results_ok { "pass" } else { "fail" },
        "runtime-certbund-report.results-read",
        if results_ok {
            "Native raw-report result rows read."
        } else {
            "Native raw-report result response was not usable."
        },
        &results,
        "/api/v1/reports/.../results?...",
    ));
    let hosts = fetch_object_pages(
        repo_root,
        &format!("/api/v1/reports/{encoded_report_id}/hosts"),
        "host",
        max_hosts,
        runner,
    );
    let hosts_ok = pages_ok(&hosts);
    findings.push(page_probe_finding(
        if hosts_ok { "pass" } else { "fail" },
        "runtime-certbund-report.hosts-read",
        if hosts_ok {
            "Native raw-report host rows read."
        } else {
            "Native raw-report host response was not usable."
        },
        &hosts,
        "/api/v1/reports/.../hosts?...",
    ));

    let mut cert_ids = certbund_ids(&results.rows);
    let discovered_cert_id_count = cert_ids.len();
    let cert_ids_truncated = discovered_cert_id_count > MAX_CERTBUND_IDS;
    cert_ids.truncate(MAX_CERTBUND_IDS);
    if cert_ids_truncated {
        findings.push(
            Finding::new(
                "warn",
                "runtime-certbund-report.cert-id-limit",
                "CERT-Bund identity processing was truncated at the bounded unique-id limit."
                    .into(),
            )
            .with_details(json!({
                "discovered": discovered_cert_id_count,
                "retained": cert_ids.len(),
                "limit": MAX_CERTBUND_IDS,
            })),
        );
    }
    let allowed_cert_ids = cert_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut advisories = BTreeMap::new();
    let mut missing_advisories = cert_ids
        .iter()
        .skip(MAX_ADVISORY_REQUESTS)
        .cloned()
        .collect::<Vec<_>>();
    if cert_ids.len() > MAX_ADVISORY_REQUESTS {
        findings.push(
            Finding::new(
                "warn",
                "runtime-certbund-report.advisory-limit",
                "CERT-Bund advisory enrichment was truncated at the bounded request limit.".into(),
            )
            .with_details(json!({
                "requested": cert_ids.len(),
                "request_limit": MAX_ADVISORY_REQUESTS,
                "not_requested": cert_ids.len() - MAX_ADVISORY_REQUESTS,
            })),
        );
    }
    let mut advisory_response_bytes = 0usize;
    let mut advisory_bytes_truncated = false;
    for (index, cert_id) in cert_ids.iter().take(MAX_ADVISORY_REQUESTS).enumerate() {
        let response = native_api_get_json(
            repo_root,
            &format!(
                "/api/v1/cert-bund-advisories/{}",
                percent_encode_component(cert_id)
            ),
            runner,
        );
        if response.usable_object() {
            let response_bytes = response.output.stdout.len();
            let Some(next_bytes) = advisory_response_bytes.checked_add(response_bytes) else {
                advisory_bytes_truncated = true;
                missing_advisories.extend(
                    cert_ids
                        .iter()
                        .skip(index)
                        .take(MAX_ADVISORY_REQUESTS - index)
                        .cloned(),
                );
                break;
            };
            if next_bytes > MAX_ADVISORY_RESPONSE_BYTES {
                advisory_bytes_truncated = true;
                missing_advisories.extend(
                    cert_ids
                        .iter()
                        .skip(index)
                        .take(MAX_ADVISORY_REQUESTS - index)
                        .cloned(),
                );
                break;
            }
            advisory_response_bytes = next_bytes;
            let object = response.object().expect("usable object checked");
            advisories.insert(
                cert_id.clone(),
                ["severity", "title"]
                    .into_iter()
                    .filter_map(|key| object.get(key).cloned().map(|value| (key.into(), value)))
                    .collect(),
            );
        } else {
            missing_advisories.push(cert_id.clone());
        }
    }
    if advisory_bytes_truncated {
        findings.push(
            Finding::new(
                "warn",
                "runtime-certbund-report.advisory-bytes-limit",
                "CERT-Bund advisory enrichment was truncated at the aggregate response-size limit."
                    .into(),
            )
            .with_details(json!({
                "retained_bytes": advisory_response_bytes,
                "byte_limit": MAX_ADVISORY_RESPONSE_BYTES,
            })),
        );
    }
    missing_advisories.sort();
    missing_advisories.dedup();
    if cert_ids.is_empty() {
        findings.push(Finding::new(
            "pass",
            "runtime-certbund-report.advisories-read",
            "No CERT-Bund refs were present in the fetched native result rows.".into(),
        ));
    } else {
        findings.push(
            Finding::new(
                if missing_advisories.is_empty() {
                    "pass"
                } else {
                    "warn"
                },
                "runtime-certbund-report.advisories-read",
                if missing_advisories.is_empty() {
                    "Native CERT-Bund advisory metadata read.".into()
                } else {
                    "Some CERT-Bund advisory metadata could not be read.".into()
                },
            )
            .with_details(json!({"requested": cert_ids, "missing": missing_advisories})),
        );
    }

    if !results_ok || !hosts_ok {
        let payload = json!({
            "status": "fail",
            "summary": "Runtime CERT-Bund report failed while reading native report data.",
            "generated_at": generated_at(),
            "details": {
                "source": "yafvs-api",
                "report_id": selected_report_id,
                "task_id": task_id,
                "results": results.response.as_ref().and_then(|response| response.parsed.clone()),
                "hosts": hosts.response.as_ref().and_then(|response| response.parsed.clone()),
            },
        });
        return result_with_payload(
            repo_root,
            findings,
            &artifact_dir.join("certbund-report-failed.json"),
            &payload,
            "Runtime CERT-Bund report failed while reading native report data.",
            runner,
        );
    }

    let results_complete = results
        .total
        .is_none_or(|total| results.rows.len() >= total);
    let hosts_complete = hosts.total.is_none_or(|total| hosts.rows.len() >= total);
    if !results_complete || !hosts_complete {
        findings.push(
            Finding::new(
                "warn",
                "runtime-certbund-report.completeness",
                "Runtime CERT-Bund report data was truncated by the requested row limits.".into(),
            )
            .with_details(json!({
                "results_complete": results_complete,
                "hosts_complete": hosts_complete,
                "max_results": max_results,
                "max_hosts": max_hosts,
            })),
        );
    }
    let (rows, rows_truncated) =
        certbund_report_rows(&results.rows, &hosts.rows, &advisories, &allowed_cert_ids);
    if rows_truncated {
        findings.push(
            Finding::new(
                "warn",
                "runtime-certbund-report.output-limit",
                "Runtime CERT-Bund report rows were truncated at the bounded output limit.".into(),
            )
            .with_details(json!({
                "row_limit": MAX_OUTPUT_ROWS,
                "text_byte_limit": MAX_OUTPUT_TEXT_BYTES,
                "retained_rows": rows.len(),
            })),
        );
    }
    let payload_status = if results_complete
        && hosts_complete
        && missing_advisories.is_empty()
        && !cert_ids_truncated
        && !rows_truncated
    {
        "pass"
    } else {
        "warn"
    };
    let payload = json!({
        "status": payload_status,
        "summary": "Runtime CERT-Bund report read through the native API.",
        "generated_at": generated_at(),
        "details": {
            "source": "yafvs-api",
            "report_id": selected_report_id,
            "task_id": task_id,
            "task": task_json,
        },
        "result_count_scanned": results.rows.len(),
        "result_total": results.total,
        "host_count_scanned": hosts.rows.len(),
        "host_total": hosts.total,
        "results_complete": results_complete,
        "hosts_complete": hosts_complete,
        "cert_bund_ids": cert_ids,
        "missing_advisories": missing_advisories,
        "row_count": rows.len(),
        "csv_fields": CSV_FIELDS,
        "rows": rows,
    });
    let mut artifacts = Vec::new();
    write_output(
        &artifact_dir.join("certbund-report.json"),
        &payload,
        true,
        &mut findings,
        &mut artifacts,
    );
    match output_format {
        "csv" => {
            let path =
                resolve_output_path(repo_root, output, artifact_dir.join("certbund-report.csv"));
            let csv = certbund_csv(payload["rows"].as_array().map(Vec::as_slice).unwrap_or(&[]));
            write_bytes_output(&path, csv.as_bytes(), &mut findings, &mut artifacts);
        }
        "json" => {
            if let Some(output) = output {
                let path = resolve_output_path(repo_root, Some(output), artifact_dir.clone());
                write_output(&path, &payload, false, &mut findings, &mut artifacts);
            }
        }
        _ => {}
    }
    make_result(
        metadata(repo_root, "runtime-certbund-report", runner),
        "Runtime CERT-Bund report read through the native API.".into(),
        findings,
    )
    .with_artifacts(artifacts)
}

fn prerequisite_failure_payload(report_id: Option<&str>, task_id: Option<&str>) -> Value {
    json!({
        "status": "fail",
        "summary": "Runtime CERT-Bund report stopped at native API prerequisites.",
        "generated_at": generated_at(),
        "details": {"source": "yafvs-api", "report_id": report_id, "task_id": task_id},
    })
}

fn result_with_payload(
    repo_root: &Path,
    mut findings: Vec<Finding>,
    path: &Path,
    payload: &Value,
    summary: &str,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut artifacts = Vec::new();
    write_output(path, payload, true, &mut findings, &mut artifacts);
    make_result(
        metadata(repo_root, "runtime-certbund-report", runner),
        summary.into(),
        findings,
    )
    .with_artifacts(artifacts)
}

fn write_output(
    path: &Path,
    payload: &Value,
    canonical: bool,
    findings: &mut Vec<Finding>,
    artifacts: &mut Vec<String>,
) {
    match write_secure_json_artifact(path, payload) {
        Ok(()) => artifacts.push(path.display().to_string()),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-certbund-report.artifact-write",
                if canonical {
                    "Runtime CERT-Bund canonical JSON artifact write failed closed.".into()
                } else {
                    "Runtime CERT-Bund requested JSON output write failed closed.".into()
                },
            )
            .with_path(&path.display().to_string())
            .with_details(json!({"error": error})),
        ),
    }
}

fn write_bytes_output(
    path: &Path,
    bytes: &[u8],
    findings: &mut Vec<Finding>,
    artifacts: &mut Vec<String>,
) {
    match write_secure_artifact(path, bytes) {
        Ok(()) => artifacts.push(path.display().to_string()),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-certbund-report.artifact-write",
                "Runtime CERT-Bund requested CSV output write failed closed.".into(),
            )
            .with_path(&path.display().to_string())
            .with_details(json!({"error": error})),
        ),
    }
}

fn resolve_output_path(repo_root: &Path, output: Option<&str>, default: PathBuf) -> PathBuf {
    let Some(output) = output else {
        return default;
    };
    let path = expand_home(PathBuf::from(output));
    if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    }
}

fn pages_ok(pages: &NativeObjectPages) -> bool {
    pages.error.is_none()
        && pages.total.is_some()
        && pages
            .response
            .as_ref()
            .is_some_and(|response| response.output.success && response.error.is_none())
}

fn page_probe_finding(
    status: &str,
    check: &str,
    message: &str,
    pages: &NativeObjectPages,
    display_path: &str,
) -> Finding {
    pages.response.as_ref().map_or_else(
        || {
            Finding::new(status, check, message.into()).with_details(json!({
                "exit_code": 1,
                "command": native_api_display_command(display_path),
                "response_summary": {"parsed": false},
                "error": pages.error,
            }))
        },
        |response| native_probe_finding(status, check, message, response, display_path),
    )
}

fn native_probe_finding(
    status: &str,
    check: &str,
    message: &str,
    response: &NativeJsonResponse,
    display_path: &str,
) -> Finding {
    let mut details = Map::new();
    details.insert(
        "exit_code".into(),
        response.output.exit_code.map_or(Value::Null, Value::from),
    );
    details.insert(
        "command".into(),
        Value::String(native_api_display_command(display_path)),
    );
    details.insert("response_summary".into(), summarize_response(response));
    if let Some(error) = &response.error {
        details.insert("error".into(), Value::String(error.clone()));
    }
    if !response.output.stdout.is_empty() {
        details.insert(
            "stdout_bytes".into(),
            Value::from(response.output.stdout.len()),
        );
    }
    if !response.output.stderr.is_empty() {
        details.insert(
            "stderr_bytes".into(),
            Value::from(response.output.stderr.len()),
        );
    }
    Finding::new(status, check, message.into()).with_details(Value::Object(details))
}

fn summarize_response(response: &NativeJsonResponse) -> Value {
    let Some(object) = response.object() else {
        return json!({"parsed": false});
    };
    let mut summary = Map::from_iter([("parsed".into(), Value::Bool(true))]);
    if let Some(page) = object.get("page").and_then(Value::as_object) {
        let bounded_page = ["page", "page_size", "total", "total_pages"]
            .into_iter()
            .filter_map(|key| {
                page.get(key)
                    .filter(|value| value.is_number())
                    .cloned()
                    .map(|value| (key.into(), value))
            })
            .collect();
        summary.insert("page".into(), Value::Object(bounded_page));
    }
    if let Some(items) = object.get("items").and_then(Value::as_array) {
        summary.insert("item_count_in_response".into(), Value::from(items.len()));
    }
    Value::Object(summary)
}

fn certbund_ids(results: &[Map<String, Value>]) -> Vec<String> {
    results
        .iter()
        .flat_map(|result| cert_ids_for_result(result).into_iter())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn cert_ids_for_result(result: &Map<String, Value>) -> Vec<String> {
    result
        .get("cert_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(value_text)
        .filter_map(|reference| certbund_id_from_ref(&reference))
        .collect()
}

fn certbund_id_from_ref(reference: &str) -> Option<String> {
    const PREFIX: &str = "cert-bund:";
    if !reference.to_ascii_lowercase().starts_with(PREFIX) {
        return None;
    }
    let id = reference[PREFIX.len()..].trim();
    (!id.is_empty() && id.len() <= MAX_CERTBUND_ID_BYTES && !id.chars().any(char::is_control))
        .then(|| id.to_string())
}

fn certbund_report_rows(
    results: &[Map<String, Value>],
    hosts: &[Map<String, Value>],
    advisories: &BTreeMap<String, Map<String, Value>>,
    allowed_cert_ids: &BTreeSet<String>,
) -> (Vec<BTreeMap<String, String>>, bool) {
    let hosts_by_ip = hosts
        .iter()
        .filter_map(|host| nonempty_field(host, "host").map(|ip| (ip.to_ascii_lowercase(), host)))
        .collect::<BTreeMap<_, _>>();
    let mut rows = Vec::new();
    let mut retained_text_bytes = 0usize;
    for result in results {
        let ids = cert_ids_for_result(result)
            .into_iter()
            .filter(|id| allowed_cert_ids.contains(id))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            continue;
        }
        let ip = nonempty_field(result, "host").unwrap_or_else(|| "N/A".into());
        let host = hosts_by_ip.get(&ip.to_ascii_lowercase()).copied();
        let hostname = nonempty_field(result, "hostname")
            .or_else(|| host.and_then(|host| nonempty_field(host, "hostname")))
            .unwrap_or_else(|| "N/A".into());
        let operating_system = host
            .and_then(|host| {
                nonempty_field(host, "best_os_txt").or_else(|| nonempty_field(host, "best_os_cpe"))
            })
            .unwrap_or_else(|| "N/A".into());
        let cves = result
            .get("cves")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(value_text)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        for id in ids {
            let advisory = advisories.get(&id);
            let row = BTreeMap::from([
                ("IP".into(), ip.clone()),
                (
                    "Port".into(),
                    nonempty_field(result, "port").unwrap_or_else(|| "N/A".into()),
                ),
                ("Hostname".into(), hostname.clone()),
                ("OS".into(), operating_system.clone()),
                (
                    "Vulnerability".into(),
                    nonempty_field(result, "name").unwrap_or_else(|| "N/A".into()),
                ),
                (
                    "Severity".into(),
                    field_text(result, "severity").unwrap_or_else(|| "N/A".into()),
                ),
                ("CVEs".into(), cves.clone()),
                ("CertBUND-ID".into(), id.clone()),
                (
                    "CertBUND-Severity".into(),
                    advisory
                        .and_then(|advisory| field_text(advisory, "severity"))
                        .unwrap_or_else(|| "N/A".into()),
                ),
                (
                    "CertBUND-Title".into(),
                    advisory
                        .and_then(|advisory| nonempty_field(advisory, "title"))
                        .unwrap_or_else(|| "N/A (could not be retrieved)".into()),
                ),
            ]);
            let row_bytes = row.values().map(String::len).sum::<usize>();
            let Some(next_text_bytes) = retained_text_bytes.checked_add(row_bytes) else {
                return (rows, true);
            };
            if rows.len() >= MAX_OUTPUT_ROWS || next_text_bytes > MAX_OUTPUT_TEXT_BYTES {
                return (rows, true);
            }
            retained_text_bytes = next_text_bytes;
            rows.push(row);
        }
    }
    (rows, false)
}

fn certbund_csv(rows: &[Value]) -> String {
    let mut csv = String::from("sep=,\n");
    csv.push_str(&CSV_FIELDS.join(","));
    csv.push('\n');
    for row in rows {
        let object = row.as_object();
        csv.push_str(
            &CSV_FIELDS
                .iter()
                .map(|field| {
                    csv_field(
                        object
                            .and_then(|object| object.get(*field))
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    csv
}

fn csv_field(value: &str) -> String {
    let value = if value
        .chars()
        .find(|character| !character.is_whitespace() && !character.is_control())
        .is_some_and(|character| matches!(character, '=' | '+' | '-' | '@'))
    {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

#[cfg(test)]
mod csv_tests {
    use super::csv_field;

    #[test]
    fn csv_neutralizes_spreadsheet_formula_cells() {
        for value in ["=cmd", "+cmd", "-1+2", "@SUM(A1:A2)", "  =cmd"] {
            assert!(csv_field(value).starts_with('\''));
        }
        assert_eq!(csv_field("ordinary"), "ordinary");
        assert_eq!(csv_field("1.0"), "1.0");
    }
}

fn field_text(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .filter(|value| !value.is_null())
        .and_then(value_text)
}

fn nonempty_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    field_text(object, key).filter(|value| !value.is_empty())
}

fn nonempty_text(value: &Value) -> Option<String> {
    value_text(value).filter(|value| !value.is_empty())
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(if *value { "True" } else { "False" }.into()),
        Value::Array(_) | Value::Object(_) => Some(value.to_string()),
    }
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

fn text_tail_lines(value: &str, lines: usize) -> Vec<String> {
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
            "yafvsctl-certbund-{label}-{}-{}",
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

    #[test]
    fn rows_expand_refs_and_apply_legacy_fallbacks() {
        let results = vec![
            json!({
                "host": "192.0.2.10",
                "port": "443/tcp",
                "name": "Example vulnerability",
                "severity": 7.5,
                "cves": ["CVE-2026-0001"],
                "cert_refs": ["CERT-BUND: CB-K14/1304", "cert-bund:CB-K14/1305"]
            })
            .as_object()
            .unwrap()
            .clone(),
        ];
        let hosts = vec![
            json!({"host": "192.0.2.10", "best_os_txt": "ExampleOS"})
                .as_object()
                .unwrap()
                .clone(),
        ];
        let advisories = BTreeMap::from([(
            "CB-K14/1304".into(),
            json!({"severity": 6.8, "title": "First advisory"})
                .as_object()
                .unwrap()
                .clone(),
        )]);
        let allowed = certbund_ids(&results).into_iter().collect();
        let (rows, truncated) = certbund_report_rows(&results, &hosts, &advisories, &allowed);
        assert!(!truncated);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["CertBUND-ID"], "CB-K14/1304");
        assert_eq!(rows[0]["CVEs"], "CVE-2026-0001");
        assert_eq!(rows[0]["OS"], "ExampleOS");
        assert_eq!(rows[1]["CertBUND-Severity"], "N/A");
        assert_eq!(rows[1]["CertBUND-Title"], "N/A (could not be retrieved)");
    }

    #[test]
    fn csv_matches_python_minimal_quoting_and_lf_contract() {
        let rows = vec![json!({
            "IP": "192.0.2.10",
            "Port": "443/tcp",
            "Hostname": "host,one",
            "OS": "Example \"OS\"",
            "Vulnerability": "line one\nline two",
            "Severity": "7.5",
            "CVEs": "CVE-1, CVE-2",
            "CertBUND-ID": "CB-K14/1304",
            "CertBUND-Severity": "8.1",
            "CertBUND-Title": "Title"
        })];
        assert_eq!(
            certbund_csv(&rows),
            "sep=,\nIP,Port,Hostname,OS,Vulnerability,Severity,CVEs,CertBUND-ID,CertBUND-Severity,CertBUND-Title\n192.0.2.10,443/tcp,\"host,one\",\"Example \"\"OS\"\"\",\"line one\nline two\",7.5,\"CVE-1, CVE-2\",CB-K14/1304,8.1,Title\n"
        );
    }

    #[test]
    fn cert_ids_are_unique_sorted_while_rows_preserve_ref_order() {
        let results = vec![
            json!({"cert_refs": ["cert-bund:Z", "cert-bund:A", "cert-bund:Z"]})
                .as_object()
                .unwrap()
                .clone(),
        ];
        assert_eq!(certbund_ids(&results), vec!["A", "Z"]);
        assert_eq!(cert_ids_for_result(&results[0]), vec!["Z", "A", "Z"]);
    }

    #[test]
    fn explicit_report_writes_private_canonical_json_and_relative_csv() {
        let repo = temporary_repo("explicit");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(
                true,
                &json!({
                    "items": [{
                        "host": "192.0.2.10",
                        "port": "443/tcp",
                        "name": "Example",
                        "severity": 7.5,
                        "cert_refs": ["cert-bund:CB-K14/1304"]
                    }],
                    "page": {"total": 1}
                })
                .to_string(),
            ),
            process_output(
                true,
                &json!({"items": [{"host": "192.0.2.10", "best_os_txt": "ExampleOS"}], "page": {"total": 1}}).to_string(),
            ),
            process_output(
                true,
                &json!({"id": "CB-K14/1304", "severity": 8.1, "title": "private advisory evidence"}).to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = command_with(
            &repo,
            Some("report/one"),
            None,
            1000,
            5000,
            "csv",
            Some("out/report.csv"),
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.artifacts.len(), 2);
        let canonical = repo
            .parent()
            .unwrap()
            .join("YAFVS-runtime/artifacts/reports/certbund-report.json");
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&canonical).unwrap()).unwrap();
        assert_eq!(payload["status"], "pass");
        assert_eq!(payload["row_count"], 1);
        assert!(payload.get("artifacts").is_none());
        assert!(
            fs::read_to_string(repo.join("out/report.csv"))
                .unwrap()
                .starts_with("sep=,\nIP,Port,Hostname")
        );
        let envelope = serde_json::to_string(&result).unwrap();
        assert!(!envelope.contains("private advisory evidence"));
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.last()
                .is_some_and(|value| value.contains("/api/v1/reports/report%2Fone/results?"))
        }));
        cleanup(&repo);
    }

    #[test]
    fn task_selector_uses_encoded_task_and_last_report_components() {
        let repo = temporary_repo("task");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(
                true,
                &json!({"id": "task/one", "last_report": {"id": "report/one"}}).to_string(),
            ),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = command_with(
            &repo,
            None,
            Some("task/one"),
            1000,
            5000,
            "json",
            None,
            &runner,
        );
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.last()
                .is_some_and(|value| value.ends_with("/api/v1/tasks/task%2Fone"))
        }));
        assert!(calls.iter().any(|call| {
            call.last()
                .is_some_and(|value| value.contains("/api/v1/reports/report%2Fone/results?"))
        }));
        cleanup(&repo);
    }

    #[test]
    fn latest_selector_runs_exact_completed_full_test_query() {
        let repo = temporary_repo("latest");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(true, "postgres-container\n"),
            process_output(true, "true\n"),
            process_output(true, "WARNING: fixture\nlatest-report\n"),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = command_with(&repo, None, None, 1000, 5000, "json", None, &runner);
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        let query_call = calls
            .iter()
            .find(|call| {
                call.iter()
                    .any(|arg| arg.contains("SELECT r.uuid FROM reports"))
            })
            .unwrap();
        let query = query_call
            .iter()
            .find(|arg| arg.contains("SELECT r.uuid FROM reports"))
            .unwrap();
        assert!(query.contains("t.name LIKE 'YAFVS full test scan %'"));
        assert!(query.contains("coalesce(r.scan_run_status, 0) = 1"));
        assert!(query.contains("ORDER BY coalesce(r.end_time, 0) DESC"));
        cleanup(&repo);
    }

    #[test]
    fn selector_conflict_and_stopped_api_write_failure_artifacts() {
        let repo = temporary_repo("prerequisites");
        let runner = Runner::new([process_output(true, "")]);
        let result = command_with(
            &repo,
            Some("report"),
            Some("task"),
            1000,
            5000,
            "json",
            None,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "runtime-certbund-report.selector")
        );
        assert_eq!(result.artifacts.len(), 1);
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&result.artifacts[0]).unwrap()).unwrap();
        assert_eq!(payload["status"], "fail");
        cleanup(&repo);
    }

    #[test]
    fn missing_advisory_and_result_cap_warn_in_envelope_and_payload() {
        let repo = temporary_repo("warn");
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(
                true,
                &json!({"items": [{"host": "192.0.2.10", "cert_refs": ["cert-bund:CB-1"]}], "page": {"total": 2}}).to_string(),
            ),
            process_output(
                true,
                &json!({"items": [{"host": "192.0.2.10"}], "page": {"total": 1}}).to_string(),
            ),
            process_output(false, "not found"),
        ]);
        let runner = Runner::new(outputs);
        let result = command_with(&repo, Some("report"), None, 1, 5000, "json", None, &runner);
        assert_eq!(result.status, "warn");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime-certbund-report.completeness" && finding.status == "warn"
        }));
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&result.artifacts[0]).unwrap()).unwrap();
        assert_eq!(payload["status"], "warn");
        assert_eq!(payload["results_complete"], false);
        assert_eq!(payload["missing_advisories"], json!(["CB-1"]));
        cleanup(&repo);
    }

    #[test]
    fn requested_output_symlink_is_refused_without_touching_victim() {
        let repo = temporary_repo("symlink");
        let victim = repo.join("victim.csv");
        fs::write(&victim, "unchanged").unwrap();
        let link = repo.join("report.csv");
        symlink(&victim, &link).unwrap();
        let mut outputs = running_api_outputs();
        outputs.extend([
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
            process_output(
                true,
                &json!({"items": [], "page": {"total": 0}}).to_string(),
            ),
        ]);
        let runner = Runner::new(outputs);
        let result = command_with(
            &repo,
            Some("report"),
            None,
            1000,
            5000,
            "csv",
            Some(link.strip_prefix(&repo).unwrap().to_str().unwrap()),
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "unchanged");
        assert!(result.findings.iter().any(|finding| {
            finding.check == "runtime-certbund-report.artifact-write" && finding.status == "fail"
        }));
        cleanup(&repo);
    }
}
