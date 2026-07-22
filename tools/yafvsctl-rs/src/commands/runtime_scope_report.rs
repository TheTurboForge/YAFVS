// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{prepare_secure_artifact_parent, write_secure_artifact};
use super::common::{metadata, runtime_dir};
use super::native_runtime::{native_api_get_json, native_probe_finding, percent_encode_component};
use super::runtime_performance_snapshot::service_running;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::path::Path;
use time::OffsetDateTime;
use time::format_description;

const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const SCOPE_REPORTS_PATH: &str = "/api/v1/scope-reports?page_size=1&sort=-creation_time&filter=";

pub fn command_runtime_scope_report_summary(repo_root: &Path) -> ResultEnvelope {
    summary_with(repo_root, &SystemCommandRunner)
}

pub fn command_runtime_scope_report_metrics(
    repo_root: &Path,
    scope_report_id: Option<&str>,
) -> ResultEnvelope {
    metrics_with(repo_root, scope_report_id, &SystemCommandRunner)
}

fn summary_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/scope-reports");
    let canonical = artifact_dir.join("summary.json");
    let failed = artifact_dir.join("summary-failed.json");
    let mut findings = artifact_finding(
        &canonical,
        "runtime-scope.artifact-dir",
        "Runtime scope artifact directory is ready.",
        "Runtime scope artifact directory is not usable",
    );
    if !require_api(
        repo_root,
        runner,
        &mut findings,
        "yafvs-api container is not running; start the app profile before reading native scope-report summaries.",
    ) {
        return finish(
            repo_root,
            "runtime-scope-report-summary",
            findings,
            &failed,
            &stopped_payload("Runtime scope report summary stopped at native API prerequisites."),
            runner,
        );
    }

    let response = native_api_get_json(
        repo_root,
        &format!("{SCOPE_REPORTS_PATH}Organization"),
        runner,
    );
    let selected = response
        .object()
        .and_then(|listing| listing.get("items"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .and_then(|report| {
            report
                .get("scope")
                .and_then(Value::as_object)
                .map(|scope| (report, scope))
        });
    let usable = response.usable_object() && selected.is_some();
    findings.push(native_probe_finding(
        if usable { "pass" } else { "fail" },
        "runtime-scope.summary-native",
        if usable {
            "Latest Organization scope report read through the native API."
        } else {
            "No Organization scope report exists through the native API."
        },
        &response,
        "/api/v1/scope-reports?page_size=1&sort=-creation_time&filter=Organization",
    ));
    if !usable {
        return finish(
            repo_root,
            "runtime-scope-report-summary",
            findings,
            &failed,
            &failure_payload(
                "No Organization scope report exists through the native API.",
                &response,
            ),
            runner,
        );
    }
    let (report, scope) = selected.expect("checked above");
    let total = response
        .object()
        .and_then(|listing| listing.get("page"))
        .and_then(Value::as_object)
        .and_then(|page| page.get("total"))
        .cloned()
        .unwrap_or(Value::Null);
    let payload = json!({
        "status": "pass",
        "summary": "Latest Organization scope report read through the native API.",
        "generated_at": generated_at(),
        "details": {
            "source": "yafvs-api",
            "scope": summary_scope(report, scope, total),
            "scope_report": summary_report(report, scope),
        },
    });
    finish(
        repo_root,
        "runtime-scope-report-summary",
        findings,
        &canonical,
        &payload,
        runner,
    )
}

fn metrics_with(
    repo_root: &Path,
    filter: Option<&str>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/metrics");
    let canonical = artifact_dir.join("scope-report-metrics.json");
    let failed = artifact_dir.join("scope-report-metrics-failed.json");
    let mut findings = artifact_finding(
        &canonical,
        "runtime-metrics.artifact-dir",
        "Runtime metrics artifact directory is ready.",
        "Runtime metrics artifact directory is not usable",
    );
    if !require_api(
        repo_root,
        runner,
        &mut findings,
        "yafvs-api container is not running; start the app profile before reading native scope-report metrics.",
    ) {
        return finish(
            repo_root,
            "runtime-scope-report-metrics",
            findings,
            &failed,
            &stopped_payload("Runtime scope report metrics stopped at native API prerequisites."),
            runner,
        );
    }

    let filter = filter.unwrap_or("Organization");
    let display_path = format!("{SCOPE_REPORTS_PATH}{}", percent_encode_component(filter));
    let listing = native_api_get_json(repo_root, &display_path, runner);
    let selected = listing
        .object()
        .and_then(|listing| listing.get("items"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object);
    let selection = selected.and_then(|report| {
        let report_id = non_empty_text(report.get("id"))?;
        let scope = report.get("scope")?.as_object()?;
        let scope_id = non_empty_text(scope.get("id"))?;
        Some((report_id, scope_id, scope.clone()))
    });
    let selected_ok = listing.usable_object() && selection.is_some();
    findings.push(native_probe_finding(
        if selected_ok { "pass" } else { "fail" },
        "runtime-metrics.scope-report-native-select",
        if selected_ok {
            "Native scope report selected."
        } else {
            "Runtime scope report metrics failed because no matching scope report was found through the native API."
        },
        &listing,
        &display_path,
    ));
    if !selected_ok {
        return finish(
            repo_root,
            "runtime-scope-report-metrics",
            findings,
            &failed,
            &json!({
                "status": "fail",
                "summary": "Runtime scope report metrics failed because no matching scope report was found through the native API.",
                "generated_at": generated_at(),
                "details": {
                    "source": "yafvs-api",
                    "filter": filter,
                    "listing": listing.parsed,
                },
            }),
            runner,
        );
    }
    let (report_id, scope_id, scope) = selection.expect("checked above");
    let metrics_path = format!(
        "/api/v1/scopes/{}/reports/{}/metrics",
        percent_encode_component(&scope_id),
        percent_encode_component(&report_id),
    );
    let metrics = native_api_get_json(repo_root, &metrics_path, runner);
    let metrics_ok = metrics.usable_object()
        && metrics
            .object()
            .and_then(|object| object.get("summary"))
            .is_some_and(Value::is_object);
    findings.push(native_probe_finding(
        if metrics_ok { "pass" } else { "fail" },
        "runtime-metrics.scope-report-native",
        if metrics_ok {
            "Runtime scope report metrics read through the native API."
        } else {
            "Runtime scope report metrics response did not include scope report metrics."
        },
        &metrics,
        "/api/v1/scopes/.../reports/.../metrics",
    ));
    let payload = json!({
        "status": if metrics_ok { "pass" } else { "fail" },
        "summary": if metrics_ok {
            "Runtime scope report metrics read through the native API."
        } else {
            "Runtime scope report metrics response did not include scope report metrics."
        },
        "generated_at": generated_at(),
        "details": {
            "source": "yafvs-api",
            "scope": scope,
            "scope_report_id": report_id,
            "metrics": metrics.parsed,
        },
    });
    finish(
        repo_root,
        "runtime-scope-report-metrics",
        findings,
        if metrics_ok { &canonical } else { &failed },
        &payload,
        runner,
    )
}

fn require_api(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    findings: &mut Vec<Finding>,
    stopped_message: &str,
) -> bool {
    let running = service_running(repo_root, "yafvs-api", runner);
    findings.push(Finding::new(
        if running { "pass" } else { "fail" },
        "native-api.container",
        if running {
            "yafvs-api container is running.".into()
        } else {
            stopped_message.into()
        },
    ));
    running && !findings.iter().any(|finding| finding.status == "fail")
}

fn artifact_finding(
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

fn summary_scope(report: &Map<String, Value>, scope: &Map<String, Value>, total: Value) -> Value {
    let name = scope.get("name").cloned().unwrap_or(Value::Null);
    json!({"id":scope.get("id"), "name":name, "global":name.as_str() == Some("Organization"), "protection_requirement":protection_requirement(report.get("protection_requirement")), "target_count":json_int(report.get("source_target_count")), "host_count":json_int(report.get("member_host_count")), "scope_report_count":json_int(Some(&total))})
}

fn summary_report(report: &Map<String, Value>, scope: &Map<String, Value>) -> Value {
    json!({"id":report.get("id"), "name":report.get("name"), "scope_id":scope.get("id"), "scope_name":scope.get("name"), "created":report.get("creation_time"), "latest_evidence_time":report.get("latest_evidence_time"), "source_report_count":json_int(report.get("source_report_count")), "hosts_total":json_int(report.get("member_host_count")), "hosts_with_evidence":json_int(report.get("evidence_host_count")), "hosts_missing_evidence":json_int(report.get("missing_host_count")), "results_total":json_int(report.get("result_count")), "vulnerabilities_total":json_int(report.get("vulnerability_count")), "excluded_candidate_hosts":json_int(report.get("excluded_candidate_host_count")), "severity":report.get("severity").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({}))})
}

fn json_int(value: Option<&Value>) -> i64 {
    value
        .and_then(|value| match value {
            Value::Number(number) => number
                .as_i64()
                .or_else(|| {
                    number
                        .as_u64()
                        .and_then(|number| i64::try_from(number).ok())
                })
                .or_else(|| number.as_f64().map(|number| number as i64)),
            Value::String(value) => value.parse().ok(),
            Value::Bool(value) => Some(i64::from(*value)),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        })
        .unwrap_or_default()
}

fn protection_requirement(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase()
        .replace(char::from(32), "_")
}

fn non_empty_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn stopped_payload(summary: &str) -> Value {
    json!({"status":"fail", "summary":summary, "generated_at":generated_at(), "details":{"source":"yafvs-api"}})
}

fn failure_payload(summary: &str, response: &super::native_runtime::NativeJsonResponse) -> Value {
    json!({"status":"fail", "summary":summary, "generated_at":generated_at(), "details":{"source":"yafvs-api", "listing":response.parsed}})
}

fn finish(
    repo_root: &Path,
    command: &str,
    mut findings: Vec<Finding>,
    path: &Path,
    payload: &Value,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut artifacts = Vec::new();
    match write_payload(path, payload) {
        Ok(()) => artifacts.push(path.display().to_string()),
        Err(error) => findings.push(
            Finding::new(
                "fail",
                "runtime-scope.artifact-write",
                "Runtime scope report artifact write failed closed.".into(),
            )
            .with_path(&path.display().to_string())
            .with_details(json!({"error":error})),
        ),
    }
    make_result(
        metadata(repo_root, command, runner),
        payload["summary"].as_str().unwrap_or_default().into(),
        findings,
    )
    .with_artifacts(artifacts)
}

fn write_payload(path: &Path, payload: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(payload).map_err(|error| error.to_string())?;
    bytes.push(10);
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "JSON artifact exceeded the {MAX_ARTIFACT_BYTES} byte limit"
        ));
    }
    write_secure_artifact(path, &bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };
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
                Some(output(true, "ecce92aa\n"))
            } else {
                None
            }
        }
        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _: Option<&Path>,
            _: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            assert_eq!(program, "docker");
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|value| (*value).into()).collect());
            self.outputs.lock().unwrap().pop_front()
        }
    }
    fn output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 22 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    fn running() -> Vec<ProcessOutput> {
        vec![output(true, "api\n"), output(true, "true\n")]
    }
    fn repo(label: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir()
            .join(format!(
                "yafvsctl-scope-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
            .join("YAFVS");
        fs::create_dir_all(&root).unwrap();
        root
    }
    fn cleanup(repo: &Path) {
        let _ = fs::remove_dir_all(repo.parent().unwrap());
    }
    fn listing() -> Value {
        json!({"items":[{"id":"report/one", "name":"Latest", "creation_time":"2026-07-19", "latest_evidence_time":"2026-07-20", "protection_requirement":"High Assurance", "source_target_count":4, "member_host_count":3, "source_report_count":2, "evidence_host_count":2, "missing_host_count":1, "result_count":4, "vulnerability_count":1, "excluded_candidate_host_count":0, "severity":{"high":1}, "scope":{"id":"scope/one", "name":"Organization"}}], "page":{"total":7}})
    }

    #[test]
    fn summary_shapes_first_organization_report() {
        let repo = repo("summary");
        let mut outputs = running();
        outputs.push(output(true, &listing().to_string()));
        let result = summary_with(&repo, &Runner::new(outputs));
        assert_eq!(result.status, "pass");
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&result.artifacts[0]).unwrap()).unwrap();
        assert_eq!(
            payload["details"]["scope"]["protection_requirement"],
            "high_assurance"
        );
        assert_eq!(payload["details"]["scope"]["scope_report_count"], 7);
        assert_eq!(payload["details"]["scope"]["target_count"], 4);
        assert_eq!(payload["details"]["scope"]["host_count"], 3);
        assert_eq!(payload["details"]["scope_report"]["scope_id"], "scope/one");
        assert_eq!(payload["details"]["scope_report"]["hosts_total"], 3);
        assert_eq!(payload["details"]["scope_report"]["results_total"], 4);
        assert_eq!(payload["details"]["scope_report"]["severity"]["high"], 1);
        cleanup(&repo);
    }
    #[test]
    fn missing_listing_is_private_failure() {
        let repo = repo("missing-listing");
        let mut outputs = running();
        outputs.push(output(
            true,
            &json!({"private":"missing evidence"}).to_string(),
        ));
        let result = summary_with(&repo, &Runner::new(outputs));
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "No Organization scope report exists through the native API."
        );
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("missing evidence")
        );
        assert!(
            fs::read_to_string(&result.artifacts[0])
                .unwrap()
                .contains("missing evidence")
        );
        cleanup(&repo);
    }
    #[test]
    fn malformed_listing_is_private_failure() {
        let repo = repo("malformed");
        let mut outputs = running();
        outputs.push(output(
            true,
            &json!({"items":["bad"], "private":"evidence"}).to_string(),
        ));
        let result = summary_with(&repo, &Runner::new(outputs));
        assert_eq!(result.status, "fail");
        assert!(!serde_json::to_string(&result).unwrap().contains("evidence"));
        assert!(
            fs::read_to_string(&result.artifacts[0])
                .unwrap()
                .contains("evidence")
        );
        cleanup(&repo);
    }
    #[test]
    fn metrics_encodes_selection_and_path() {
        let repo = repo("metrics");
        let mut outputs = running();
        outputs.push(output(true, &listing().to_string()));
        outputs.push(output(
            true,
            &json!({"summary":{}, "private":"metrics"}).to_string(),
        ));
        let runner = Runner::new(outputs);
        let result = metrics_with(&repo, Some("Org / one"), &runner);
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.last()
                .is_some_and(|value| value.contains("filter=Org%20%2F%20one"))
        }));
        assert!(calls.iter().any(|call| call.last().is_some_and(|value| {
            value.contains("/scopes/scope%2Fone/reports/report%2Fone/metrics")
        })));
        cleanup(&repo);
    }
    #[test]
    fn missing_metrics_summary_fails_privately() {
        let repo = repo("missing-metrics");
        let mut outputs = running();
        outputs.push(output(true, &listing().to_string()));
        outputs.push(output(
            true,
            &json!({"summary":null, "private":"evidence"}).to_string(),
        ));
        let result = metrics_with(&repo, None, &Runner::new(outputs));
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime scope report metrics response did not include scope report metrics."
        );
        assert!(!serde_json::to_string(&result).unwrap().contains("evidence"));
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&result.artifacts[0]).unwrap()).unwrap();
        assert_eq!(payload["details"]["scope_report_id"], "report/one");
        assert_eq!(payload["details"]["metrics"]["private"], "evidence");
        cleanup(&repo);
    }
    #[test]
    fn symlinked_artifact_directory_fails_closed() {
        let repo = repo("symlink");
        let runtime = repo.parent().unwrap().join("YAFVS-runtime");
        let outside = repo.parent().unwrap().join("outside");
        fs::create_dir_all(runtime.join("artifacts")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, runtime.join("artifacts/scope-reports")).unwrap();
        let result = summary_with(&repo, &Runner::new([output(false, "")]));
        assert_eq!(result.status, "fail");
        assert!(result.artifacts.is_empty());
        assert!(!outside.join("summary-failed.json").exists());
        cleanup(&repo);
    }
    #[test]
    fn stopped_api_prerequisite_has_contract_summary() {
        let repo = repo("stopped");
        let result = summary_with(&repo, &Runner::new([output(false, "")]));
        assert_eq!(
            result.summary,
            "Runtime scope report summary stopped at native API prerequisites."
        );
        cleanup(&repo);
    }
}
