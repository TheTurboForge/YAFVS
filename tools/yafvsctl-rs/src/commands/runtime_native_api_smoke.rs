// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::write_secure_json_artifact;
use super::common::{compact_finding, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::native_runtime::{native_api_get_json, native_probe_finding, NativeJsonResponse};
use super::runtime_health::container_running;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{make_result, Finding, ResultEnvelope};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

const SERVICE: &str = "yafvs-api";
const ARTIFACT_RELATIVE_PATH: &str = "artifacts/native-api/native-api-smoke.json";
const ROUTES_FILE: &str = "services/yafvs-api/src/read_api_routes.rs";
const SERVICE_LOG_TAIL_LINES: usize = 80;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

const EXPECTED_FEED_TYPES: [&str; 4] = ["NVT", "SCAP", "CERT", "GVMD_DATA"];
const ALLOWED_TRASHCAN_ITEM_KEYS: [&str; 8] = [
    "id",
    "resource_type",
    "entity_type",
    "title",
    "name",
    "comment",
    "creation_time",
    "modification_time",
];
const FORBIDDEN_TRASHCAN_ITEM_KEYS: [&str; 14] = [
    "password",
    "value",
    "hosts",
    "exclude_hosts",
    "scanner_credential",
    "credential_location",
    "ca_pub",
    "relay_host",
    "method_data",
    "condition_data",
    "event_data",
    "nvt_selector",
    "preferences",
    "port",
];

pub fn command_runtime_native_api_smoke(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_runtime_native_api_smoke_with_runner(repo_root, status_only, &SystemCommandRunner)
}

pub(crate) fn command_runtime_native_api_smoke_with_runner(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_path = runtime_dir(repo_root).join(ARTIFACT_RELATIVE_PATH);
    let mut findings = Vec::new();
    let mut details = Map::from_iter([("service".into(), Value::String(SERVICE.into()))]);
    let environment = runtime_environment(repo_root);
    let running = container_running(runner, repo_root, SERVICE, &environment);
    findings.push(
        Finding::new(
            if running { "pass" } else { "fail" },
            "native-api.running",
            if running {
                "yafvs-api container is running."
            } else {
                "yafvs-api container is not running; run just runtime-app-up."
            }
            .into(),
        )
        .with_details(json!({
            "service": SERVICE,
            "logs_tail": if running { Vec::new() } else { service_log_tail(repo_root, runner) },
        })),
    );
    if !running {
        return finish(
            repo_root,
            runner,
            "Native API smoke could not run because yafvs-api is not running.",
            findings,
            details,
            artifact_path,
            status_only,
        );
    }

    let health = native_api_get_json(repo_root, "/healthz", runner);
    details.insert("health".into(), response_summary(&health));
    findings.push(native_probe_finding(
        if health.output.success
            && health.error.is_none()
            && health
                .object()
                .is_some_and(|object| object.get("status").and_then(Value::as_str) == Some("ok"))
        {
            "pass"
        } else {
            "fail"
        },
        "native-api.healthz",
        &format!(
            "Native API health probe exit code {}.",
            exit_code(&health.output)
        ),
        &health,
        "/healthz",
    ));

    let feeds = native_api_get_json(repo_root, "/api/v1/feeds", runner);
    details.insert("feeds".into(), response_summary(&feeds));
    let feed_types = observed_feed_types(feeds.object());
    let mut expected_feed_types = EXPECTED_FEED_TYPES;
    expected_feed_types.sort_unstable();
    let feeds_ok = feeds.usable_object() && feed_contract_ok(feeds.object());
    findings.push(
        native_probe_finding(
            if feeds_ok { "pass" } else { "fail" },
            "native-api.feeds",
            if feeds_ok {
                "Native API feed inventory probe returned fixed feed metadata/status rows."
            } else {
                "Native API feed inventory probe failed or returned unexpected payload data."
            },
            &feeds,
            "/api/v1/feeds",
        )
        .with_details(json!({
            "exit_code": feeds.output.exit_code,
            "command": super::native_runtime::native_api_display_command("/api/v1/feeds"),
            "response_summary": response_summary(&feeds),
            "expected_types": expected_feed_types,
            "observed_types": feed_types,
            "error": feeds.error,
            "stdout_bytes": feeds.output.stdout.len(),
            "stderr_bytes": feeds.output.stderr.len(),
        })),
    );

    if route_declared(repo_root, ".route(\"/api/v1/trashcan/summary\"") {
        let summary = native_api_get_json(repo_root, "/api/v1/trashcan/summary", runner);
        details.insert("trashcan_summary".into(), response_summary(&summary));
        let summary_ok = summary.usable_object() && trashcan_summary_ok(summary.object());
        findings.push(native_probe_finding(
            if summary_ok { "pass" } else { "fail" },
            "native-api.trashcan-summary",
            if summary_ok {
                "Native API Trashcan counts-only summary probe returned summary JSON."
            } else {
                "Native API Trashcan summary probe failed or returned non-summary payload data."
            },
            &summary,
            "/api/v1/trashcan/summary",
        ));
    } else {
        findings.push(
            Finding::new(
                "pass",
                "native-api.trashcan-summary.deferred",
                "Trashcan counts-only summary route is not declared yet; runtime probe is deferred until the implementation lands.".into(),
            )
            .with_details(json!({
                "path": "/api/v1/trashcan/summary",
                "row_level_trash_data": "inherited/deferred",
            })),
        );
    }

    if route_declared(repo_root, ".route(\"/api/v1/trashcan/items\"") {
        let items = native_api_get_json(repo_root, "/api/v1/trashcan/items?page_size=1", runner);
        details.insert("trashcan_items".into(), response_summary(&items));
        let (items_ok, unexpected_keys, forbidden_keys) = trashcan_items_ok(items.object());
        findings.push(native_probe_finding(
            if items.usable_object() && items_ok { "pass" } else { "fail" },
            "native-api.trashcan-items",
            if items.usable_object() && items_ok {
                "Native API Trashcan redacted item probe returned redacted collection JSON."
            } else {
                "Native API Trashcan item probe failed or returned non-redacted payload data."
            },
            &items,
            "/api/v1/trashcan/items?page_size=1",
        )
        .with_details(json!({
            "exit_code": items.output.exit_code,
            "command": super::native_runtime::native_api_display_command("/api/v1/trashcan/items?page_size=1"),
            "response_summary": response_summary(&items),
            "unexpected_keys": unexpected_keys,
            "forbidden_keys": forbidden_keys,
            "error": items.error,
            "stdout_bytes": items.output.stdout.len(),
            "stderr_bytes": items.output.stderr.len(),
        })));
    }

    finish(
        repo_root,
        runner,
        "Native API smoke completed.",
        findings,
        details,
        artifact_path,
        status_only,
    )
}

fn finish(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Map<String, Value>,
    artifact_path: std::path::PathBuf,
    status_only: bool,
) -> ResultEnvelope {
    let artifact_dir = artifact_path.parent().expect("artifact path has a parent");
    let mut result = make_result(
        super::common::metadata(repo_root, "runtime-native-api-smoke", runner),
        summary.into(),
        findings,
    )
    .with_artifacts(vec![artifact_dir.display().to_string()])
    .with_details(Value::Object(details));
    if let Err(error) = write_secure_json_artifact(&artifact_path, &result) {
        result.status = "fail".into();
        result.findings.push(
            Finding::new(
                "fail",
                "native-api.artifact",
                "Native API smoke artifact could not be written securely.".into(),
            )
            .with_path(&artifact_path.display().to_string())
            .with_details(json!({ "error": error })),
        );
    }
    if status_only {
        status_only_result(result)
    } else {
        result
    }
}

fn status_only_result(mut result: ResultEnvelope) -> ResultEnvelope {
    let non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let important_checks = result
        .findings
        .iter()
        .filter(|finding| {
            finding.status != "pass"
                || matches!(
                    finding.check.as_str(),
                    "native-api.running" | "native-api.healthz"
                )
        })
        .map(|finding| (finding.check.clone(), Value::String(finding.status.clone())))
        .collect::<Map<_, _>>();
    let service = result
        .details
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|details| details.get("service"))
        .cloned()
        .unwrap_or(Value::Null);
    result.details = Some(json!({
        "service": service,
        "finding_count": result.findings.len(),
        "non_pass_count": non_pass.len(),
        "artifact_count": result.artifacts.len(),
        "important_checks": important_checks,
    }));
    result.findings = if non_pass.is_empty() {
        vec![Finding::new(
            "pass",
            "runtime-native-api-smoke.status-only",
            "runtime-native-api-smoke passed; no non-pass findings.".into(),
        )]
    } else {
        non_pass
    };
    result
}

fn service_log_tail(repo_root: &Path, runner: &dyn CommandRunner) -> Vec<String> {
    let args = compose_command(
        repo_root,
        &[
            "logs".into(),
            "--tail".into(),
            SERVICE_LOG_TAIL_LINES.to_string(),
            SERVICE.into(),
        ],
    );
    let output = runner
        .run_with(
            "docker",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(COMMAND_TIMEOUT),
        )
        .unwrap_or_else(failed_output);
    output_tail(&output.stdout, SERVICE_LOG_TAIL_LINES)
}

fn failed_output() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn exit_code(output: &ProcessOutput) -> i32 {
    output.exit_code.unwrap_or(1)
}

fn response_summary(response: &NativeJsonResponse) -> Value {
    let Some(object) = response.object() else {
        return json!({"parsed": false});
    };
    let mut summary = Map::from_iter([("parsed".into(), Value::Bool(true))]);
    for key in ["status", "database", "id"] {
        if let Some(value) = object.get(key) {
            summary.insert(key.into(), value.clone());
        }
    }
    for key in ["page", "summary", "policy"] {
        if let Some(value) = object.get(key).filter(|value| value.is_object()) {
            summary.insert(key.into(), value.clone());
        }
    }
    if let Some(error) = object.get("error").and_then(Value::as_object) {
        summary.insert(
            "error".into(),
            Value::Object(
                error
                    .iter()
                    .filter(|(key, _)| matches!(key.as_str(), "code" | "message"))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(items) = object.get("items").and_then(Value::as_array) {
        summary.insert("item_count_in_response".into(), Value::from(items.len()));
    }
    Value::Object(summary)
}

fn observed_feed_types(object: Option<&Map<String, Value>>) -> Vec<String> {
    let mut types = object
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("type").and_then(Value::as_str).map(str::to_string))
        .collect::<Vec<_>>();
    types.sort();
    types.dedup();
    types
}

fn feed_contract_ok(object: Option<&Map<String, Value>>) -> bool {
    let Some(items) = object
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    let types = observed_feed_types(object)
        .into_iter()
        .collect::<BTreeSet<_>>();
    types
        == EXPECTED_FEED_TYPES
            .into_iter()
            .map(str::to_string)
            .collect()
        && items.iter().all(|item| {
            let Some(item) = item.as_object() else {
                return false;
            };
            item.get("name").and_then(Value::as_str).is_some()
                && item.get("version").and_then(Value::as_str).is_some()
                && matches!(
                    item.get("status").and_then(Value::as_str),
                    Some("Up-to-date..." | "Update in progress..." | "Unknown")
                )
                && matches!(
                    item.get("sync_status").and_then(Value::as_str),
                    Some("up_to_date" | "syncing" | "unknown")
                )
                && item.get("metadata_source").and_then(Value::as_str) == Some("runtime_feed_copy")
                && matches!(
                    item.get("status_source").and_then(Value::as_str),
                    Some("runtime_feed_lock" | "unavailable")
                )
        })
}

fn trashcan_summary_ok(object: Option<&Map<String, Value>>) -> bool {
    let Some(object) = object else {
        return false;
    };
    let forbidden = ["rows", "resources", "credentials", "targets", "scanners"];
    object
        .get("items")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().all(|item| {
                let Some(item) = item.as_object() else {
                    return false;
                };
                item.keys()
                    .all(|key| matches!(key.as_str(), "resource_type" | "title" | "count"))
                    && item.get("resource_type").and_then(Value::as_str).is_some()
                    && item.get("title").and_then(Value::as_str).is_some()
                    && item.get("count").and_then(Value::as_i64).is_some()
            })
        })
        && object.get("total").and_then(Value::as_i64).is_some()
        && forbidden.iter().all(|key| !object.contains_key(*key))
}

fn trashcan_items_ok(object: Option<&Map<String, Value>>) -> (bool, Vec<String>, Vec<String>) {
    let Some(object) = object else {
        return (false, Vec::new(), Vec::new());
    };
    let Some(items) = object.get("items").and_then(Value::as_array) else {
        return (false, Vec::new(), Vec::new());
    };
    let allowed = ALLOWED_TRASHCAN_ITEM_KEYS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let forbidden = FORBIDDEN_TRASHCAN_ITEM_KEYS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let unexpected = items
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|item| item.keys())
        .filter(|key| !allowed.contains(key.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let forbidden_keys = items
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|item| item.keys())
        .filter(|key| forbidden.contains(key.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let rows_ok = items.iter().all(|item| {
        item.as_object().is_some_and(|item| {
            ["id", "resource_type", "entity_type", "title", "name"]
                .into_iter()
                .all(|key| item.get(key).and_then(Value::as_str).is_some())
        })
    });
    (
        rows_ok
            && object
                .get("page")
                .and_then(Value::as_object)
                .and_then(|page| page.get("total"))
                .and_then(Value::as_i64)
                .is_some()
            && unexpected.is_empty()
            && forbidden_keys.is_empty(),
        unexpected,
        forbidden_keys,
    )
}

fn route_declared(repo_root: &Path, needle: &str) -> bool {
    let path = repo_root.join(ROUTES_FILE);
    std::fs::symlink_metadata(&path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
        && std::fs::read_to_string(path).is_ok_and(|source| source.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    struct FakeRunner {
        outputs: Mutex<VecDeque<ProcessOutput>>,
    }
    impl FakeRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
            }
        }
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            if program == "git" {
                return Some(output(true, "test-head"));
            }
            self.outputs.lock().ok()?.pop_front()
        }
        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _: Option<&Path>,
            _: Option<&std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.run(program, args)
        }
    }
    fn output(success: bool, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    fn repo(routes: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-native-smoke-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("repo/services/yafvs-api/src")).unwrap();
        fs::write(
            root.join("repo/services/yafvs-api/src/read_api_routes.rs"),
            routes,
        )
        .unwrap();
        root.join("repo")
    }
    fn finish_test(repo: &Path) {
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }
    fn running_prefix() -> Vec<ProcessOutput> {
        vec![output(true, "container-id\n"), output(true, "true\n")]
    }
    fn feeds() -> &'static str {
        r#"{"items":[{"type":"NVT","name":"n","version":"v","status":"Up-to-date...","sync_status":"up_to_date","metadata_source":"runtime_feed_copy","status_source":"runtime_feed_lock"},{"type":"SCAP","name":"n","version":"v","status":"Unknown","sync_status":"unknown","metadata_source":"runtime_feed_copy","status_source":"unavailable"},{"type":"CERT","name":"n","version":"v","status":"Unknown","sync_status":"unknown","metadata_source":"runtime_feed_copy","status_source":"unavailable"},{"type":"GVMD_DATA","name":"n","version":"v","status":"Unknown","sync_status":"unknown","metadata_source":"runtime_feed_copy","status_source":"unavailable"}]}"#
    }
    fn finding<'a>(result: &'a ResultEnvelope, check: &str) -> &'a Finding {
        result
            .findings
            .iter()
            .find(|finding| finding.check == check)
            .unwrap()
    }

    #[test]
    fn stopped_container_returns_early_and_writes_artifact() {
        let repo = repo("");
        let result = command_runtime_native_api_smoke_with_runner(
            &repo,
            false,
            &FakeRunner::new(vec![output(true, ""), output(true, "one\ntwo\n")]),
        );
        assert_eq!(finding(&result, "native-api.running").status, "fail");
        assert_eq!(result.findings.len(), 1);
        assert!(repo
            .parent()
            .unwrap()
            .join("YAFVS-runtime/artifacts/native-api/native-api-smoke.json")
            .is_file());
        finish_test(&repo);
    }

    #[test]
    fn healthy_feed_contract_and_deferred_routes_pass() {
        let repo = repo("");
        let mut outputs = running_prefix();
        outputs.extend([output(true, r#"{"status":"ok"}"#), output(true, feeds())]);
        let result =
            command_runtime_native_api_smoke_with_runner(&repo, false, &FakeRunner::new(outputs));
        assert_eq!(finding(&result, "native-api.healthz").status, "pass");
        assert_eq!(finding(&result, "native-api.feeds").status, "pass");
        assert_eq!(
            finding(&result, "native-api.trashcan-summary.deferred").status,
            "pass"
        );
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.check != "native-api.trashcan-items"));
        let feeds = finding(&result, "native-api.feeds")
            .details
            .as_ref()
            .unwrap();
        assert_eq!(
            feeds["expected_types"],
            json!(["CERT", "GVMD_DATA", "NVT", "SCAP"])
        );
        finish_test(&repo);
    }

    #[test]
    fn invalid_feed_metadata_fails() {
        let repo = repo("");
        let mut outputs = running_prefix();
        outputs.extend([
            output(true, r#"{"status":"ok"}"#),
            output(true, r#"{"items":[{"type":"NVT"}]}"#),
        ]);
        let result =
            command_runtime_native_api_smoke_with_runner(&repo, false, &FakeRunner::new(outputs));
        assert_eq!(finding(&result, "native-api.feeds").status, "fail");
        finish_test(&repo);
    }

    #[test]
    fn trashcan_summary_rejects_counts_with_rows() {
        let repo = repo(r#".route("/api/v1/trashcan/summary""#);
        let mut outputs = running_prefix();
        outputs.extend([output(true, r#"{"status":"ok"}"#), output(true, feeds()), output(true, r#"{"items":[{"resource_type":"task","title":"Tasks","count":1}],"total":1,"rows":[]}"#)]);
        let result =
            command_runtime_native_api_smoke_with_runner(&repo, false, &FakeRunner::new(outputs));
        assert_eq!(
            finding(&result, "native-api.trashcan-summary").status,
            "fail"
        );
        finish_test(&repo);
    }

    #[test]
    fn trashcan_item_forbidden_and_unexpected_keys_fail() {
        let repo = repo(r#".route("/api/v1/trashcan/items""#);
        let mut outputs = running_prefix();
        outputs.extend([output(true, r#"{"status":"ok"}"#), output(true, feeds()), output(true, r#"{"items":[{"id":"1","resource_type":"task","entity_type":"task","title":"t","name":"n","password":"secret","surprise":"x"}],"page":{"total":1}}"#)]);
        let result =
            command_runtime_native_api_smoke_with_runner(&repo, false, &FakeRunner::new(outputs));
        let detail = finding(&result, "native-api.trashcan-items")
            .details
            .as_ref()
            .unwrap();
        assert_eq!(finding(&result, "native-api.trashcan-items").status, "fail");
        assert_eq!(detail["forbidden_keys"], json!(["password"]));
        assert_eq!(detail["unexpected_keys"], json!(["password", "surprise"]));
        finish_test(&repo);
    }

    #[test]
    fn malformed_json_fails_without_body_exposure() {
        let repo = repo("");
        let mut outputs = running_prefix();
        outputs.extend([output(true, "not json"), output(true, feeds())]);
        let result =
            command_runtime_native_api_smoke_with_runner(&repo, false, &FakeRunner::new(outputs));
        let detail = finding(&result, "native-api.healthz")
            .details
            .as_ref()
            .unwrap();
        assert_eq!(finding(&result, "native-api.healthz").status, "fail");
        assert_eq!(detail["response_summary"], json!({"parsed": false}));
        assert!(detail.get("stdout").is_none());
        finish_test(&repo);
    }

    #[test]
    fn status_only_compacts_successful_result() {
        let repo = repo("");
        let mut outputs = running_prefix();
        outputs.extend([output(true, r#"{"status":"ok"}"#), output(true, feeds())]);
        let result =
            command_runtime_native_api_smoke_with_runner(&repo, true, &FakeRunner::new(outputs));
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].check,
            "runtime-native-api-smoke.status-only"
        );
        assert_eq!(
            result.details.as_ref().unwrap()["important_checks"]["native-api.healthz"],
            "pass"
        );
        finish_test(&repo);
    }
}
