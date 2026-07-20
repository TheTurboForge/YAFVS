// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::write_secure_json_artifact;
use super::common::{compact_finding, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::native_runtime::{
    native_api_display_command, native_api_get_json, native_probe_finding,
    percent_encode_component, validate_api_path, NativeJsonResponse, MAX_NATIVE_API_RESPONSE_BYTES,
};
use super::runtime_health::container_running;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{make_result, Finding, ResultEnvelope};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

const SERVICE: &str = "yafvs-api";
const ARTIFACT_RELATIVE_PATH: &str = "artifacts/native-api/native-api-smoke.json";
const ROUTES_FILE: &str = "services/yafvs-api/src/read_api_routes.rs";
const SERVICE_LOG_TAIL_LINES: usize = 80;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const COLLECTIONS_FILE: &str = "services/yafvs-api/src/collections.rs";
const DEFAULT_MAX_COLLECTION_FILTER_LENGTH: usize = 4096;
const MAX_REASONABLE_COLLECTION_FILTER_LENGTH: usize = 1_048_576;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const HTTP_STATUS_TRAILER: &str = "__YAFVS_HTTP_STATUS__:";

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
            "command": native_api_display_command("/api/v1/feeds"),
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

    let reports_path = "/api/v1/scope-reports?page_size=1&sort=-creation_time";
    let reports = native_api_get_json(repo_root, reports_path, runner);
    details.insert("scope_reports".into(), response_summary(&reports));
    let reports_ok = reports.usable_object()
        && reports
            .object()
            .and_then(|object| object.get("items"))
            .is_some_and(Value::is_array);
    findings.push(native_probe_finding(
        if reports_ok { "pass" } else { "fail" },
        "native-api.scope-reports",
        &format!(
            "Native API scope-report list probe exit code {}.",
            exit_code(&reports.output)
        ),
        &reports,
        reports_path,
    ));

    for (check, path, display_path, filter_length) in scope_report_bad_request_probes(repo_root) {
        let response = native_api_get_json_with_http_status(repo_root, &path, runner);
        findings.push(expected_bad_request_finding(
            check,
            display_path,
            &response,
            filter_length,
        ));
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

struct NativeStatusJsonResponse {
    output: ProcessOutput,
    stdout_bytes: usize,
    stderr_bytes: usize,
    http_status: Option<u16>,
    parsed: Option<Map<String, Value>>,
    error: Option<String>,
}

fn native_api_get_json_with_http_status(
    repo_root: &Path,
    path: &str,
    runner: &dyn CommandRunner,
) -> NativeStatusJsonResponse {
    if let Err(error) = validate_api_path(path) {
        return NativeStatusJsonResponse {
            output: failed_output(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            http_status: None,
            parsed: None,
            error: Some(error),
        };
    }
    let arguments = compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            SERVICE.into(),
            "curl".into(),
            "-sS".into(),
            "--max-time".into(),
            "10".into(),
            "--max-filesize".into(),
            MAX_NATIVE_API_RESPONSE_BYTES.to_string(),
            "-w".into(),
            format!("\\n{HTTP_STATUS_TRAILER}%{{http_code}}"),
            format!("http://127.0.0.1:9080{path}"),
        ],
    );
    let mut output = runner
        .run_with_output_limit(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(COMMAND_TIMEOUT),
            MAX_NATIVE_API_RESPONSE_BYTES,
        )
        .unwrap_or_else(failed_output);
    let stdout_bytes = output.stdout.len();
    let stderr_bytes = output.stderr.len();
    if stdout_bytes.saturating_add(stderr_bytes) > MAX_NATIVE_API_RESPONSE_BYTES {
        output.success = false;
        output.exit_code = Some(1);
        output.stdout.clear();
        output.stderr.clear();
        return NativeStatusJsonResponse {
            output,
            stdout_bytes,
            stderr_bytes,
            http_status: None,
            parsed: None,
            error: Some("native API HTTP-status response exceeded the byte limit".into()),
        };
    }
    let parsed_result = parse_json_with_http_status(&output.stdout);
    output.stdout.clear();
    output.stderr.clear();
    match parsed_result {
        Ok((parsed, http_status)) => NativeStatusJsonResponse {
            output,
            stdout_bytes,
            stderr_bytes,
            http_status: Some(http_status),
            parsed: Some(parsed),
            error: None,
        },
        Err(error) => NativeStatusJsonResponse {
            output,
            stdout_bytes,
            stderr_bytes,
            http_status: None,
            parsed: None,
            error: Some(error),
        },
    }
}

fn parse_json_with_http_status(output: &str) -> Result<(Map<String, Value>, u16), String> {
    let trailers = output
        .match_indices(HTTP_STATUS_TRAILER)
        .collect::<Vec<_>>();
    let Some(&(position, _)) = trailers.last() else {
        return Err("native API HTTP-status trailer was missing".into());
    };
    if trailers.len() != 1 || position == 0 || output.as_bytes()[position - 1] != b'\n' {
        return Err("native API HTTP-status trailer was malformed or duplicated".into());
    }
    let status = &output[position + HTTP_STATUS_TRAILER.len()..];
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("native API HTTP-status trailer was malformed or duplicated".into());
    }
    let http_status = status
        .parse::<u16>()
        .map_err(|_| "native API HTTP-status trailer was malformed or duplicated")?;
    let body = &output[..position - 1];
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .map(|object| (object, http_status))
        .ok_or_else(|| "native API HTTP-status response was not a JSON object".into())
}

fn expected_bad_request_finding(
    check: &str,
    display_path: &str,
    response: &NativeStatusJsonResponse,
    filter_length: Option<usize>,
) -> Finding {
    let actual_code = response
        .parsed
        .as_ref()
        .and_then(|object| object.get("error"))
        .and_then(Value::as_object)
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str);
    let ok = response.output.success
        && response.http_status == Some(400)
        && actual_code == Some("bad_request");
    let mut summary = Map::from_iter([
        (
            "http_status".into(),
            response.http_status.map_or(Value::Null, Value::from),
        ),
        (
            "error_code".into(),
            actual_code.map_or(Value::Null, |code| Value::String(code.into())),
        ),
        ("parsed".into(), Value::Bool(response.parsed.is_some())),
    ]);
    if let Some(length) = filter_length {
        summary.insert("filter_length".into(), Value::from(length));
    }
    let mut details = Map::from_iter([
        (
            "exit_code".into(),
            response.output.exit_code.map_or(Value::Null, Value::from),
        ),
        (
            "command".into(),
            Value::String(native_api_status_display_command(display_path)),
        ),
        ("response_summary".into(), Value::Object(summary)),
        ("stdout_bytes".into(), Value::from(response.stdout_bytes)),
        ("stderr_bytes".into(), Value::from(response.stderr_bytes)),
    ]);
    if let Some(error) = &response.error {
        details.insert("error".into(), Value::String(error.clone()));
    }
    let message = if ok {
        format!("Native API rejected {display_path} with JSON 400 bad_request.")
    } else {
        format!("Native API did not reject {display_path} with JSON 400 bad_request.")
    };
    Finding::new(if ok { "pass" } else { "fail" }, check, message)
        .with_details(Value::Object(details))
}

fn native_api_status_display_command(path: &str) -> String {
    format!(
        "docker compose exec -T {SERVICE} curl -sS --max-time 10 --max-filesize \
         {MAX_NATIVE_API_RESPONSE_BYTES} -w '\\n{HTTP_STATUS_TRAILER}%{{http_code}}' \
         http://127.0.0.1:9080{path}"
    )
}

fn scope_report_bad_request_probes(
    repo_root: &Path,
) -> Vec<(&'static str, String, &'static str, Option<usize>)> {
    let base = "/api/v1/scope-reports?page_size=1";
    let max_filter_length = max_collection_filter_length(repo_root);
    let filter_length = max_filter_length.saturating_add(1);
    vec![
        (
            "native-api.scope-reports.invalid-sort",
            format!("{base}&sort=not_a_scope_report_sort"),
            "/api/v1/scope-reports?page_size=1&sort=not_a_scope_report_sort",
            None,
        ),
        (
            "native-api.scope-reports.invalid-page",
            "/api/v1/scope-reports?page=0&page_size=1".into(),
            "/api/v1/scope-reports?page=0&page_size=1",
            None,
        ),
        (
            "native-api.scope-reports.malformed-page",
            "/api/v1/scope-reports?page=abc&page_size=1".into(),
            "/api/v1/scope-reports?page=abc&page_size=1",
            None,
        ),
        (
            "native-api.scope-reports.oversized-page-size",
            "/api/v1/scope-reports?page_size=501".into(),
            "/api/v1/scope-reports?page_size=501",
            None,
        ),
        (
            "native-api.scope-reports.oversized-filter",
            format!(
                "{base}&filter={}",
                percent_encode_component(&"x".repeat(filter_length))
            ),
            "/api/v1/scope-reports?page_size=1&filter=OVERSIZED_FILTER",
            Some(filter_length),
        ),
    ]
}

fn max_collection_filter_length(repo_root: &Path) -> usize {
    let Some(source) = read_bounded_source(repo_root, COLLECTIONS_FILE) else {
        return DEFAULT_MAX_COLLECTION_FILTER_LENGTH;
    };
    source
        .lines()
        .find_map(|line| {
            let value = line
                .trim()
                .strip_prefix("pub(crate) const MAX_COLLECTION_FILTER_LENGTH: usize = ")?
                .strip_suffix(';')?;
            if value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            value
                .parse::<usize>()
                .ok()
                .filter(|value| *value <= MAX_REASONABLE_COLLECTION_FILTER_LENGTH)
        })
        .unwrap_or(DEFAULT_MAX_COLLECTION_FILTER_LENGTH)
}

fn read_bounded_source(repo_root: &Path, relative_path: &str) -> Option<String> {
    let path = repo_root.join(relative_path);
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_SOURCE_BYTES
    {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let opened_metadata = file.metadata().ok()?;
    if !opened_metadata.file_type().is_file() || opened_metadata.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
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
    read_bounded_source(repo_root, ROUTES_FILE).is_some_and(|source| source.contains(needle))
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
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }
    impl FakeRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            if program == "git" {
                return Some(output(true, "test-head"));
            }
            self.calls.lock().ok()?.push((
                program.to_string(),
                args.iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
            ));
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
        fs::write(
            root.join("repo/services/yafvs-api/src/collections.rs"),
            "pub(crate) const MAX_COLLECTION_FILTER_LENGTH: usize = 4096;\n",
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
    fn bad_request_output() -> ProcessOutput {
        output(
            true,
            &format!(
                "{{\"error\":{{\"code\":\"bad_request\",\"message\":\"rejected\"}}}}\n\
                 {HTTP_STATUS_TRAILER}400"
            ),
        )
    }
    fn successful_scope_tail() -> Vec<ProcessOutput> {
        let mut outputs = vec![output(
            true,
            r#"{"items":[{"id":"scope-report"}],"page":{"total":1}}"#,
        )];
        outputs.extend((0..5).map(|_| bad_request_output()));
        outputs
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
        outputs.extend(successful_scope_tail());
        let runner = FakeRunner::new(outputs);
        let result = command_runtime_native_api_smoke_with_runner(&repo, false, &runner);
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
        for check in [
            "native-api.scope-reports",
            "native-api.scope-reports.invalid-sort",
            "native-api.scope-reports.invalid-page",
            "native-api.scope-reports.malformed-page",
            "native-api.scope-reports.oversized-page-size",
            "native-api.scope-reports.oversized-filter",
        ] {
            assert_eq!(finding(&result, check).status, "pass", "{check}");
        }
        let oversized_url = runner
            .calls()
            .into_iter()
            .flat_map(|(_, arguments)| arguments)
            .find(|argument| argument.contains("/api/v1/scope-reports?page_size=1&filter=x"))
            .unwrap();
        let filter = oversized_url.split_once("&filter=").unwrap().1;
        assert_eq!(filter.len(), 4097);
        assert!(filter.bytes().all(|byte| byte == b'x'));
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(&"x".repeat(64)));
        let artifact = fs::read_to_string(
            repo.parent()
                .unwrap()
                .join("YAFVS-runtime/artifacts/native-api/native-api-smoke.json"),
        )
        .unwrap();
        assert!(!artifact.contains(&"x".repeat(64)));
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
        outputs.extend(successful_scope_tail());
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
        outputs.extend(successful_scope_tail());
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
        outputs.extend(successful_scope_tail());
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
        outputs.extend(successful_scope_tail());
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
        outputs.extend(successful_scope_tail());
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

    #[test]
    fn scope_report_collection_rejects_non_array_and_malformed_json() {
        for body in [r#"{"items":{}}"#, "not json"] {
            let repo = repo("");
            let mut outputs = running_prefix();
            outputs.extend([
                output(true, r#"{"status":"ok"}"#),
                output(true, feeds()),
                output(true, body),
            ]);
            outputs.extend((0..5).map(|_| bad_request_output()));
            let result = command_runtime_native_api_smoke_with_runner(
                &repo,
                false,
                &FakeRunner::new(outputs),
            );
            assert_eq!(finding(&result, "native-api.scope-reports").status, "fail");
            finish_test(&repo);
        }
    }

    #[test]
    fn status_trailer_and_bad_request_contract_fail_closed_without_body_retention() {
        for body in [
            format!("{{\"error\":{{\"code\":\"bad_request\"}}}}\n{HTTP_STATUS_TRAILER}200"),
            format!(
                "{{\"error\":{{\"code\":\"wrong\",\"message\":\"RAW_BODY_SENTINEL\"}}}}\n\
                 {HTTP_STATUS_TRAILER}400"
            ),
            format!("{{\"error\":{{}}}}\n{HTTP_STATUS_TRAILER}400"),
            "{\"error\":{\"code\":\"bad_request\"}}".to_string(),
            format!(
                "{{\"error\":{{\"code\":\"bad_request\"}}}}\n{HTTP_STATUS_TRAILER}400\
                 \n{HTTP_STATUS_TRAILER}400"
            ),
            format!("[]\n{HTTP_STATUS_TRAILER}400"),
        ] {
            let runner = FakeRunner::new(vec![output(true, &body)]);
            let response = native_api_get_json_with_http_status(
                Path::new("/srv/YAFVS"),
                "/api/v1/scope-reports?page=0&page_size=1",
                &runner,
            );
            let finding = expected_bad_request_finding(
                "native-api.scope-reports.invalid-page",
                "/api/v1/scope-reports?page=0&page_size=1",
                &response,
                None,
            );
            assert_eq!(finding.status, "fail");
            let details = finding.details.unwrap();
            assert!(details.get("stdout").is_none());
            assert!(details.get("stderr").is_none());
            assert!(!serde_json::to_string(&details)
                .unwrap()
                .contains("RAW_BODY_SENTINEL"));
        }

        let runner = FakeRunner::new(vec![output(
            false,
            &format!("{{\"error\":{{\"code\":\"bad_request\"}}}}\n{HTTP_STATUS_TRAILER}400"),
        )]);
        let response = native_api_get_json_with_http_status(
            Path::new("/srv/YAFVS"),
            "/api/v1/scope-reports?page=0&page_size=1",
            &runner,
        );
        assert_eq!(
            expected_bad_request_finding(
                "native-api.scope-reports.invalid-page",
                "/api/v1/scope-reports?page=0&page_size=1",
                &response,
                None,
            )
            .status,
            "fail"
        );
    }

    #[test]
    fn status_probe_rejects_unsafe_paths_before_process_launch() {
        let runner = FakeRunner::new(Vec::new());
        let response = native_api_get_json_with_http_status(
            Path::new("/srv/YAFVS"),
            "https://example.invalid/api/v1/scope-reports",
            &runner,
        );
        assert!(response.error.is_some());
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn collection_filter_limit_falls_back_for_links_and_absurd_values() {
        let repo = repo("");
        assert_eq!(max_collection_filter_length(&repo), 4096);
        let path = repo.join(COLLECTIONS_FILE);
        fs::write(
            &path,
            "pub(crate) const MAX_COLLECTION_FILTER_LENGTH: usize = 9999999999;\n",
        )
        .unwrap();
        assert_eq!(max_collection_filter_length(&repo), 4096);
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        assert_eq!(max_collection_filter_length(&repo), 4096);
        finish_test(&repo);
    }
}
