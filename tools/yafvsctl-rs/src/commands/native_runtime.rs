// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, ProcessOutput};
use crate::result::Finding;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::time::Duration;

const API_BASE_URL: &str = "http://127.0.0.1:9080";
const API_TIMEOUT: Duration = Duration::from_secs(30);
const CURL_MAX_TIME_SECONDS: &str = "10";
const PAGE_SIZE: usize = 500;
const MAX_PAGE_REQUESTS: usize = 256;
pub(crate) const MAX_NATIVE_API_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_NATIVE_API_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct NativeJsonResponse {
    pub(crate) output: ProcessOutput,
    pub(crate) parsed: Option<Value>,
    pub(crate) error: Option<String>,
}

pub(crate) fn native_pages_ok(pages: &NativeObjectPages) -> bool {
    pages.error.is_none()
        && pages.total.is_some()
        && pages
            .response
            .as_ref()
            .is_some_and(|response| response.output.success && response.error.is_none())
}

pub(crate) fn native_page_finding(
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

pub(crate) fn native_probe_finding(
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

impl NativeJsonResponse {
    pub(crate) fn object(&self) -> Option<&Map<String, Value>> {
        self.parsed.as_ref()?.as_object()
    }

    pub(crate) fn usable_object(&self) -> bool {
        self.output.success && self.error.is_none() && self.object().is_some()
    }
}

#[derive(Debug)]
pub(crate) struct NativeObjectPages {
    pub(crate) rows: Vec<Map<String, Value>>,
    pub(crate) total: Option<usize>,
    pub(crate) response: Option<NativeJsonResponse>,
    pub(crate) error: Option<String>,
}

pub(crate) fn percent_encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

pub(crate) fn native_api_get_json(
    repo_root: &Path,
    path: &str,
    runner: &dyn CommandRunner,
) -> NativeJsonResponse {
    if let Err(error) = validate_api_path(path) {
        return NativeJsonResponse {
            output: failed_output(),
            parsed: None,
            error: Some(error),
        };
    }
    let arguments = native_api_get_arguments(repo_root, path);
    let mut output = runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(API_TIMEOUT),
        )
        .unwrap_or_else(failed_output);
    if output.stdout.len() > MAX_NATIVE_API_RESPONSE_BYTES {
        output.stdout.clear();
        output.success = false;
        output.exit_code = Some(1);
        return NativeJsonResponse {
            output,
            parsed: None,
            error: Some(format!(
                "native API response exceeded the {} byte limit",
                MAX_NATIVE_API_RESPONSE_BYTES
            )),
        };
    }
    let parsed = serde_json::from_str::<Value>(&output.stdout).ok();
    let error = if output.success && parsed.is_none() {
        Some("native API response was not valid JSON".to_string())
    } else {
        None
    };
    NativeJsonResponse {
        output,
        parsed,
        error,
    }
}

pub(crate) fn fetch_object_pages(
    repo_root: &Path,
    collection_path: &str,
    sort: &str,
    max_items: usize,
    runner: &dyn CommandRunner,
) -> NativeObjectPages {
    let mut rows = Vec::new();
    let mut total = None;
    let mut selected_response = None;
    let mut page = 1usize;
    let mut retained_bytes = 0usize;
    while rows.len() < max_items {
        if page > MAX_PAGE_REQUESTS {
            return NativeObjectPages {
                rows,
                total,
                response: selected_response,
                error: Some(format!(
                    "native API pagination exceeded the {MAX_PAGE_REQUESTS} request limit"
                )),
            };
        }
        let page_size = PAGE_SIZE.min(max_items - rows.len());
        let path = format!("{collection_path}?page={page}&page_size={page_size}&sort={sort}");
        let response = native_api_get_json(repo_root, &path, runner);
        let Some(object) = response.object() else {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page response was not a JSON object".into()),
            };
        };
        if !response.output.success || response.error.is_some() {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page request failed".into()),
            };
        }
        let Some(items) = object.get("items").and_then(Value::as_array) else {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page items were not an array".into()),
            };
        };
        let Some(page_info) = object.get("page").and_then(Value::as_object) else {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page metadata was not an object".into()),
            };
        };
        let Some(observed_total) = json_usize(page_info.get("total")) else {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page total was not a non-negative integer".into()),
            };
        };
        if total.is_some_and(|expected| expected != observed_total) {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page total changed during pagination".into()),
            };
        }
        if items.len() > page_size || items.iter().any(|item| !item.is_object()) {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page row shape or count exceeded its contract".into()),
            };
        }
        if rows
            .len()
            .checked_add(items.len())
            .is_none_or(|count| count > observed_total || count > max_items)
        {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page rows exceeded the declared total or item cap".into()),
            };
        }
        let Some(next_retained_bytes) =
            aggregate_bytes(retained_bytes, response.output.stdout.len())
        else {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some(format!(
                    "native API pagination exceeded the {} byte aggregate limit",
                    MAX_NATIVE_API_AGGREGATE_BYTES
                )),
            };
        };
        retained_bytes = next_retained_bytes;
        total = Some(observed_total);
        if selected_response.is_none() {
            selected_response = Some(response.clone());
        }
        let before = rows.len();
        rows.extend(items.iter().filter_map(Value::as_object).cloned());
        if rows.len() >= total.unwrap_or_default() || items.is_empty() || rows.len() >= max_items {
            break;
        }
        if rows.len() == before {
            return NativeObjectPages {
                rows,
                total,
                response: Some(response),
                error: Some("native API page contained no object rows".into()),
            };
        }
        page += 1;
    }
    NativeObjectPages {
        rows,
        total,
        response: selected_response,
        error: None,
    }
}

pub(crate) fn native_api_display_command(path: &str) -> String {
    format!(
        "docker compose exec -T yafvs-api curl -fsS --max-time {CURL_MAX_TIME_SECONDS} {API_BASE_URL}{path}"
    )
}

fn native_api_get_arguments(repo_root: &Path, path: &str) -> Vec<String> {
    compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "yafvs-api".into(),
            "curl".into(),
            "-fsS".into(),
            "--max-time".into(),
            CURL_MAX_TIME_SECONDS.into(),
            "--max-filesize".into(),
            MAX_NATIVE_API_RESPONSE_BYTES.to_string(),
            format!("{API_BASE_URL}{path}"),
        ],
    )
}

pub(crate) fn validate_api_path(path: &str) -> Result<(), String> {
    if path != "/healthz" && !path.starts_with("/api/v1/") {
        return Err("native API path must be /healthz or start with /api/v1/".into());
    }
    if path
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
        || path.contains('#')
    {
        return Err("native API path contains forbidden characters".into());
    }
    let path_only = path.split_once('?').map_or(path, |(path, _)| path);
    if path_only
        .split('/')
        .skip(3)
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err("native API path contains an unsafe segment".into());
    }
    Ok(())
}

fn json_usize(value: Option<&Value>) -> Option<usize> {
    value.and_then(|value| {
        value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .or_else(|| value.as_str()?.parse::<usize>().ok())
    })
}

fn aggregate_bytes(current: usize, next: usize) -> Option<usize> {
    current
        .checked_add(next)
        .filter(|total| *total <= MAX_NATIVE_API_AGGREGATE_BYTES)
}

fn failed_output() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::sync::Mutex;

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
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            _program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|value| (*value).to_string()).collect());
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

    #[test]
    fn percent_encodes_every_non_unreserved_component_byte() {
        assert_eq!(
            percent_encode_component("CB-K14/1304 ü?"),
            "CB-K14%2F1304%20%C3%BC%3F"
        );
    }

    #[test]
    fn rejects_oversized_response_without_retaining_it() {
        let oversized = "x".repeat(MAX_NATIVE_API_RESPONSE_BYTES + 1);
        let runner = Runner::new([output(true, &oversized)]);
        let response =
            native_api_get_json(Path::new("/srv/YAFVS"), "/api/v1/reports/example", &runner);
        assert!(!response.output.success);
        assert!(response.output.stdout.is_empty());
        assert!(response.error.unwrap().contains("exceeded"));
        let calls = runner.calls.lock().unwrap();
        assert!(calls[0].windows(2).any(|pair| {
            pair[0] == "--max-filesize" && pair[1] == MAX_NATIVE_API_RESPONSE_BYTES.to_string()
        }));
    }

    #[test]
    fn paginates_with_bounded_page_sizes_and_truncates_at_cap() {
        let first_items = (0..500)
            .map(|index| serde_json::json!({"id": index}))
            .collect::<Vec<_>>();
        let second_items = (500..550)
            .map(|index| serde_json::json!({"id": index}))
            .collect::<Vec<_>>();
        let runner = Runner::new([
            output(
                true,
                &serde_json::json!({"items": first_items, "page": {"total": 620}}).to_string(),
            ),
            output(
                true,
                &serde_json::json!({"items": second_items, "page": {"total": 620}}).to_string(),
            ),
        ]);
        let pages = fetch_object_pages(
            Path::new("/srv/YAFVS"),
            "/api/v1/reports/id/results",
            "-severity",
            550,
            &runner,
        );
        assert!(pages.error.is_none());
        assert_eq!(pages.rows.len(), 550);
        assert_eq!(pages.total, Some(620));
        let calls = runner.calls.lock().unwrap();
        assert!(calls[0].last().unwrap().contains("page=1&page_size=500"));
        assert!(calls[1].last().unwrap().contains("page=2&page_size=50"));
    }

    #[test]
    fn rejects_malformed_pages_and_nonprogressing_rows() {
        for body in [
            serde_json::json!({"items": {}, "page": {"total": 1}}),
            serde_json::json!({"items": [], "page": []}),
            serde_json::json!({"items": ["not-an-object"], "page": {"total": 1}}),
            serde_json::json!({"items": [], "page": {}}),
            serde_json::json!({"items": [], "page": {"total": -1}}),
            serde_json::json!({"items": [], "page": {"total": "not-a-number"}}),
        ] {
            let runner = Runner::new([output(true, &body.to_string())]);
            let pages = fetch_object_pages(
                Path::new("/srv/YAFVS"),
                "/api/v1/reports/id/results",
                "-severity",
                10,
                &runner,
            );
            assert!(pages.error.is_some());
        }
    }

    #[test]
    fn rejects_total_drift_and_rows_beyond_declared_total() {
        let runner = Runner::new([
            output(
                true,
                &serde_json::json!({"items": [{"id": 1}], "page": {"total": 2}}).to_string(),
            ),
            output(
                true,
                &serde_json::json!({"items": [{"id": 2}], "page": {"total": 3}}).to_string(),
            ),
        ]);
        let pages = fetch_object_pages(
            Path::new("/srv/YAFVS"),
            "/api/v1/reports/id/results",
            "-severity",
            10,
            &runner,
        );
        assert!(pages.error.unwrap().contains("changed"));

        let runner = Runner::new([output(
            true,
            &serde_json::json!({"items": [{"id": 1}, {"id": 2}], "page": {"total": 1}}).to_string(),
        )]);
        let pages = fetch_object_pages(
            Path::new("/srv/YAFVS"),
            "/api/v1/reports/id/results",
            "-severity",
            10,
            &runner,
        );
        assert!(pages.error.unwrap().contains("declared total"));
    }

    #[test]
    fn aggregate_byte_limit_is_overflow_safe_and_inclusive() {
        assert_eq!(
            aggregate_bytes(MAX_NATIVE_API_AGGREGATE_BYTES - 1, 1),
            Some(MAX_NATIVE_API_AGGREGATE_BYTES)
        );
        assert_eq!(aggregate_bytes(MAX_NATIVE_API_AGGREGATE_BYTES, 1), None);
        assert_eq!(aggregate_bytes(usize::MAX, 1), None);
    }

    #[test]
    fn stops_adversarial_underfilled_pagination_at_request_limit() {
        let body =
            serde_json::json!({"items": [{"id": "one"}], "page": {"total": 300}}).to_string();
        let runner = Runner::new((0..MAX_PAGE_REQUESTS).map(|_| output(true, &body)));
        let pages = fetch_object_pages(
            Path::new("/srv/YAFVS"),
            "/api/v1/reports/id/results",
            "-severity",
            300,
            &runner,
        );
        assert_eq!(pages.rows.len(), MAX_PAGE_REQUESTS);
        assert!(pages.error.unwrap().contains("request limit"));
        assert_eq!(runner.calls.lock().unwrap().len(), MAX_PAGE_REQUESTS);
    }

    #[test]
    fn rejects_unsafe_api_paths_before_running_docker() {
        let runner = Runner::new([]);
        for path in [
            "https://example.invalid/api/v1/reports",
            "/api/v1/../reports",
            "/api/v1/reports/",
            "/api/v1/reports#fragment",
        ] {
            assert!(native_api_get_json(Path::new("/srv/YAFVS"), path, &runner)
                .error
                .is_some());
        }
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn accepts_the_exact_health_path_and_rejects_health_descendants() {
        let runner = Runner::new([output(true, r#"{"status":"ok"}"#)]);
        let response = native_api_get_json(Path::new("/srv/YAFVS"), "/healthz", &runner);
        assert!(response.usable_object());
        assert_eq!(runner.calls.lock().unwrap().len(), 1);

        let runner = Runner::new([]);
        let response = native_api_get_json(Path::new("/srv/YAFVS"), "/healthz/anything", &runner);
        assert!(response.error.is_some());
        assert!(runner.calls.lock().unwrap().is_empty());
    }
}
