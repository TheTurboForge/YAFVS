// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{expand_home, metadata};
use super::compose::{compose_command, runtime_environment};
use super::direct_api::{
    BEARER_TOKEN_CONTAINER_FILE, BEARER_TOKEN_ENV, BEARER_TOKEN_FILE_ENV, BEARER_TOKEN_SECRET,
    bearer_token_is_acceptable, direct_base_url, direct_config_shape_finding,
    direct_runtime_environment, environment_value,
};
use super::secret::{read_private_text, runtime_secret_path};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::time::Duration;

pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_PATH_BYTES: usize = 64 * 1024;
const REQUEST_ID_MAX: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(30);

#[allow(clippy::too_many_arguments)]
pub fn command_native_api_request(
    repo_root: &Path,
    path: &str,
    direct: bool,
    method: &str,
    request_id: Option<&str>,
    body_json: Option<&str>,
    allow_write_control: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        repo_root,
        path,
        direct,
        method,
        request_id,
        body_json,
        allow_write_control,
        status_only,
        &SystemCommandRunner,
    )
}

pub(crate) struct GuardedDirectBinaryDownload {
    pub(crate) output: ProcessOutput,
    pub(crate) http_status: Option<i64>,
    pub(crate) content_type: Option<String>,
    pub(crate) reported_bytes: Option<u64>,
    pub(crate) cap_exceeded: bool,
    pub(crate) config: Finding,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn guarded_direct_api_binary_download(
    repo_root: &Path,
    path: &str,
    max_bytes: u64,
    output: &File,
    config_check: &str,
    token_check: &str,
    runner: &dyn CommandRunner,
) -> Result<GuardedDirectBinaryDownload, Vec<Finding>> {
    let environment = direct_runtime_environment(repo_root, runner).map_err(|_| {
        vec![Finding::new(
            "fail",
            config_check,
            "Direct native API host, port, or bind settings are malformed.".into(),
        )]
    })?;
    let config = direct_config_shape_finding(&environment, config_check);
    if config.status == "fail" {
        return Err(vec![config]);
    }
    let token = direct_token(repo_root, &environment).unwrap_or_default();
    if !bearer_token_is_acceptable(&token) {
        return Err(vec![
            config,
            Finding::new(
                "fail",
                token_check,
                "Direct native API bearer token is too short or contains unsafe characters.".into(),
            )
            .with_details(json!({"minimum_token_length": 32})),
        ]);
    }
    let header = match authorization_header(&token) {
        Ok(header) => header,
        Err(_) => {
            return Err(vec![
                config,
                Finding::new(
                    "fail",
                    token_check,
                    "Direct native API authorization could not be prepared privately.".into(),
                ),
            ]);
        }
    };
    let header_fd = header.as_raw_fd();
    let output_fd = output.as_raw_fd();
    let args = vec![
        "--disable".into(),
        "-sS".into(),
        "--noproxy".into(),
        "*".into(),
        "--max-filesize".into(),
        max_bytes.to_string(),
        "--max-time".into(),
        "30".into(),
        "-o".into(),
        format!("/proc/self/fd/{output_fd}"),
        "-H".into(),
        format!("@/proc/self/fd/{header_fd}"),
        "-w".into(),
        "\nYAFVS_HTTP_STATUS:%{http_code}\nYAFVS_CONTENT_TYPE:%{content_type}\nYAFVS_SIZE_DOWNLOAD:%{size_download}\n"
            .into(),
        format!("{}{}", direct_base_url(&environment), path),
    ];
    let curl_env = direct_curl_environment(&environment);
    let output = runner
        .run_with_input_and_fds(
            "curl",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&curl_env),
            Some(TIMEOUT),
            None,
            &[header_fd, output_fd],
            Some(max_bytes),
        )
        .unwrap_or_else(failed);
    let http_status = unique_marker(&output.stdout, "YAFVS_HTTP_STATUS:")
        .and_then(|value| value.parse::<i64>().ok());
    let content_type = unique_marker(&output.stdout, "YAFVS_CONTENT_TYPE:")
        .map(normalize_content_type)
        .filter(|value| !value.is_empty());
    let reported_bytes = unique_marker(&output.stdout, "YAFVS_SIZE_DOWNLOAD:")
        .and_then(|value| value.parse::<u64>().ok());
    let cap_exceeded =
        output.exit_code == Some(63) || reported_bytes.is_some_and(|bytes| bytes > max_bytes);
    Ok(GuardedDirectBinaryDownload {
        output,
        http_status,
        content_type,
        reported_bytes,
        cap_exceeded,
        config,
    })
}

fn unique_marker<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::trim);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn normalize_content_type(value: &str) -> String {
    value
        .split_once(';')
        .map_or(value, |(media_type, _)| media_type)
        .trim()
        .to_ascii_lowercase()
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, "native-api-request", runner),
        summary.into(),
        findings,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn command_with_runner(
    repo_root: &Path,
    path: &str,
    direct: bool,
    method: &str,
    request_id: Option<&str>,
    body_json: Option<&str>,
    allow_write_control: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let method = match validate_method(method) {
        Ok(value) => value,
        Err(message) => {
            return result(
                repo_root,
                runner,
                "Native API request rejected before runtime access.",
                vec![
                    Finding::new("fail", "native-api-request.method", message)
                        .with_details(json!({"method": method})),
                ],
            );
        }
    };
    let path = match validate_path(path) {
        Ok(value) => value,
        Err(message) => {
            return result(
                repo_root,
                runner,
                "Native API request rejected before runtime access.",
                vec![
                    Finding::new("fail", "native-api-request.path", message)
                        .with_details(json!({"path": path})),
                ],
            );
        }
    };
    let request_id = match request_id.map(validate_request_id).transpose() {
        Ok(value) => value,
        Err(message) => {
            return result(
                repo_root,
                runner,
                "Native API request rejected before runtime access.",
                vec![
                    Finding::new("fail", "native-api-request.request-id", message)
                        .with_details(json!({"request_id": request_id})),
                ],
            );
        }
    };
    let body = match body_json.map(validate_body).transpose().and_then(|body| validate_shape(&method, body.as_deref(), allow_write_control, direct && path.contains('?')).map(|()| body)) {
        Ok(body) => body,
        Err(message) => return result(repo_root, runner, "Native API request rejected before runtime access.", vec![Finding::new("fail", "native-api-request.write-control-intent", message).with_details(json!({"method": method, "has_body": body_json.is_some(), "allow_write_control": allow_write_control}))]),
    };
    if direct {
        return direct_request(
            repo_root,
            &path,
            &method,
            request_id.as_deref(),
            body.as_deref(),
            status_only,
            runner,
        );
    }
    let mut args = compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "yafvs-api".into(),
            "curl".into(),
            "-fsS".into(),
            "--max-filesize".into(),
            MAX_RESPONSE_BYTES.to_string(),
            "--max-time".into(),
            "10".into(),
        ],
    );
    add_request_arguments(&mut args, &method, request_id.as_deref(), body.is_some());
    args.push(format!("http://127.0.0.1:9080{path}"));
    let output = runner
        .run_with_input(
            "docker",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(TIMEOUT),
            body.as_deref().map(str::as_bytes),
        )
        .unwrap_or_else(failed);
    finish(
        repo_root,
        runner,
        false,
        &path,
        &method,
        request_id.as_deref(),
        body.as_deref(),
        output,
        None,
        status_only,
    )
}

fn direct_request(
    repo_root: &Path,
    path: &str,
    method: &str,
    request_id: Option<&str>,
    body: Option<&str>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let call = match guarded_direct_api_call(
        repo_root,
        path,
        method,
        request_id,
        body,
        "native-api-request.direct-config-shape",
        "native-api-request.direct-token-strength",
        runner,
    ) {
        Ok(call) => call,
        Err(findings) => {
            return result(
                repo_root,
                runner,
                "Direct native API request rejected before runtime access.",
                findings,
            );
        }
    };
    finish(
        repo_root,
        runner,
        true,
        path,
        method,
        request_id,
        body,
        call.output,
        Some(call.config),
        status_only,
    )
}

pub(crate) struct GuardedDirectApiCall {
    pub(crate) output: ProcessOutput,
    pub(crate) parsed: Option<Value>,
    pub(crate) http_status: Option<i64>,
    pub(crate) oversized: bool,
    pub(crate) config: Finding,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn guarded_direct_api_call(
    repo_root: &Path,
    path: &str,
    method: &str,
    request_id: Option<&str>,
    body: Option<&str>,
    config_check: &str,
    token_check: &str,
    runner: &dyn CommandRunner,
) -> Result<GuardedDirectApiCall, Vec<Finding>> {
    let environment = direct_runtime_environment(repo_root, runner).map_err(|_| {
        vec![Finding::new(
            "fail",
            config_check,
            "Direct native API host, port, or bind settings are malformed.".into(),
        )]
    })?;
    let config = direct_config_shape_finding(&environment, config_check);
    if config.status == "fail" {
        return Err(vec![config]);
    }
    let token = direct_token(repo_root, &environment).unwrap_or_default();
    if !bearer_token_is_acceptable(&token) {
        return Err(vec![
            config,
            Finding::new(
                "fail",
                token_check,
                "Direct native API bearer token is too short or contains unsafe characters.".into(),
            )
            .with_details(json!({"minimum_token_length": 32})),
        ]);
    }
    let output = direct_curl(
        repo_root,
        path,
        method,
        request_id,
        body,
        &token,
        &environment,
        runner,
    );
    let oversized = output.stdout.len() > MAX_RESPONSE_BYTES;
    let (parsed, http_status) = if oversized {
        (None, None)
    } else {
        parse_status(&output.stdout)
    };
    Ok(GuardedDirectApiCall {
        output,
        parsed,
        http_status,
        oversized,
        config,
    })
}

fn direct_token(
    repo_root: &Path,
    env: &std::collections::BTreeMap<OsString, OsString>,
) -> std::io::Result<String> {
    if let Some(token) = environment_value(env, BEARER_TOKEN_ENV).filter(|value| !value.is_empty())
    {
        return Ok(token);
    }
    let file = environment_value(env, BEARER_TOKEN_FILE_ENV).unwrap_or_default();
    let path = if file.is_empty() || file == BEARER_TOKEN_CONTAINER_FILE {
        runtime_secret_path(repo_root, BEARER_TOKEN_SECRET)
    } else {
        expand_home(file.into())
    };
    Ok(read_private_text(&path, 4096)?.trim().to_string())
}

#[allow(clippy::too_many_arguments)]
fn direct_curl(
    repo_root: &Path,
    path: &str,
    method: &str,
    request_id: Option<&str>,
    body: Option<&str>,
    token: &str,
    env: &std::collections::BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> ProcessOutput {
    (|| {
        let header = authorization_header(token).ok()?;
        let header_fd = header.as_raw_fd();
        let mut args = vec![
            "--disable".into(),
            "-sS".into(),
            "--noproxy".into(),
            "*".into(),
            "--max-filesize".into(),
            MAX_RESPONSE_BYTES.to_string(),
            "--max-time".into(),
            "10".into(),
            "-w".into(),
            "\n%{http_code}".into(),
            "-H".into(),
            format!("@/proc/self/fd/{header_fd}"),
        ];
        add_request_arguments(&mut args, method, request_id, body.is_some());
        args.push(format!("{}{}", direct_base_url(env), path));
        let curl_env = direct_curl_environment(env);
        runner.run_with_input_and_fd(
            "curl",
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&curl_env),
            Some(TIMEOUT),
            body.map(str::as_bytes),
            header_fd,
        )
    })()
    .unwrap_or_else(failed)
}

fn authorization_header(token: &str) -> std::io::Result<File> {
    let name = CString::new("yafvsctl-auth")
        .expect("the fixed anonymous authorization file name contains no NUL");
    // SAFETY: name is a valid C string and memfd_create returns a new owned
    // descriptor or -1. MFD_CLOEXEC is cleared only in the curl child.
    let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(format!("Authorization: Bearer {token}\n").as_bytes())?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn direct_curl_environment(env: &BTreeMap<OsString, OsString>) -> BTreeMap<OsString, OsString> {
    ["PATH", "LANG", "LC_ALL"]
        .into_iter()
        .filter_map(|name| {
            env.get(&OsString::from(name))
                .cloned()
                .map(|value| (OsString::from(name), value))
        })
        .collect()
}

fn add_request_arguments(
    args: &mut Vec<String>,
    method: &str,
    request_id: Option<&str>,
    has_body: bool,
) {
    if method != "GET" || has_body {
        args.extend(["-X".into(), method.into()]);
    }
    if let Some(id) = request_id {
        args.extend(["-H".into(), format!("X-Request-Id: {id}")]);
    }
    if has_body {
        args.extend([
            "-H".into(),
            "Content-Type: application/json".into(),
            "--data-binary".into(),
            "@-".into(),
        ]);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type Call = (String, Vec<String>, BTreeMap<OsString, OsString>, Vec<u8>);

    #[derive(Default)]
    struct Runner {
        calls: Mutex<Vec<Call>>,
        header_was_private: Mutex<bool>,
        output: Mutex<Option<ProcessOutput>>,
    }

    impl Runner {
        fn successful(output: &str) -> Self {
            Self {
                output: Mutex::new(Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: output.into(),
                    stderr: String::new(),
                })),
                ..Self::default()
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            if program == "git" {
                return Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: "deadbee\n".into(),
                    stderr: String::new(),
                });
            }
            self.run_with_input(program, args, None, None, None, None)
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
            input: Option<&[u8]>,
        ) -> Option<ProcessOutput> {
            if let Some(path) = args
                .iter()
                .find_map(|arg| arg.strip_prefix("@/proc/self/fd/"))
            {
                let content = std::fs::read_to_string(format!("/proc/self/fd/{path}")).ok()?;
                *self.header_was_private.lock().unwrap() =
                    content == "Authorization: Bearer secret-token-material-1234567890\n";
            }
            self.calls.lock().unwrap().push((
                program.into(),
                args.iter().map(|value| (*value).into()).collect(),
                env.cloned().unwrap_or_default(),
                input.unwrap_or_default().to_vec(),
            ));
            self.output.lock().unwrap().take()
        }
    }

    #[test]
    fn validation_matches_the_public_request_contract() {
        assert_eq!(unique_marker("x\nK:one\n", "K:"), Some("one"));
        assert_eq!(unique_marker("K:one\nK:two\n", "K:"), None);
        assert_eq!(
            normalize_content_type(" Application/PDF; charset=binary "),
            "application/pdf"
        );
        assert_eq!(validate_method("post").unwrap(), "POST");
        assert!(validate_method("HEAD").is_err());
        assert_eq!(validate_path("/api/v1").unwrap(), "/api/v1");
        assert_eq!(
            validate_path("/api/v1/items?page_size=1").unwrap(),
            "/api/v1/items?page_size=1"
        );
        for path in [
            "https://example.test/api/v1",
            "//example.test/api/v1",
            "/api/v1/a/../b",
            "/api/v1/a//b",
            "/api/v1/x#fragment",
            "/api/v1/%2e%2e/admin",
            "/api/v1/a%2fb",
            "/api/v1/a\\b",
            "/api/v1/x\nheader",
        ] {
            assert!(validate_path(path).is_err(), "{path}");
        }
        assert_eq!(validate_request_id("a-_.:9").unwrap(), "a-_.:9");
        assert!(validate_request_id("bad id").is_err());
        assert_eq!(validate_body(" { \"b\": 2 } ").unwrap(), "{\"b\":2}");
        assert!(validate_shape("GET", Some("{}"), true, false).is_err());
        assert!(validate_shape("DELETE", Some("{}"), true, false).is_err());
        assert!(validate_shape("POST", None, false, false).is_err());
        assert!(validate_shape("POST", None, true, true).is_err());
    }

    #[test]
    fn internal_body_uses_stdin_and_is_absent_from_arguments_and_results() {
        let runner = Runner::successful(r#"{"id":"created"}"#);
        let result = command_with_runner(
            Path::new("/srv/YAFVS"),
            "/api/v1/items",
            false,
            "POST",
            Some("request-1"),
            Some(r#"{"secret_field":"request-body-value"}"#),
            true,
            false,
            &runner,
        );
        assert_eq!(result.status, "pass");
        let calls = runner.calls.lock().unwrap();
        let (_, args, _, input) = calls.last().unwrap();
        assert_eq!(input, br#"{"secret_field":"request-body-value"}"#);
        assert!(!args.join(" ").contains("request-body-value"));
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("request-body-value")
        );
    }

    #[test]
    fn direct_token_uses_anonymous_fd_and_sanitized_environment() {
        let token = "secret-token-material-1234567890";
        let runner = Runner::successful("{\"status\":\"ok\"}\n200");
        let environment = BTreeMap::from([
            (OsString::from("PATH"), OsString::from("/usr/bin")),
            (OsString::from(BEARER_TOKEN_ENV), OsString::from(token)),
            (
                OsString::from(BEARER_TOKEN_FILE_ENV),
                OsString::from("/secret/path"),
            ),
        ]);
        let output = direct_curl(
            Path::new("/srv/YAFVS"),
            "/api/v1/items",
            "GET",
            None,
            None,
            token,
            &environment,
            &runner,
        );
        assert!(output.success);
        assert!(*runner.header_was_private.lock().unwrap());
        let calls = runner.calls.lock().unwrap();
        let (_, args, env, input) = calls.last().unwrap();
        assert!(args.iter().any(|arg| arg.starts_with("@/proc/self/fd/")));
        assert!(!args.join(" ").contains(token));
        assert!(!env.values().any(|value| value == token));
        assert!(!env.contains_key(&OsString::from(BEARER_TOKEN_ENV)));
        assert!(!env.contains_key(&OsString::from(BEARER_TOKEN_FILE_ENV)));
        assert!(input.is_empty());
    }

    #[test]
    fn direct_empty_204_is_a_success() {
        let result = finish(
            Path::new("/srv/YAFVS"),
            &Runner::default(),
            true,
            "/api/v1/items/id",
            "DELETE",
            Some("request-1"),
            None,
            ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "\n204".into(),
                stderr: String::new(),
            },
            None,
            false,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.details.as_ref().unwrap()["http_status"],
            Value::from(204)
        );
    }

    #[test]
    fn status_only_drops_response_and_passing_findings() {
        let mut result = result(
            Path::new("/srv/YAFVS"),
            &Runner::default(),
            "Native API request completed.",
            vec![Finding::new("pass", "native-api-request.get", "ok".into())],
        )
        .with_details(json!({"path":"/api/v1/x", "method":"GET", "body_bytes":0, "response":{"items":[{"name":"bounded"}]}}));
        status_only_result(&mut result);
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("\"response\":{\"items"));
        assert_eq!(result.findings[0].check, "native-api-request.status-only");
    }

    #[test]
    fn oversized_response_is_cleared_before_parsing() {
        let output = ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: "x".repeat(MAX_RESPONSE_BYTES + 1),
            stderr: String::new(),
        };
        let result = finish(
            Path::new("/srv/YAFVS"),
            &Runner::default(),
            false,
            "/api/v1/x",
            "GET",
            None,
            None,
            output,
            None,
            false,
        );
        assert_eq!(result.status, "fail");
        assert!(serde_json::to_string(&result).unwrap().len() < 4096);
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    direct: bool,
    path: &str,
    method: &str,
    request_id: Option<&str>,
    body: Option<&str>,
    mut output: ProcessOutput,
    config: Option<Finding>,
    status_only: bool,
) -> ResultEnvelope {
    let body_bytes = body.map_or(0, str::len);
    let oversized = output.stdout.len() > MAX_RESPONSE_BYTES;
    if oversized {
        output.stdout.clear();
    }
    let (parsed, http_status) = if direct {
        parse_status(&output.stdout)
    } else {
        (serde_json::from_str::<Value>(&output.stdout).ok(), None)
    };
    let object = parsed.as_ref().and_then(Value::as_object);
    let ok = !oversized
        && output.success
        && object.is_some()
        && (!direct || http_status.is_some_and(|status| (200..300).contains(&status)))
        || (direct && !oversized && output.success && http_status == Some(204) && parsed.is_none());
    let check = if direct {
        "native-api-request.direct"
    } else {
        "native-api-request.get"
    };
    let message = if direct {
        if ok {
            format!("Direct native API {method} {path} returned an authenticated success response.")
        } else {
            format!(
                "Direct native API {method} {path} failed, returned non-2xx, or returned an invalid response body."
            )
        }
    } else if ok {
        format!("Native API {method} {path} returned JSON.")
    } else {
        format!("Native API {method} {path} failed or returned non-JSON output.")
    };
    let mut details = json!({"path": path, "method": method, "request_id": request_id, "body_bytes": body_bytes, "response": object.cloned()});
    if direct {
        details["direct"] = Value::Bool(true);
        details["http_status"] = http_status.map_or(Value::Null, Value::from);
    }
    let mut finding_details =
        json!({"exit_code": output.exit_code, "response_summary": summarize(object)});
    if direct {
        finding_details["http_status"] = http_status.map_or(Value::Null, Value::from);
        finding_details["request_id"] = request_id.map_or(Value::Null, Value::from);
        finding_details["method"] = Value::String(method.into());
        finding_details["body_bytes"] = Value::from(body_bytes);
    }
    if oversized {
        finding_details["error"] = Value::String(format!(
            "native API response exceeded the {MAX_RESPONSE_BYTES} byte limit"
        ));
    }
    let mut findings = config.into_iter().collect::<Vec<_>>();
    findings.push(
        Finding::new(if ok { "pass" } else { "fail" }, check, message)
            .with_details(finding_details),
    );
    let mut result = result(
        repo_root,
        runner,
        if direct {
            if ok {
                "Direct native API request completed."
            } else {
                "Direct native API request failed."
            }
        } else if ok {
            "Native API request completed."
        } else {
            "Native API request failed."
        },
        findings,
    );
    result.details = Some(details);
    if status_only {
        status_only_result(&mut result);
    }
    result
}

fn parse_status(text: &str) -> (Option<Value>, Option<i64>) {
    let Some((body, status)) = text.rsplit_once('\n') else {
        return (None, None);
    };
    (
        if body.is_empty() {
            None
        } else {
            serde_json::from_str(body).ok()
        },
        status.trim().parse().ok(),
    )
}
fn failed() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: String::new(),
    }
}
fn validate_method(value: &str) -> Result<String, String> {
    let value = value.to_ascii_uppercase();
    if ["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&value.as_str()) {
        Ok(value)
    } else {
        Err("native API request method must be one of: DELETE, GET, PATCH, POST, PUT".into())
    }
}
fn validate_path(value: &str) -> Result<String, String> {
    if value.len() > MAX_REQUEST_PATH_BYTES {
        return Err(format!(
            "native API path exceeds the {MAX_REQUEST_PATH_BYTES} byte limit"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("native API path must not contain control characters".into());
    }
    if value.contains('#') {
        return Err("native API path must not contain a fragment".into());
    }
    if value.contains("://") || value.starts_with("//") {
        return Err("native API path must be relative, not an absolute URL".into());
    }
    let (path, query) = value.split_once('?').unwrap_or((value, ""));
    let lower_path = path.to_ascii_lowercase();
    if path.contains('\\')
        || lower_path.contains("%2f")
        || lower_path.contains("%5c")
        || lower_path.split('/').any(|segment| {
            let decoded_dots = segment.replace("%2e", ".");
            matches!(decoded_dots.as_str(), "." | "..")
        })
    {
        return Err("native API path must not contain encoded traversal or path separators".into());
    }
    if path != "/api/v1" && !path.starts_with("/api/v1/") {
        return Err("native API path must start with /api/v1/".into());
    }
    if path != "/api/v1"
        && path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("native API path must not contain empty, '.', or '..' segments".into());
    }
    Ok(if query.is_empty() {
        path.into()
    } else {
        format!("{path}?{query}")
    })
}
fn validate_request_id(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("request ID must not be empty".into())
    } else if value.len() > REQUEST_ID_MAX {
        Err(format!(
            "request ID must be at most {REQUEST_ID_MAX} characters"
        ))
    } else if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    {
        Err("request ID may contain only ASCII letters, digits, '-', '_', '.', and ':'".into())
    } else {
        Ok(value.into())
    }
}
fn validate_body(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("request body JSON must not be empty".into());
    }
    if value.len() > MAX_REQUEST_BODY_BYTES {
        return Err(format!(
            "request body JSON exceeds the {MAX_REQUEST_BODY_BYTES} byte limit"
        ));
    }
    serde_json::from_str::<Value>(value)
        .map_err(|error| format!("request body must be valid JSON: {}", error))
        .and_then(|value| serde_json::to_string(&value).map_err(|error| error.to_string()))
}
fn validate_shape(
    method: &str,
    body: Option<&str>,
    allow: bool,
    direct_query: bool,
) -> Result<(), String> {
    if matches!(method, "GET" | "DELETE") && body.is_some() {
        return Err(format!(
            "{method} native API requests must not include a request body"
        ));
    }
    if method != "GET" && direct_query {
        return Err("non-GET native API requests must not include query parameters".into());
    }
    if method != "GET" && !allow {
        return Err("non-GET native API requests require --allow-write-control".into());
    }
    if body.is_some() && !allow {
        return Err("native API request bodies require --allow-write-control".into());
    }
    Ok(())
}
fn summarize(object: Option<&Map<String, Value>>) -> Value {
    let Some(value) = object else {
        return json!({"parsed": false});
    };
    let mut out = Map::from_iter([("parsed".into(), Value::Bool(true))]);
    for key in ["status", "database", "id"] {
        if let Some(item) = value.get(key) {
            out.insert(key.into(), item.clone());
        }
    }
    for key in ["page", "summary", "policy"] {
        if let Some(item) = value.get(key).filter(|item| item.is_object()) {
            out.insert(key.into(), item.clone());
        }
    }
    if let Some(error) = value.get("error").and_then(Value::as_object) {
        out.insert(
            "error".into(),
            json!({"code": error.get("code"), "message": error.get("message")}),
        );
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        out.insert("item_count_in_response".into(), Value::from(items.len()));
        out.insert(
            "items_sample".into(),
            Value::Array(items.iter().take(3).map(compact_item).collect()),
        );
    }
    if let Some(items) = value.get("sources").and_then(Value::as_array) {
        out.insert("source_count".into(), Value::from(items.len()));
        out.insert(
            "sources_sample".into(),
            Value::Array(items.iter().take(3).map(compact_item).collect()),
        );
    }
    for key in ["systems", "vulnerabilities"] {
        let Some(items) = value.get(key).and_then(Value::as_array) else {
            continue;
        };
        out.insert(format!("{key}_count"), Value::from(items.len()));
        out.insert(
            format!("{key}_sample"),
            Value::Array(items.iter().take(3).map(compact_item).collect()),
        );
    }
    Value::Object(out)
}
fn compact_item(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return json!({"type": "non-object"});
    };
    let mut compact = object
        .iter()
        .filter(|(key, _)| {
            [
                "id",
                "name",
                "type",
                "version",
                "status",
                "host",
                "port",
                "severity",
                "nvt_oid",
                "sync_status",
                "max_severity",
                "result_count",
                "vulnerability_count",
                "affected_system_count",
                "source_report_count",
                "created_at",
                "creation_time",
            ]
            .contains(&key.as_str())
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<String, Value>>();
    if let Some(scope) = object.get("scope").and_then(Value::as_object) {
        compact.insert(
            "scope".into(),
            Value::Object(
                scope
                    .iter()
                    .filter(|(key, _)| matches!(key.as_str(), "id" | "name"))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
        );
    }
    Value::Object(compact)
}
fn status_only_result(result: &mut ResultEnvelope) {
    let details = result.details.take().unwrap_or_else(|| json!({}));
    let response = details.get("response").and_then(Value::as_object);
    let mut compact = Map::new();
    for key in [
        "path",
        "direct",
        "method",
        "http_status",
        "request_id",
        "body_bytes",
    ] {
        if let Some(value) = details.get(key) {
            compact.insert(key.into(), value.clone());
        }
    }
    compact.insert("response_summary".into(), summarize(response));
    result.details = Some(Value::Object(compact));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            "native-api-request.status-only",
            "Native API request passed; response body summarized.".into(),
        ));
    }
}
