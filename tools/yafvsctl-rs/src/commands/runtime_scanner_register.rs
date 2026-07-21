// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guarded native registration of the prepared OpenVAS scanner.

use super::common::{metadata, runtime_dir};
use super::compose::{compose_command, runtime_app_environment};
use super::direct_api::{OPERATOR_NAME_ENV, validate_operator_name, validate_operator_uuid};
use super::feed_generation::require_current_app_deployment;
use super::native_runtime::{MAX_NATIVE_API_RESPONSE_BYTES, validate_api_path};
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use super::runtime_performance_snapshot::{psql, psql_value};
use super::runtime_probe::socket_readiness_finding;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "runtime-scanner-register";
pub(crate) const SCANNER_ID: &str = "08b69003-5fc2-4037-a479-93b440211c73";
const SCANNER_NAME: &str = "OpenVAS Default";
const SCANNER_SOCKET: &str = "/runtime/run/ospd/ospd-openvas.sock";
const SCANNER_TYPE_OPENVAS: i64 = 2;
const SCANNER_DETAIL_PATH: &str = "/api/v1/scanners/08b69003-5fc2-4037-a479-93b440211c73";
const SCANNER_VERIFY_PATH: &str = "/api/v1/scanners/08b69003-5fc2-4037-a479-93b440211c73/verify";
const SCANNER_PREFLIGHT_PATH: &str = "/api/v1/scanners?page=1&page_size=1&sort=name";
const USER_PREFLIGHT_PATH: &str = "/api/v1/users?page=1&page_size=500&sort=name";
const DEFAULT_OPERATOR_NAME: &str = "admin";
const NATIVE_API_TIMEOUT: Duration = Duration::from_secs(30);
const NATIVE_API_BASE_URL: &str = "http://127.0.0.1:9080";
const BROWSER_PROXY_VERIFY_SCRIPT: &str = r#"
test -n "${YAFVS_API_BROWSER_PROXY_SECRET:-}"
exec curl -sS --max-time 10 --max-filesize 8388608 -X POST -w '\n%{http_code}' -H "x-yafvs-browser-proxy-secret: ${YAFVS_API_BROWSER_PROXY_SECRET}" -H "$2" -H "$3" "http://127.0.0.1:9080$1"
"#;

/// This operation deliberately accepts no caller-controlled values. It owns
/// the one built-in scanner identity required by the supported OSPD runtime.
/// The conditional timestamp keeps an already-correct invocation semantically
/// idempotent while repairing all configuration and ownership drift.
const ENSURE_DEFAULT_SCANNER_SQL: &str = r#"
WITH ensured AS (
    INSERT INTO public.scanners
        (uuid, owner, name, comment, host, port, type, ca_pub, credential,
         relay_host, relay_port, creation_time, modification_time)
    VALUES
        ('08b69003-5fc2-4037-a479-93b440211c73', NULL, 'OpenVAS Default', '',
         '/runtime/run/ospd/ospd-openvas.sock', 0, 2, NULL, NULL, NULL, 0,
         m_now(), m_now())
    ON CONFLICT (uuid) DO UPDATE
       SET modification_time = CASE
               WHEN scanners.owner IS NOT NULL
                 OR scanners.name IS DISTINCT FROM 'OpenVAS Default'
                 OR scanners.host IS DISTINCT FROM '/runtime/run/ospd/ospd-openvas.sock'
                 OR scanners.port IS DISTINCT FROM 0
                 OR scanners.type IS DISTINCT FROM 2
                 OR scanners.ca_pub IS NOT NULL
                 OR scanners.credential IS NOT NULL
                 OR scanners.relay_host IS NOT NULL
                 OR scanners.relay_port IS DISTINCT FROM 0
               THEN m_now()
               ELSE scanners.modification_time
           END,
           owner = NULL,
           name = 'OpenVAS Default',
           host = '/runtime/run/ospd/ospd-openvas.sock',
           port = 0,
           type = 2,
           ca_pub = NULL,
           credential = NULL,
           relay_host = NULL,
           relay_port = 0
    RETURNING uuid::text AS id,
              owner IS NULL AS owner_is_null,
              name,
              host,
              port::bigint,
              type::bigint AS scanner_type,
              ca_pub IS NULL AS ca_pub_is_null,
              credential IS NULL AS credential_is_null,
              relay_host IS NULL AS relay_host_is_null,
              relay_port::bigint
)
SELECT json_build_object(
           'id', id,
           'owner_is_null', owner_is_null,
           'name', name,
           'host', host,
           'port', port,
           'scanner_type', scanner_type,
           'ca_pub_is_null', ca_pub_is_null,
           'credential_is_null', credential_is_null,
           'relay_host_is_null', relay_host_is_null,
           'relay_port', relay_port
       )::text
  FROM ensured;
"#;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DefaultScannerRecord {
    id: String,
    owner_is_null: bool,
    name: String,
    host: String,
    port: i64,
    scanner_type: i64,
    ca_pub_is_null: bool,
    credential_is_null: bool,
    relay_host_is_null: bool,
    relay_port: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct OperatorIdentity {
    id: String,
    name: String,
}

struct NativeCall {
    output: ProcessOutput,
    parsed: Option<Value>,
    http_status: Option<i64>,
    oversized: bool,
    error: Option<String>,
}

pub fn command_runtime_scanner_register(repo_root: &Path) -> ResultEnvelope {
    command_with_runner_and_timeout(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_with_runner_and_timeout(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
            Ok(lock) => lock,
            Err(error) => return lock_failure(repo_root, runner, error),
        };
    let mut context = SystemContext { repo_root, runner };
    command_unlocked(repo_root, runner, &mut context)
}

trait RegisterContext {
    fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String>;
    fn deployment(&mut self, environment: &BTreeMap<OsString, OsString>) -> Result<(), String>;
    fn ospd_socket(&mut self) -> Finding;
    fn ensure_default_scanner(&mut self) -> ProcessOutput;
    fn native_get(&mut self, path: &str) -> NativeCall;
    fn native_verify(&mut self, operator: &OperatorIdentity) -> NativeCall;
}

struct SystemContext<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
}

impl RegisterContext for SystemContext<'_> {
    fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
        runtime_app_environment(self.repo_root)
            .map_err(|error| format!("Application runtime environment is unavailable: {error}"))
    }

    fn deployment(&mut self, environment: &BTreeMap<OsString, OsString>) -> Result<(), String> {
        require_current_app_deployment(self.repo_root, self.runner, environment).map(|_| ())
    }

    fn ospd_socket(&mut self) -> Finding {
        socket_readiness_finding(
            "ospd.socket",
            "ospd-openvas",
            &runtime_dir(self.repo_root).join("run/ospd/ospd-openvas.sock"),
            "fail",
        )
    }

    fn ensure_default_scanner(&mut self) -> ProcessOutput {
        psql(self.repo_root, ENSURE_DEFAULT_SCANNER_SQL, self.runner)
    }

    fn native_get(&mut self, path: &str) -> NativeCall {
        container_native_get(self.repo_root, self.runner, path)
    }

    fn native_verify(&mut self, operator: &OperatorIdentity) -> NativeCall {
        browser_proxy_verify(self.repo_root, self.runner, operator)
    }
}

fn command_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    context: &mut dyn RegisterContext,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let environment = match context.app_environment() {
        Ok(value) => value,
        Err(error) => {
            return result(
                repo_root,
                runner,
                "Runtime scanner registration stopped at prerequisites.",
                vec![Finding::new("fail", "runtime.app-environment", error)],
            );
        }
    };
    if let Err(error) = context.deployment(&environment) {
        findings.push(Finding::new(
            "fail",
            "runtime.app-deployment-receipt",
            error,
        ));
        return result(
            repo_root,
            runner,
            "Runtime scanner registration stopped at prerequisites.",
            findings,
        );
    }
    findings.push(Finding::new(
        "pass",
        "runtime.app-deployment-receipt",
        "Prepared application deployment receipt is valid for scanner registration.".into(),
    ));
    let socket = context.ospd_socket();
    let ready = socket.status == "pass";
    findings.push(socket);
    if !ready {
        return result(
            repo_root,
            runner,
            "Runtime scanner registration stopped at prerequisites.",
            findings,
        );
    }

    let preflight = context.native_get(SCANNER_PREFLIGHT_PATH);
    let preflight_ok = successful_object(&preflight, 200);
    findings.push(api_finding(
        if preflight_ok { "pass" } else { "fail" },
        "native.scanners.preflight",
        if preflight_ok {
            "Container-internal native scanner API preflight completed."
        } else {
            "Container-internal native scanner API preflight failed."
        },
        &preflight,
    ));
    if !preflight_ok {
        return result(
            repo_root,
            runner,
            "Scanner registration stopped at the native API preflight.",
            findings,
        );
    }

    let operator_name = match configured_operator_name(&environment) {
        Ok(value) => value,
        Err(error) => {
            findings.push(Finding::new("fail", "native.scanner-operator", error));
            return result(
                repo_root,
                runner,
                "Scanner registration stopped while resolving its native operator.",
                findings,
            );
        }
    };
    let users = context.native_get(USER_PREFLIGHT_PATH);
    let operator = users
        .parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array)
        .and_then(|items| resolve_operator(items, &operator_name));
    let operator_ok = successful_object(&users, 200) && operator.is_some();
    findings.push(
        api_finding(
            if operator_ok { "pass" } else { "fail" },
            "native.scanner-operator",
            if operator_ok {
                "Native scanner registration operator resolved uniquely."
            } else {
                "Native scanner registration operator could not be resolved uniquely."
            },
            &users,
        )
        .with_details(json!({
            "http_status": users.http_status,
            "oversized": users.oversized,
            "operator_name": operator_name,
            "operator_id": operator.as_ref().map(|value| value.id.as_str()),
            "error": users.error,
        })),
    );
    let Some(operator) = operator else {
        return result(
            repo_root,
            runner,
            "Scanner registration stopped while resolving its native operator.",
            findings,
        );
    };

    let ensured = context.ensure_default_scanner();
    let record = ensured
        .success
        .then(|| parse_default_scanner_record(psql_value(&ensured.stdout)))
        .flatten();
    let ensured_ok = record.as_ref().is_some_and(default_scanner_record_is_exact);
    findings.push(
        Finding::new(
            if ensured_ok { "pass" } else { "fail" },
            "manager.scanner.openvas-default.ensure",
            if ensured_ok {
                "Rust manager operation ensured the fixed OpenVAS Default scanner registration."
            } else {
                "Rust manager operation failed to ensure the fixed OpenVAS Default scanner registration."
            }
            .into(),
        )
        .with_details(json!({
            "exit_code": ensured.exit_code,
            "scanner": record.as_ref().map(default_scanner_record_summary),
        })),
    );
    if !ensured_ok {
        return result(
            repo_root,
            runner,
            "Scanner registration stopped while ensuring the native manager state.",
            findings,
        );
    }

    let confirmed = context.native_get(SCANNER_DETAIL_PATH);
    let confirmed_ok = successful_object(&confirmed, 200)
        && confirmed
            .parsed
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(default_scanner_api_object_is_exact);
    findings.push(api_finding(
        if confirmed_ok { "pass" } else { "fail" },
        "native.scanner.openvas-default",
        "Native API confirmed the fixed OpenVAS Default scanner registration.",
        &confirmed,
    ));
    if !confirmed_ok {
        return result(
            repo_root,
            runner,
            "Scanner registration stopped during native confirmation.",
            findings,
        );
    }

    let verified_response = context.native_verify(&operator);
    let verified = successful_object(&verified_response, 200)
        && verified_response
            .parsed
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|object| object.get("verified"))
            .and_then(Value::as_bool)
            == Some(true);
    findings.push(api_finding(
        if verified { "pass" } else { "warn" },
        "native.scanner.openvas-default.verify",
        if verified {
            "Container-internal native OpenVAS Default scanner verification completed."
        } else {
            "Container-internal native OpenVAS Default scanner verification did not complete."
        },
        &verified_response,
    ));
    result(
        repo_root,
        runner,
        "Runtime scanner registration completed through the native manager path.",
        findings,
    )
}

fn configured_operator_name(environment: &BTreeMap<OsString, OsString>) -> Result<String, String> {
    let value = environment
        .get(&OsString::from(OPERATOR_NAME_ENV))
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_OPERATOR_NAME);
    validate_operator_name(value, OPERATOR_NAME_ENV)
}

fn resolve_operator(items: &[Value], name: &str) -> Option<OperatorIdentity> {
    let mut matches = items
        .iter()
        .filter_map(Value::as_object)
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(name));
    let item = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    let id = item.get("id").and_then(Value::as_str)?;
    Some(OperatorIdentity {
        id: validate_operator_uuid(id, "native scanner operator id").ok()?,
        name: name.to_owned(),
    })
}

fn browser_proxy_verify(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    operator: &OperatorIdentity,
) -> NativeCall {
    let environment = match runtime_app_environment(repo_root) {
        Ok(value) => value,
        Err(_) => {
            return failed_native_call(
                "application runtime environment is unavailable for scanner verification",
            );
        }
    };
    let arguments = browser_proxy_verify_arguments(repo_root, operator);
    let output = runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&environment),
            Some(NATIVE_API_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        });
    parse_native_call_output(output, "native scanner verification")
}

fn browser_proxy_verify_arguments(repo_root: &Path, operator: &OperatorIdentity) -> Vec<String> {
    compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "yafvs-api".into(),
            "sh".into(),
            "-ceu".into(),
            BROWSER_PROXY_VERIFY_SCRIPT.into(),
            "yafvsctl-browser-proxy-verify".into(),
            SCANNER_VERIFY_PATH.into(),
            format!("x-yafvs-operator-name: {}", operator.name),
            format!("x-yafvs-operator-uuid: {}", operator.id),
        ],
    )
}

fn container_native_get(repo_root: &Path, runner: &dyn CommandRunner, path: &str) -> NativeCall {
    if let Err(error) = validate_api_path(path) {
        return failed_native_call(&error);
    }
    let environment = match runtime_app_environment(repo_root) {
        Ok(value) => value,
        Err(_) => {
            return failed_native_call(
                "application runtime environment is unavailable for native scanner access",
            );
        }
    };
    let arguments = compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "yafvs-api".into(),
            "curl".into(),
            "-sS".into(),
            "--max-time".into(),
            "10".into(),
            "--max-filesize".into(),
            MAX_NATIVE_API_RESPONSE_BYTES.to_string(),
            "-w".into(),
            "\n%{http_code}".into(),
            format!("{NATIVE_API_BASE_URL}{path}"),
        ],
    );
    let output = runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&environment),
            Some(NATIVE_API_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        });
    parse_native_call_output(output, "native scanner request")
}

fn parse_native_call_output(mut output: ProcessOutput, context: &str) -> NativeCall {
    let oversized = output.stdout.len() > MAX_NATIVE_API_RESPONSE_BYTES.saturating_add(4);
    if oversized {
        output.stdout.clear();
        output.stderr.clear();
        output.success = false;
        output.exit_code = Some(1);
        return NativeCall {
            output,
            parsed: None,
            http_status: None,
            oversized: true,
            error: Some(format!("{context} response exceeded its byte limit")),
        };
    }
    let (body, http_status) = split_http_status(&output.stdout);
    let parsed = serde_json::from_str::<Value>(&body).ok();
    let error = if !output.success {
        Some(format!("container-internal {context} command failed"))
    } else if http_status.is_none() {
        Some(format!(
            "container-internal {context} omitted its HTTP status"
        ))
    } else if parsed.as_ref().is_none_or(|value| !value.is_object()) {
        Some(format!(
            "container-internal {context} returned invalid JSON"
        ))
    } else {
        None
    };
    output.stdout.clear();
    output.stderr.clear();
    NativeCall {
        output,
        parsed,
        http_status,
        oversized: false,
        error,
    }
}

fn split_http_status(output: &str) -> (String, Option<i64>) {
    let Some((body, status)) = output.rsplit_once('\n') else {
        return (String::new(), None);
    };
    let status = status
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|value| (100..=599).contains(value));
    (body.to_owned(), status)
}

fn failed_native_call(error: &str) -> NativeCall {
    NativeCall {
        output: ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        },
        parsed: None,
        http_status: None,
        oversized: false,
        error: Some(error.into()),
    }
}

fn successful_object(response: &NativeCall, expected_status: i64) -> bool {
    !response.oversized
        && response.output.success
        && response.http_status == Some(expected_status)
        && response.error.is_none()
        && response.parsed.as_ref().is_some_and(Value::is_object)
}

fn api_finding(status: &str, check: &str, message: &str, response: &NativeCall) -> Finding {
    Finding::new(status, check, message.into()).with_details(json!({
        "http_status": response.http_status,
        "oversized": response.oversized,
        "error": response.error,
        "scanner_id": response.parsed.as_ref().and_then(Value::as_object)
            .and_then(|object| object.get("id")).and_then(Value::as_str),
        "verification_mode": response.parsed.as_ref().and_then(Value::as_object)
            .and_then(|object| object.get("verification_mode")).and_then(Value::as_str),
    }))
}

fn parse_default_scanner_record(value: &str) -> Option<DefaultScannerRecord> {
    serde_json::from_str(value).ok()
}

fn default_scanner_record_is_exact(record: &DefaultScannerRecord) -> bool {
    record.id.eq_ignore_ascii_case(SCANNER_ID)
        && record.owner_is_null
        && record.name == SCANNER_NAME
        && record.host == SCANNER_SOCKET
        && record.port == 0
        && record.scanner_type == SCANNER_TYPE_OPENVAS
        && record.ca_pub_is_null
        && record.credential_is_null
        && record.relay_host_is_null
        && record.relay_port == 0
}

fn default_scanner_record_summary(record: &DefaultScannerRecord) -> Value {
    json!({
        "id": record.id,
        "owner_is_null": record.owner_is_null,
        "name": record.name,
        "host": record.host,
        "port": record.port,
        "scanner_type": record.scanner_type,
        "ca_pub_is_null": record.ca_pub_is_null,
        "credential_is_null": record.credential_is_null,
        "relay_host_is_null": record.relay_host_is_null,
        "relay_port": record.relay_port,
    })
}

pub(crate) fn default_scanner_api_object_is_exact(object: &Map<String, Value>) -> bool {
    object.get("id").and_then(Value::as_str) == Some(SCANNER_ID)
        && object.get("name").and_then(Value::as_str) == Some(SCANNER_NAME)
        && object.get("host").and_then(Value::as_str) == Some(SCANNER_SOCKET)
        && object.get("port").and_then(Value::as_i64) == Some(0)
        && object.get("scanner_type").and_then(Value::as_i64) == Some(SCANNER_TYPE_OPENVAS)
        && object.get("ca_pub").is_none_or(Value::is_null)
        && object.get("credential").is_none_or(Value::is_null)
        && object.get("relay_host").is_none_or(Value::is_null)
        && object.get("relay_port").and_then(Value::as_i64) == Some(0)
}

fn result(
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
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

fn lock_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    error: RuntimeLockError,
) -> ResultEnvelope {
    let (message, details) = match error {
        RuntimeLockError::Timeout {
            name,
            operation,
            holder,
        } => (
            format!("Timed out waiting for runtime lock {name:?}."),
            json!({"operation": operation, "holder": holder}),
        ),
        RuntimeLockError::Setup(message) => (
            format!("Runtime feed lifecycle lock failed closed: {message}."),
            json!({}),
        ),
    };
    result(
        repo_root,
        runner,
        "Runtime scanner registration stopped while waiting for the feed lifecycle lock.",
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message)
                .with_path(&runtime_lock_dir(repo_root).display().to_string())
                .with_details(details),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Runner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program.into())
                    .chain(args.iter().map(|arg| (*arg).into()))
                    .collect(),
            );
            Some(output(true, ""))
        }
    }

    struct Context {
        ready: bool,
        database_output: ProcessOutput,
        database_calls: usize,
        api_outputs: VecDeque<NativeCall>,
        api_calls: Vec<String>,
    }

    impl Context {
        fn successful() -> Self {
            Self {
                ready: true,
                database_output: output(true, &record_json()),
                database_calls: 0,
                api_outputs: VecDeque::from([
                    api(200, json!({"items": [], "page": {"total": 0}})),
                    api(200, operator_collection()),
                    api(200, scanner_detail()),
                    api(
                        200,
                        json!({
                            "id": SCANNER_ID,
                            "verified": true,
                            "verification_mode": "osp-unix-socket"
                        }),
                    ),
                ]),
                api_calls: Vec::new(),
            }
        }
    }

    impl RegisterContext for Context {
        fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
            self.ready
                .then(BTreeMap::new)
                .ok_or_else(|| "environment unavailable".into())
        }

        fn deployment(&mut self, _: &BTreeMap<OsString, OsString>) -> Result<(), String> {
            self.ready
                .then_some(())
                .ok_or_else(|| "deployment unavailable".into())
        }

        fn ospd_socket(&mut self) -> Finding {
            Finding::new(
                if self.ready { "pass" } else { "fail" },
                "ospd.socket",
                "socket".into(),
            )
        }

        fn ensure_default_scanner(&mut self) -> ProcessOutput {
            self.database_calls += 1;
            self.database_output.clone()
        }

        fn native_get(&mut self, path: &str) -> NativeCall {
            self.api_calls.push(format!("GET {path}"));
            self.api_outputs.pop_front().unwrap()
        }

        fn native_verify(&mut self, operator: &OperatorIdentity) -> NativeCall {
            self.api_calls.push(format!(
                "POST {SCANNER_VERIFY_PATH} {} {}",
                operator.name, operator.id
            ));
            self.api_outputs.pop_front().unwrap()
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

    fn api(status: i64, parsed: Value) -> NativeCall {
        NativeCall {
            output: output(true, ""),
            parsed: Some(parsed),
            http_status: Some(status),
            oversized: false,
            error: None,
        }
    }

    fn operator_collection() -> Value {
        json!({
            "items": [{
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": DEFAULT_OPERATOR_NAME
            }],
            "page": {"total": 1}
        })
    }

    fn record_json() -> String {
        json!({
            "id": SCANNER_ID,
            "owner_is_null": true,
            "name": SCANNER_NAME,
            "host": SCANNER_SOCKET,
            "port": 0,
            "scanner_type": SCANNER_TYPE_OPENVAS,
            "ca_pub_is_null": true,
            "credential_is_null": true,
            "relay_host_is_null": true,
            "relay_port": 0,
        })
        .to_string()
    }

    fn scanner_detail() -> Value {
        json!({
            "id": SCANNER_ID,
            "name": SCANNER_NAME,
            "comment": "",
            "host": SCANNER_SOCKET,
            "port": 0,
            "scanner_type": SCANNER_TYPE_OPENVAS,
            "relay_host": null,
            "relay_port": 0,
        })
    }

    fn run(context: &mut Context) -> ResultEnvelope {
        command_unlocked(Path::new("/repo"), &Runner::default(), context)
    }

    #[test]
    fn fixed_manager_operation_and_native_confirmation_pass() {
        let mut context = Context::successful();
        let result = run(&mut context);
        assert_eq!(result.status, "pass");
        assert_eq!(context.database_calls, 1);
        assert_eq!(
            context.api_calls,
            vec![
                format!("GET {SCANNER_PREFLIGHT_PATH}"),
                format!("GET {USER_PREFLIGHT_PATH}"),
                format!("GET {SCANNER_DETAIL_PATH}"),
                format!(
                    "POST {SCANNER_VERIFY_PATH} {DEFAULT_OPERATOR_NAME} 123e4567-e89b-12d3-a456-426614174000"
                ),
            ]
        );
    }

    #[test]
    fn ensure_sql_owns_only_the_fixed_built_in_contract() {
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains(SCANNER_ID));
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains(SCANNER_SOCKET));
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains("ON CONFLICT (uuid) DO UPDATE"));
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains("owner = NULL"));
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains("credential = NULL"));
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains("ca_pub = NULL"));
        assert!(ENSURE_DEFAULT_SCANNER_SQL.contains("relay_host = NULL"));
        assert!(!ENSURE_DEFAULT_SCANNER_SQL.contains('$'));
        assert!(!ENSURE_DEFAULT_SCANNER_SQL.contains("format!"));
    }

    #[test]
    fn parser_rejects_drift_and_unknown_fields() {
        let exact = parse_default_scanner_record(&record_json()).unwrap();
        assert!(default_scanner_record_is_exact(&exact));
        let mut drifted: Value = serde_json::from_str(&record_json()).unwrap();
        drifted["host"] = Value::String("elsewhere".into());
        assert!(!default_scanner_record_is_exact(
            &parse_default_scanner_record(&drifted.to_string()).unwrap()
        ));
        drifted["host"] = Value::String(SCANNER_SOCKET.into());
        drifted["unexpected"] = Value::Bool(true);
        assert!(parse_default_scanner_record(&drifted.to_string()).is_none());
    }

    #[test]
    fn preflight_failure_prevents_database_mutation() {
        let mut context = Context::successful();
        context.api_outputs = VecDeque::from([api(503, json!({"error": {}}))]);
        assert_eq!(run(&mut context).status, "fail");
        assert_eq!(context.database_calls, 0);
        assert_eq!(context.api_calls.len(), 1);
    }

    #[test]
    fn database_failure_stops_before_confirmation() {
        let mut context = Context::successful();
        context.database_output = output(false, "database detail must not be exposed");
        assert_eq!(run(&mut context).status, "fail");
        assert_eq!(context.database_calls, 1);
        assert_eq!(context.api_calls.len(), 2);
    }

    #[test]
    fn confirmation_drift_fails_before_verification() {
        let mut context = Context::successful();
        let mut drifted = scanner_detail();
        drifted["scanner_type"] = Value::from(5);
        context.api_outputs = VecDeque::from([
            api(200, json!({"items": [], "page": {"total": 0}})),
            api(200, operator_collection()),
            api(200, drifted),
        ]);
        assert_eq!(run(&mut context).status, "fail");
        assert_eq!(context.api_calls.len(), 3);
    }

    #[test]
    fn ambiguous_operator_prevents_database_mutation() {
        let mut context = Context::successful();
        context.api_outputs = VecDeque::from([
            api(200, json!({"items": [], "page": {"total": 0}})),
            api(
                200,
                json!({
                    "items": [
                        {"id": "123e4567-e89b-12d3-a456-426614174000", "name": "admin"},
                        {"id": "223e4567-e89b-12d3-a456-426614174000", "name": "admin"}
                    ],
                    "page": {"total": 2}
                }),
            ),
        ]);
        assert_eq!(run(&mut context).status, "fail");
        assert_eq!(context.database_calls, 0);
        assert_eq!(context.api_calls.len(), 2);
    }

    #[test]
    fn browser_proxy_verification_contract_keeps_secrets_out_of_arguments() {
        assert!(BROWSER_PROXY_VERIFY_SCRIPT.contains("YAFVS_API_BROWSER_PROXY_SECRET"));
        assert!(BROWSER_PROXY_VERIFY_SCRIPT.contains("-H \"$2\" -H \"$3\""));
        assert!(BROWSER_PROXY_VERIFY_SCRIPT.contains("http://127.0.0.1:9080$1"));
        assert_eq!(
            split_http_status("{\"verified\":true}\n200"),
            ("{\"verified\":true}".into(), Some(200))
        );
        assert_eq!(split_http_status("missing"), (String::new(), None));

        let operator = OperatorIdentity {
            id: "123e4567-e89b-12d3-a456-426614174000".into(),
            name: "operator-$(must-not-execute)-`or-this`".into(),
        };
        let call = browser_proxy_verify_arguments(Path::new("/repo"), &operator);
        assert!(
            call.contains(&"x-yafvs-operator-name: operator-$(must-not-execute)-`or-this`".into())
        );
        assert!(
            call.contains(&"x-yafvs-operator-uuid: 123e4567-e89b-12d3-a456-426614174000".into())
        );
        assert!(!BROWSER_PROXY_VERIFY_SCRIPT.contains("YAFVS_REGISTER_OPERATOR"));
    }

    #[test]
    fn native_get_preserves_non_success_http_status() {
        let response = parse_native_call_output(
            ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "{\"error\":{}}\n503".into(),
                stderr: String::new(),
            },
            "native scanner request",
        );
        assert_eq!(response.http_status, Some(503));
        assert!(!successful_object(&response, 200));
    }

    #[test]
    fn verification_failure_remains_nonfatal_warning() {
        let mut context = Context::successful();
        context.api_outputs.pop_back();
        context
            .api_outputs
            .push_back(api(409, json!({"verified": false})));
        let result = run(&mut context);
        assert_eq!(result.status, "warn");
        assert_eq!(
            result.findings.last().unwrap().check,
            "native.scanner.openvas-default.verify"
        );
    }

    #[test]
    fn prerequisite_failure_runs_no_mutation() {
        let mut context = Context::successful();
        context.ready = false;
        assert_eq!(run(&mut context).status, "fail");
        assert_eq!(context.database_calls, 0);
        assert!(context.api_calls.is_empty());
    }

    #[test]
    fn lock_contention_fails_closed() {
        let root = std::env::temp_dir().join(format!("yafvs-register-lock-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let _holder =
            RuntimeOperationLock::acquire(&root, FEED_ACTIVATION_LOCK, "holder", Duration::ZERO)
                .unwrap();
        let runner = Runner::default();
        let result = command_with_runner_and_timeout(&root, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.first().is_none_or(|program| program != "docker"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
