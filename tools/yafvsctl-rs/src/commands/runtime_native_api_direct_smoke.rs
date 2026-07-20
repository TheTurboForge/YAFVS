// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::write_secure_json_artifact;
use super::common::{compact_finding, metadata, output_tail, runtime_dir};
use super::direct_api::{
    BEARER_TOKEN_ENV, DIRECT_BIND_ENV, bearer_token_is_acceptable, direct_base_url,
    direct_config_shape_finding, direct_host, direct_port, ensure_direct_environment_defaults,
    environment_value, host_is_loopback, host_is_wildcard,
};
use super::feed_generation::{
    command_feed_generation_runtime_guard_with_runner, deployed_app_environment,
    native_api_up_arguments, pinned_app_compose_command, refresh_deployment,
    require_current_app_deployment_snapshot, run_compose,
};
use super::native_api_request::{
    DirectRawRequest, MAX_RESPONSE_BYTES, direct_token, raw_direct_api_request,
};
use super::native_runtime::percent_encode_component;
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use super::runtime_native_api_smoke::command_runtime_native_api_smoke_with_runner;
use super::runtime_setup::ensure_runtime_setup;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::thread;
use std::time::Duration;

const COMMAND: &str = "runtime-native-api-direct-smoke";
const CONFIG_TIMEOUT: Duration = Duration::from_secs(120);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1200);
const START_TIMEOUT: Duration = Duration::from_secs(300);
const HEALTH_ATTEMPTS: usize = 20;
const HEALTH_DELAY: Duration = Duration::from_secs(1);
const REQUEST_ID_MAX: usize = 128;
const REPORTS_PATH: &str = "/api/v1/reports?page_size=1";
const EXPECTED_SECURITY_HEADERS: &[(&str, &str)] = &[
    ("cache-control", "no-store"),
    ("pragma", "no-cache"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("x-frame-options", "DENY"),
];

struct DisabledProbe {
    check: &'static str,
    method: &'static str,
    path: &'static str,
    body: Option<&'static str>,
}

const DISABLED_WRITE_PROBES: &[DisabledProbe] = &[
    DisabledProbe {
        check: "native-api-direct.scope-write-disabled",
        method: "POST",
        path: "/api/v1/scopes",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.alert-definition-put-disabled",
        method: "PUT",
        path: "/api/v1/alerts/00000000-0000-0000-0000-000000000000/definition",
        body: Some(
            r#"{"expected_revision":"0","definition":{"method":"SYSLOG","name":"disabled alert definition replacement","active":false,"status":"Done"}}"#,
        ),
    },
    DisabledProbe {
        check: "native-api-direct.filter-create-disabled",
        method: "POST",
        path: "/api/v1/filters",
        body: Some(r#"{"name":"disabled saved filter","filter_type":"task"}"#),
    },
    DisabledProbe {
        check: "native-api-direct.filter-patch-disabled",
        method: "PATCH",
        path: "/api/v1/filters/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.filter-delete-disabled",
        method: "DELETE",
        path: "/api/v1/filters/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.filter-restore-disabled",
        method: "POST",
        path: "/api/v1/filters/00000000-0000-0000-0000-000000000000/restore",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.filter-hard-delete-disabled",
        method: "DELETE",
        path: "/api/v1/filters/00000000-0000-0000-0000-000000000000/trash",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.port-list-create-disabled",
        method: "POST",
        path: "/api/v1/port-lists",
        body: Some(
            r#"{"name":"disabled-write-port-list","port_ranges":[{"protocol":"tcp","start":80,"end":80}]}"#,
        ),
    },
    DisabledProbe {
        check: "native-api-direct.port-list-patch-disabled",
        method: "PATCH",
        path: "/api/v1/port-lists/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.port-list-delete-disabled",
        method: "DELETE",
        path: "/api/v1/port-lists/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.port-list-restore-disabled",
        method: "POST",
        path: "/api/v1/port-lists/00000000-0000-0000-0000-000000000000/restore",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.port-list-hard-delete-disabled",
        method: "DELETE",
        path: "/api/v1/port-lists/00000000-0000-0000-0000-000000000000/trash",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.schedule-create-disabled",
        method: "POST",
        path: "/api/v1/schedules",
        body: Some(
            r#"{"name":"disabled-write-schedule","timezone":"UTC","icalendar":"BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nDTSTART:20300101T000000Z\nEND:VEVENT\nEND:VCALENDAR"}"#,
        ),
    },
    DisabledProbe {
        check: "native-api-direct.schedule-patch-disabled",
        method: "PATCH",
        path: "/api/v1/schedules/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.schedule-delete-disabled",
        method: "DELETE",
        path: "/api/v1/schedules/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.schedule-restore-disabled",
        method: "POST",
        path: "/api/v1/schedules/00000000-0000-0000-0000-000000000000/restore",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.schedule-hard-delete-disabled",
        method: "DELETE",
        path: "/api/v1/schedules/00000000-0000-0000-0000-000000000000/trash",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.scan-config-patch-disabled",
        method: "PATCH",
        path: "/api/v1/scan-configs/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.scan-config-create-disabled",
        method: "POST",
        path: "/api/v1/scan-configs",
        body: Some(
            r#"{"base_scan_config_id":"00000000-0000-0000-0000-000000000000","comment":"disabled scan-config create","name":"disabled scan-config create"}"#,
        ),
    },
    DisabledProbe {
        check: "native-api-direct.scan-config-clone-disabled",
        method: "POST",
        path: "/api/v1/scan-configs/00000000-0000-0000-0000-000000000000/clone",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.scan-config-hard-delete-disabled",
        method: "DELETE",
        path: "/api/v1/scan-configs/00000000-0000-0000-0000-000000000000/trash",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.target-create-disabled",
        method: "POST",
        path: "/api/v1/targets",
        body: Some(
            r#"{"name":"disabled target create","port_list_id":"00000000-0000-0000-0000-000000000000","hosts":["192.0.2.42"],"exclude_hosts":[],"alive_tests":["TCP-ACK Service Ping"],"allow_simultaneous_ips":true,"reverse_lookup_only":false,"reverse_lookup_unify":false}"#,
        ),
    },
    DisabledProbe {
        check: "native-api-direct.target-patch-disabled",
        method: "PATCH",
        path: "/api/v1/targets/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.target-clone-disabled",
        method: "POST",
        path: "/api/v1/targets/00000000-0000-0000-0000-000000000000/clone",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.target-delete-disabled",
        method: "DELETE",
        path: "/api/v1/targets/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.target-restore-disabled",
        method: "POST",
        path: "/api/v1/targets/00000000-0000-0000-0000-000000000000/restore",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.target-hard-delete-disabled",
        method: "DELETE",
        path: "/api/v1/targets/00000000-0000-0000-0000-000000000000/trash",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.task-create-disabled",
        method: "POST",
        path: "/api/v1/tasks",
        body: Some(
            r#"{"name":"yafvs-direct-disabled-task-create","target_id":"00000000-0000-0000-0000-000000000000","config_id":"00000000-0000-0000-0000-000000000000","scanner_id":"00000000-0000-0000-0000-000000000000"}"#,
        ),
    },
    DisabledProbe {
        check: "native-api-direct.task-patch-disabled",
        method: "PATCH",
        path: "/api/v1/tasks/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.override-patch-disabled",
        method: "PATCH",
        path: "/api/v1/overrides/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.tag-write-disabled",
        method: "POST",
        path: "/api/v1/tags",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.tag-delete-disabled",
        method: "DELETE",
        path: "/api/v1/tags/00000000-0000-0000-0000-000000000000",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.tag-restore-disabled",
        method: "POST",
        path: "/api/v1/tags/00000000-0000-0000-0000-000000000000/restore",
        body: None,
    },
    DisabledProbe {
        check: "native-api-direct.tag-hard-delete-disabled",
        method: "DELETE",
        path: "/api/v1/tags/00000000-0000-0000-0000-000000000000/trash",
        body: None,
    },
];

struct ProbeResponse {
    output: ProcessOutput,
    body: Option<Value>,
    status: Option<i64>,
    headers: BTreeMap<String, String>,
}

pub fn command_runtime_native_api_direct_smoke(
    repo_root: &Path,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner_and_timeout(
        repo_root,
        status_only,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_with_runner_and_timeout(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
            Ok(lock) => lock,
            Err(error) => return lock_failure(repo_root, status_only, runner, error),
        };
    command_unlocked(repo_root, status_only, runner)
}

fn command_unlocked(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut findings = ensure_runtime_setup(repo_root, runner);
    findings.extend(
        command_feed_generation_runtime_guard_with_runner(repo_root, false, runner).findings,
    );
    let mut environment = match deployed_app_environment(repo_root, runner) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new("fail", "runtime.app-environment", error));
            return finish(
                repo_root,
                status_only,
                runner,
                "Direct native API smoke stopped at prerequisites.",
                findings,
                None,
                Vec::new(),
            );
        }
    };
    if let Err(error) = ensure_direct_environment_defaults(repo_root, &mut environment) {
        findings.push(Finding::new(
            "fail",
            "native-api-direct.config-shape",
            format!("Direct native API runtime defaults could not be prepared: {error}"),
        ));
    }
    let deployment = match require_current_app_deployment_snapshot(repo_root, runner, &environment)
    {
        Ok(deployment) => {
            findings.push(Finding::new("pass", "runtime.app-deployment-receipt", "Prepared application deployment receipt is valid before the direct native API smoke.".into()).with_path(&receipt_path(repo_root)));
            Some(deployment)
        }
        Err(error) => {
            findings.push(
                Finding::new("fail", "runtime.app-deployment-receipt", error)
                    .with_path(&receipt_path(repo_root)),
            );
            None
        }
    };
    findings.push(direct_config_shape_finding(
        &environment,
        "native-api-direct.config-shape",
    ));
    findings.push(host_binding_finding(&environment));
    let token_source = if environment_value(&environment, BEARER_TOKEN_ENV)
        .is_some_and(|value| !value.is_empty())
    {
        "environment"
    } else {
        "runtime-secret-file"
    };
    let token = direct_token(repo_root, &environment).unwrap_or_default();
    findings.push(
        Finding::new(
            if bearer_token_is_acceptable(&token) {
                "pass"
            } else {
                "fail"
            },
            "native-api-direct.bearer-token-strength",
            if bearer_token_is_acceptable(&token) {
                "Direct native API bearer token satisfies the minimum local strength contract."
                    .into()
            } else {
                "Direct native API bearer token is too short or contains unsafe characters.".into()
            },
        )
        .with_details(json!({"minimum_token_length": 32, "token_source": token_source})),
    );
    let config = run_compose(
        repo_root,
        runner,
        &environment,
        &["config", "--quiet"],
        CONFIG_TIMEOUT,
    );
    findings.push(process_finding(
        config.as_ref(),
        "compose.config",
        "Compose direct native API config validation",
    ));
    if failed(&findings) || deployment.is_none() {
        return finish(
            repo_root,
            status_only,
            runner,
            "Direct native API smoke stopped at prerequisites.",
            findings,
            Some((&environment, token_source)),
            Vec::new(),
        );
    }
    let build = run_compose(
        repo_root,
        runner,
        &environment,
        &["build", "yafvs-api"],
        BUILD_TIMEOUT,
    );
    findings.push(process_finding(
        build.as_ref(),
        "compose.yafvs-api-build",
        "docker compose build yafvs-api",
    ));
    if !process_passed(build.as_ref()) {
        return finish(
            repo_root,
            status_only,
            runner,
            "Direct native API smoke stopped because image build failed.",
            findings,
            Some((&environment, token_source)),
            Vec::new(),
        );
    }
    let deployment = match refresh_deployment(
        repo_root,
        runner,
        &environment,
        deployment.expect("checked"),
        "yafvs-api",
    ) {
        Ok(deployment) => {
            findings.push(Finding::new("pass", "runtime.app-deployment-receipt-refresh", "Prepared application deployment receipt now identifies the direct native API smoke image.".into()).with_path(&receipt_path(repo_root)));
            deployment
        }
        Err(error) => {
            findings.push(
                Finding::new("fail", "runtime.app-deployment-receipt-refresh", error)
                    .with_path(&receipt_path(repo_root)),
            );
            return finish(
                repo_root,
                status_only,
                runner,
                "Direct native API smoke stopped because the deployment receipt could not be refreshed.",
                findings,
                Some((&environment, token_source)),
                Vec::new(),
            );
        }
    };
    let up_command = match pinned_app_compose_command(
        repo_root,
        &environment,
        &deployment.image_ids,
        &native_api_up_arguments(),
    ) {
        Ok(command) => command,
        Err(error) => {
            findings.push(Finding::new("fail", "compose.yafvs-api-direct-up", error));
            return finish(
                repo_root,
                status_only,
                runner,
                "Direct native API smoke stopped because yafvs-api restart failed.",
                findings,
                Some((&environment, token_source)),
                Vec::new(),
            );
        }
    };
    let up = runner.run_with(
        "docker",
        &up_command.iter().map(String::as_str).collect::<Vec<_>>(),
        Some(repo_root),
        Some(&environment),
        Some(START_TIMEOUT),
    );
    findings.push(process_finding(
        up.as_ref(),
        "compose.yafvs-api-direct-up",
        "docker compose direct yafvs-api up",
    ));
    if !process_passed(up.as_ref()) {
        return finish(
            repo_root,
            status_only,
            runner,
            "Direct native API smoke stopped because yafvs-api restart failed.",
            findings,
            Some((&environment, token_source)),
            Vec::new(),
        );
    }
    findings.push(wait_for_health(repo_root, &environment, runner));
    run_auth_and_header_probes(repo_root, &environment, &token, runner, &mut findings);
    run_disabled_write_probes(repo_root, &environment, &token, runner, &mut findings);
    run_request_shape_probes(repo_root, &environment, &token, runner, &mut findings);
    run_scope_report_probes(repo_root, &environment, &token, runner, &mut findings);
    let internal = command_runtime_native_api_smoke_with_runner(repo_root, false, runner);
    findings.push(
        Finding::new(
            &internal.status,
            "native-api.internal-smoke",
            internal.summary.clone(),
        )
        .with_details(json!({"status": internal.status, "artifacts": internal.artifacts})),
    );
    let artifacts = internal.artifacts;
    finish(
        repo_root,
        status_only,
        runner,
        "Direct native API smoke checks completed.",
        findings,
        Some((&environment, token_source)),
        artifacts,
    )
}

fn run_auth_and_header_probes(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    token: &str,
    runner: &dyn CommandRunner,
    findings: &mut Vec<Finding>,
) {
    let missing = probe(
        repo_root,
        environment,
        REPORTS_PATH,
        "GET",
        None,
        None,
        &[],
        true,
        runner,
    );
    let missing_id = header(&missing, "x-request-id");
    let missing_ok = response_is(&missing, 401, Some("unauthorized"));
    findings.push(probe_finding(
        &missing,
        missing_ok,
        "native-api-direct.missing-token",
        "Direct native API rejects missing bearer token with JSON 401.",
    ));
    findings.push(Finding::new(if missing_ok && safe_generated_request_id(&missing_id) { "pass" } else { "fail" }, "native-api-direct.request-id-unauthorized", "Direct native API attaches a generated safe X-Request-Id to missing-token JSON 401 responses.".into()).with_details(json!({"http_status": missing.status, "request_id": missing_id})));
    let wrong = probe(
        repo_root,
        environment,
        REPORTS_PATH,
        "GET",
        Some("wrong-token"),
        None,
        &[],
        false,
        runner,
    );
    findings.push(probe_finding(
        &wrong,
        response_is(&wrong, 401, Some("unauthorized")),
        "native-api-direct.wrong-token",
        "Direct native API rejects wrong bearer token with JSON 401.",
    ));
    let valid = probe(
        repo_root,
        environment,
        REPORTS_PATH,
        "GET",
        Some(token),
        None,
        &[("X-Request-Id", "direct-smoke-1")],
        true,
        runner,
    );
    let valid_ok = response_is(&valid, 200, None)
        && valid
            .body
            .as_ref()
            .and_then(|body| body.get("items"))
            .is_some_and(Value::is_array);
    let valid_id = header(&valid, "x-request-id");
    findings.push(probe_finding(
        &valid,
        valid_ok,
        "native-api-direct.valid-token",
        "Direct native API accepts the configured bearer token and returns JSON.",
    ));
    findings.push(Finding::new(if valid_ok && valid_id == "direct-smoke-1" { "pass" } else { "fail" }, "native-api-direct.request-id-client", "Direct native API echoes a bounded safe client X-Request-Id on valid-token JSON responses.".into()).with_details(json!({"http_status": valid.status, "request_id": valid_id})));
    let cors = [
        "access-control-allow-origin",
        "access-control-allow-credentials",
    ]
    .into_iter()
    .filter_map(|name| valid.headers.get(name).map(|value| (name, value)))
    .collect::<BTreeMap<_, _>>();
    findings.push(
        Finding::new(
            if valid_ok && cors.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "native-api-direct.cors-disabled",
            "Direct native API valid-token responses do not advertise browser CORS access.".into(),
        )
        .with_details(json!({"http_status": valid.status, "present_cors_headers": cors})),
    );
    let observed = EXPECTED_SECURITY_HEADERS
        .iter()
        .map(|(name, _)| (*name, valid.headers.get(*name).cloned().unwrap_or_default()))
        .collect::<BTreeMap<_, _>>();
    let expected = EXPECTED_SECURITY_HEADERS
        .iter()
        .map(|(name, value)| (*name, (*value).to_owned()))
        .collect::<BTreeMap<_, _>>();
    findings.push(Finding::new(if valid_ok && observed == expected { "pass" } else { "fail" }, "native-api-direct.security-headers", "Direct native API valid-token responses include no-store, no-sniff browser safety headers.".into()).with_details(json!({"expected_headers": expected, "observed_headers": observed})));
    let unsafe_id = probe(
        repo_root,
        environment,
        REPORTS_PATH,
        "GET",
        Some(token),
        None,
        &[("X-Request-Id", "../bad")],
        true,
        runner,
    );
    let response_id = header(&unsafe_id, "x-request-id");
    let unsafe_ok = response_is(&unsafe_id, 200, None)
        && safe_generated_request_id(&response_id)
        && response_id != "../bad";
    findings.push(Finding::new(if unsafe_ok { "pass" } else { "fail" }, "native-api-direct.request-id-unsafe-client", "Direct native API replaces unsafe client X-Request-Id values with a generated safe request ID.".into()).with_details(json!({"http_status": unsafe_id.status, "request_id": response_id, "unsafe_request_id": "../bad"})));
    let non_get = probe(
        repo_root,
        environment,
        REPORTS_PATH,
        "POST",
        Some(token),
        None,
        &[],
        false,
        runner,
    );
    findings.push(probe_finding(
        &non_get,
        response_is(&non_get, 405, Some("method_not_allowed")),
        "native-api-direct.read-only-method-guard",
        "Direct native API rejects valid-token non-GET /api/v1 requests with JSON 405.",
    ));
}

fn run_disabled_write_probes(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    token: &str,
    runner: &dyn CommandRunner,
    findings: &mut Vec<Finding>,
) {
    for spec in DISABLED_WRITE_PROBES {
        let headers = if spec.body.is_some() {
            &[("Content-Type", "application/json")][..]
        } else {
            &[][..]
        };
        let response = probe(
            repo_root,
            environment,
            spec.path,
            spec.method,
            Some(token),
            spec.body,
            headers,
            false,
            runner,
        );
        findings.push(probe_finding(
            &response,
            response_is(&response, 405, Some("method_not_allowed")),
            spec.check,
            "Direct native API rejects this write while direct write-control is disabled.",
        ));
    }
}

fn run_request_shape_probes(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    token: &str,
    runner: &dyn CommandRunner,
    findings: &mut Vec<Finding>,
) {
    let cases = [
        (
            "native-api-direct.request-shape-guard",
            REPORTS_PATH,
            Some("probe-body"),
            &[][..],
            413,
            Some("request_too_large"),
        ),
        (
            "native-api-direct.request-shape-transfer-encoding",
            REPORTS_PATH,
            None,
            &[("Transfer-Encoding", "chunked")][..],
            413,
            Some("request_too_large"),
        ),
    ];
    for (check, path, body, headers, status, code) in cases {
        let response = probe(
            repo_root,
            environment,
            path,
            "GET",
            Some(token),
            body,
            headers,
            false,
            runner,
        );
        findings.push(probe_finding(
            &response,
            response_is(&response, status, code),
            check,
            "Direct native API rejects the unsafe request shape.",
        ));
    }
    let malformed = probe(
        repo_root,
        environment,
        REPORTS_PATH,
        "GET",
        Some(token),
        None,
        &[("Content-Length", "not-a-number")],
        false,
        runner,
    );
    let malformed_ok = response_is(&malformed, 413, Some("request_too_large"))
        || (malformed.output.success && malformed.status == Some(400) && malformed.body.is_none());
    findings.push(probe_finding(
        &malformed,
        malformed_ok,
        "native-api-direct.request-shape-malformed-content-length",
        "Direct native API or HTTP parsing rejects malformed Content-Length.",
    ));
    let oversized_path = format!("/api/v1/reports?filter={}", "a".repeat(9000));
    let oversized = probe(
        repo_root,
        environment,
        &oversized_path,
        "GET",
        Some(token),
        None,
        &[],
        false,
        runner,
    );
    findings.push(probe_finding(
        &oversized,
        response_is(&oversized, 413, Some("request_too_large")),
        "native-api-direct.request-shape-oversized-query",
        "Direct native API rejects oversized valid-token query strings using JSON 413.",
    ));
    for (check, path) in [
        (
            "native-api-direct.positive-allowlist",
            "/api/v1/__unclassified_probe__",
        ),
        (
            "native-api-direct.empty-dynamic-segment",
            "/api/v1/reports//results",
        ),
        (
            "native-api-direct.internal-only-scope-report-detail",
            "/api/v1/scopes/scope-id/reports/scope-report-id",
        ),
    ] {
        let response = probe(
            repo_root,
            environment,
            path,
            "GET",
            Some(token),
            None,
            &[],
            false,
            runner,
        );
        findings.push(probe_finding(
            &response,
            response_is(&response, 404, Some("not_found")),
            check,
            "Direct native API denies the unclassified path with JSON 404.",
        ));
    }
}

fn run_scope_report_probes(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    token: &str,
    runner: &dyn CommandRunner,
    findings: &mut Vec<Finding>,
) {
    let list = probe(
        repo_root,
        environment,
        "/api/v1/scope-reports?page_size=1&sort=-creation_time",
        "GET",
        Some(token),
        None,
        &[],
        false,
        runner,
    );
    let selected = list
        .body
        .as_ref()
        .and_then(|body| body.get("items"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object);
    let Some(item) = selected else {
        findings.push(Finding::new(
            "warn",
            "native-api-direct.scope-report-detail",
            "No scope report exists yet, so the direct scope-report detail probe was skipped."
                .into(),
        ));
        findings.push(Finding::new(
            "warn",
            "native-api-direct.scope-report-retention-plan",
            "No scope report exists yet, so the direct retention preview probe was skipped.".into(),
        ));
        return;
    };
    let report_id = item.get("id").and_then(Value::as_str).unwrap_or_default();
    let scope_id = item
        .get("scope")
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let detail_path = format!(
        "/api/v1/scope-reports/{}",
        percent_encode_component(report_id)
    );
    let detail = probe(
        repo_root,
        environment,
        &detail_path,
        "GET",
        Some(token),
        None,
        &[],
        false,
        runner,
    );
    let detail_ok = response_is(&detail, 200, None)
        && detail
            .body
            .as_ref()
            .and_then(|body| body.get("id"))
            .and_then(Value::as_str)
            == Some(report_id)
        && detail
            .body
            .as_ref()
            .and_then(|body| body.get("sources"))
            .is_some_and(Value::is_array);
    findings.push(probe_finding(
        &detail,
        detail_ok,
        "native-api-direct.scope-report-detail",
        "Direct native API reads scope-report detail metadata and evidence sources.",
    ));
    if scope_id.is_empty() || report_id.is_empty() {
        findings.push(Finding::new("warn", "native-api-direct.scope-report-retention-plan", "The selected scope report lacks identifiers, so the direct retention preview probe was skipped.".into()));
        return;
    }
    let retention_path = format!(
        "/api/v1/scopes/{}/reports/{}/retention-plan",
        percent_encode_component(scope_id),
        percent_encode_component(report_id)
    );
    let retention = probe(
        repo_root,
        environment,
        &retention_path,
        "GET",
        Some(token),
        None,
        &[],
        false,
        runner,
    );
    let retention_ok = response_is(&retention, 200, None)
        && retention
            .body
            .as_ref()
            .and_then(|body| body.get("id"))
            .and_then(Value::as_str)
            == Some(report_id)
        && retention
            .body
            .as_ref()
            .and_then(|body| body.pointer("/policy/mode"))
            .and_then(Value::as_str)
            == Some("dry_run_preview")
        && retention
            .body
            .as_ref()
            .and_then(|body| body.pointer("/policy/destructive_actions"))
            .and_then(Value::as_bool)
            == Some(false);
    findings.push(probe_finding(
        &retention,
        retention_ok,
        "native-api-direct.scope-report-retention-plan",
        "Direct native API exposes the non-destructive scope-report retention preview.",
    ));
}

#[allow(clippy::too_many_arguments)]
fn probe(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    path: &str,
    method: &str,
    token: Option<&str>,
    body: Option<&str>,
    headers: &[(&str, &str)],
    include_headers: bool,
    runner: &dyn CommandRunner,
) -> ProbeResponse {
    let output = raw_direct_api_request(
        repo_root,
        environment,
        DirectRawRequest {
            path,
            method,
            request_id: None,
            body,
            token,
            headers,
            include_response_headers: include_headers,
        },
        runner,
    );
    parse_probe_response(output, include_headers)
}

fn parse_probe_response(output: ProcessOutput, include_headers: bool) -> ProbeResponse {
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_RESPONSE_BYTES + 64 * 1024 {
        return ProbeResponse {
            output,
            body: None,
            status: None,
            headers: BTreeMap::new(),
        };
    }
    let (payload, status) = output
        .stdout
        .trim_end()
        .rsplit_once('\n')
        .map_or((output.stdout.as_str(), None), |(payload, status)| {
            (payload, status.trim().parse().ok())
        });
    let (body_text, headers) = if include_headers {
        let normalized = payload.replace("\r\n", "\n");
        normalized.rsplit_once("\n\n").map_or(
            (normalized.clone(), BTreeMap::new()),
            |(header_text, body)| {
                let block = header_text.rsplit("\n\n").next().unwrap_or(header_text);
                let headers = block
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| {
                        (name.trim().to_ascii_lowercase(), value.trim().to_owned())
                    })
                    .collect();
                (body.to_owned(), headers)
            },
        )
    } else {
        (payload.to_owned(), BTreeMap::new())
    };
    let body = serde_json::from_str::<Value>(&body_text)
        .ok()
        .filter(Value::is_object);
    ProbeResponse {
        output,
        body,
        status,
        headers,
    }
}

fn response_is(response: &ProbeResponse, status: i64, error_code: Option<&str>) -> bool {
    response.output.success
        && response.status == Some(status)
        && response.body.as_ref().is_some_and(|body| {
            error_code.is_none_or(|code| {
                body.pointer("/error/code").and_then(Value::as_str) == Some(code)
            })
        })
}

fn header(response: &ProbeResponse, name: &str) -> String {
    response.headers.get(name).cloned().unwrap_or_default()
}
fn safe_generated_request_id(value: &str) -> bool {
    value.starts_with("tv-") && value.len() <= REQUEST_ID_MAX
}

fn probe_finding(response: &ProbeResponse, ok: bool, check: &str, message: &str) -> Finding {
    let mut details = json!({"exit_code": response.output.exit_code, "http_status": response.status, "response_summary": summarize_response(response.body.as_ref())});
    if response.body.is_none() && !response.output.stdout.is_empty() {
        details["stdout_tail"] = json!(bounded_tail(&response.output.stdout));
    }
    if !response.output.stderr.is_empty() {
        details["stderr_tail"] = json!(bounded_tail(&response.output.stderr));
    }
    Finding::new(
        if ok { "pass" } else { "fail" },
        check,
        if ok {
            message.into()
        } else {
            format!("{message} The observed response did not satisfy the contract.")
        },
    )
    .with_details(details)
}

fn summarize_response(value: Option<&Value>) -> Value {
    let Some(object) = value.and_then(Value::as_object) else {
        return json!({"parsed": false});
    };
    let mut summary = Map::from_iter([("parsed".into(), Value::Bool(true))]);
    for key in ["status", "database", "id"] {
        if let Some(value) = object.get(key) {
            summary.insert(key.into(), value.clone());
        }
    }
    if let Some(error) = object.get("error").and_then(Value::as_object) {
        summary.insert(
            "error".into(),
            json!({"code": error.get("code"), "message": error.get("message")}),
        );
    }
    for key in ["items", "sources"] {
        if let Some(items) = object.get(key).and_then(Value::as_array) {
            summary.insert(format!("{key}_count"), items.len().into());
        }
    }
    Value::Object(summary)
}

fn bounded_tail(value: &str) -> String {
    let value = value.trim();
    if value.len() <= 1200 {
        value.into()
    } else {
        format!(
            "{}...<truncated {} chars>",
            &value[..1200],
            value.len() - 1200
        )
    }
}

fn wait_for_health(
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    runner: &dyn CommandRunner,
) -> Finding {
    let mut last = None;
    for attempt in 1..=HEALTH_ATTEMPTS {
        let response = probe(
            repo_root,
            environment,
            "/healthz",
            "GET",
            None,
            None,
            &[],
            false,
            runner,
        );
        let ok = response_is(&response, 200, None)
            && response
                .body
                .as_ref()
                .and_then(|body| body.get("status"))
                .and_then(Value::as_str)
                == Some("ok");
        if ok {
            return probe_finding(&response, true, "native-api-direct.healthz", "Direct native API health endpoint is reachable without bearer auth.").with_details(json!({"http_status": response.status, "attempt": attempt, "max_attempts": HEALTH_ATTEMPTS, "response_summary": summarize_response(response.body.as_ref())}));
        }
        last = Some(response);
        if attempt < HEALTH_ATTEMPTS {
            thread::sleep(HEALTH_DELAY);
        }
    }
    probe_finding(
        &last.expect("health attempted"),
        false,
        "native-api-direct.healthz",
        "Direct native API health endpoint did not become reachable after restart.",
    )
}

fn host_binding_finding(environment: &BTreeMap<OsString, OsString>) -> Finding {
    let host = direct_host(environment);
    let ok = !host_is_wildcard(&host) && host_is_loopback(&host);
    Finding::new(if ok { "pass" } else { "fail" }, "native-api-direct.host-binding", if ok { "Direct native API host binding is explicit and loopback-bounded.".into() } else { "Direct native API host binding must remain loopback-bounded until production hardening exists.".into() }).with_details(json!({"host": host, "host_port": direct_port(environment), "container_bind": environment_value(environment, DIRECT_BIND_ENV)}))
}

fn process_finding(output: Option<&ProcessOutput>, check: &str, label: &str) -> Finding {
    let exit_code = output.and_then(|output| output.exit_code).unwrap_or(1);
    Finding::new(if process_passed(output) { "pass" } else { "fail" }, check, format!("{label} exit code {exit_code}.")).with_details(json!({"exit_code": exit_code, "output_tail": output.map(|output| output_tail(&format!("{}\n{}", output.stdout, output.stderr), 40)).unwrap_or_default()}))
}
fn process_passed(output: Option<&ProcessOutput>) -> bool {
    output.is_some_and(|output| output.success)
}
fn failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}
fn receipt_path(repo_root: &Path) -> String {
    runtime_dir(repo_root)
        .join("state/app-deployment.json")
        .display()
        .to_string()
}

fn finish(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    direct: Option<(&BTreeMap<OsString, OsString>, &str)>,
    extra_artifacts: Vec<String>,
) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/native-api");
    let mut artifacts = vec![artifact_dir.display().to_string()];
    artifacts.extend(extra_artifacts);
    artifacts.sort();
    artifacts.dedup();
    let details = direct.map_or_else(|| json!({}), |(environment, token_source)| json!({"base_url": direct_base_url(environment), "container_bind": environment_value(environment, DIRECT_BIND_ENV), "token_source": token_source, "direct_request_example": "tools/yafvsctl native-api-request --direct --json --path '/api/v1/reports?page_size=1'"}));
    let mut result = make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_artifacts(artifacts)
    .with_details(details);
    let artifact = artifact_dir.join(if result.status == "fail" {
        "native-api-direct-smoke-failed.json"
    } else {
        "native-api-direct-smoke.json"
    });
    if let Err(error) = write_secure_json_artifact(&artifact, &result) {
        result.status = "fail".into();
        result.findings.push(
            Finding::new(
                "fail",
                "native-api-direct.artifact",
                "Direct native API smoke artifact could not be written securely.".into(),
            )
            .with_path(&artifact.display().to_string())
            .with_details(json!({"error": error})),
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
    let important = result
        .findings
        .iter()
        .filter(|finding| {
            finding.status != "pass"
                || finding.check.starts_with("native-api-direct.")
                || finding.check == "native-api.internal-smoke"
        })
        .map(|finding| (finding.check.clone(), Value::String(finding.status.clone())))
        .collect::<Map<_, _>>();
    let details = result.details.take().unwrap_or_else(|| json!({}));
    result.details = Some(
        json!({"base_url": details.get("base_url"), "container_bind": details.get("container_bind"), "token_source": details.get("token_source"), "finding_count": result.findings.len(), "non_pass_count": non_pass.len(), "artifact_count": result.artifacts.len(), "important_checks": important}),
    );
    result.findings = if non_pass.is_empty() {
        vec![Finding::new(
            "pass",
            "runtime-native-api-direct-smoke.status-only",
            "runtime-native-api-direct-smoke passed; no non-pass findings.".into(),
        )]
    } else {
        non_pass
    };
    result
}

fn lock_failure(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
    error: RuntimeLockError,
) -> ResultEnvelope {
    let (summary, message, details) = match error {
        RuntimeLockError::Timeout {
            name,
            operation,
            holder,
        } => (
            "Direct native API smoke stopped while waiting for the feed lifecycle lock.",
            format!(
                "Timed out waiting for runtime lock '{name}'; another operation may still be running."
            ),
            json!({"operation": operation, "holder": holder}),
        ),
        RuntimeLockError::Setup(error) => (
            "Direct native API smoke stopped because the feed lifecycle lock failed closed.",
            format!("Feed lifecycle lock failed closed: {error}"),
            json!({}),
        ),
    };
    let result = make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message).with_details(details),
        ],
    )
    .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()]);
    if status_only {
        status_only_result(result)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn disabled_write_table_is_unique_and_complete() {
        let checks = DISABLED_WRITE_PROBES
            .iter()
            .map(|probe| probe.check)
            .collect::<BTreeSet<_>>();
        assert_eq!(checks.len(), DISABLED_WRITE_PROBES.len());
        assert_eq!(DISABLED_WRITE_PROBES.len(), 34);
        assert!(checks.contains("native-api-direct.scope-write-disabled"));
        assert!(checks.contains("native-api-direct.tag-hard-delete-disabled"));
        for probe in DISABLED_WRITE_PROBES {
            assert!(probe.path.starts_with("/api/v1/"));
            assert_ne!(probe.method, "GET");
        }
    }

    #[test]
    fn response_parser_keeps_last_header_block_and_json_status() {
        let output = ProcessOutput { success: true, exit_code: Some(0), stdout: "HTTP/1.1 200 OK\r\nX-Request-Id: direct-smoke-1\r\nCache-Control: no-store\r\n\r\n{\"items\":[]}\n200".into(), stderr: String::new() };
        let response = parse_probe_response(output, true);
        assert_eq!(response.status, Some(200));
        assert_eq!(header(&response, "x-request-id"), "direct-smoke-1");
        assert!(response.body.unwrap()["items"].is_array());
    }

    #[test]
    fn response_summary_excludes_unapproved_fields() {
        let summary = summarize_response(Some(
            &json!({"id":"safe","secret":"no","items":[{"password":"no"}]}),
        ));
        let encoded = summary.to_string();
        assert!(encoded.contains("safe"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("password"));
    }
}
