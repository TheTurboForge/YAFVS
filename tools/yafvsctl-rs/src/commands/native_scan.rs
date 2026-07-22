// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::direct_api::{
    OPERATOR_UUID_ENV, direct_runtime_environment, environment_value, validate_operator_uuid,
};
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use super::native_runtime::percent_encode_component;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use yafvs_domain::ScannerType;

pub(crate) const IANA_TCP_UDP_PORT_LIST_ID: &str = "4a4717fe-57d2-11e1-9a26-406186ea4fc5";
pub(crate) const FULL_AND_FAST_SCAN_CONFIG_ID: &str = "daba56c8-73ec-11df-a475-002264764cea";
pub(crate) const DEFAULT_SCANNER_ID: &str = "08b69003-5fc2-4037-a479-93b440211c73";
pub(crate) const EMPTY_SCAN_CONFIG_ID: &str = "085569ce-73ed-11df-83c3-002264764cea";
const DIAGNOSTIC_PREREQUISITE_IDS: [&str; 2] = [
    "1.3.6.1.4.1.25623.1.0.14259",
    "1.3.6.1.4.1.25623.1.0.100315",
];
const DEFAULT_ALIVE_TEST: &str = "Scan Config Default";
static OPERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanKind {
    NewSystem,
    Delivery,
    Diagnostic,
}

impl ScanKind {
    fn command(self) -> &'static str {
        match self {
            Self::NewSystem => "native-scan-new-system",
            Self::Delivery => "native-scan-with-delivery",
            Self::Diagnostic => "native-nvt-diagnostic-scan",
        }
    }

    fn defaults_to_dry_run(self) -> bool {
        matches!(self, Self::Delivery | Self::Diagnostic)
    }
}

struct ApiReply {
    output: ProcessOutput,
    parsed: Option<Value>,
    http_status: Option<i64>,
    oversized: bool,
    config: Option<Finding>,
}

trait ScanApi {
    fn call(
        &self,
        root: &Path,
        path: &str,
        method: &str,
        body: Option<&Value>,
        command: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>>;
}

struct GuardedApi;

impl ScanApi for GuardedApi {
    fn call(
        &self,
        root: &Path,
        path: &str,
        method: &str,
        body: Option<&Value>,
        command: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>> {
        let serialized = body
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| {
                vec![Finding::new(
                    "fail",
                    &format!("{command}.request-body"),
                    format!("Native scan request body could not be serialized: {error}"),
                )]
            })?;
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            serialized.as_deref(),
            &format!("{command}.direct-config-shape"),
            &format!("{command}.direct-token-strength"),
            runner,
        )
        .map(reply_from_guarded)
    }
}

fn reply_from_guarded(call: GuardedDirectApiCall) -> ApiReply {
    ApiReply {
        output: call.output,
        parsed: call.parsed,
        http_status: call.http_status,
        oversized: call.oversized,
        config: Some(call.config),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn command_native_scan_new_system(
    root: &Path,
    host: &str,
    port_list_id: &str,
    scan_config_id: &str,
    scanner_id: &str,
    allow_scan_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_scan(
        root,
        ScanKind::NewSystem,
        Some(host),
        None,
        None,
        port_list_id,
        scan_config_id,
        scanner_id,
        allow_scan_control,
        dry_run,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
        &operation_key(),
        "",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn command_native_nvt_diagnostic_scan(
    root: &Path,
    host: &str,
    nvt_id: &str,
    source_scan_config_id: &str,
    port_list_id: &str,
    scanner_id: &str,
    allow_scan_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_diagnostic_scan(
        root,
        host,
        nvt_id,
        source_scan_config_id,
        port_list_id,
        scanner_id,
        allow_scan_control,
        dry_run,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn command_native_scan_with_delivery(
    root: &Path,
    host: Option<&str>,
    target_id: Option<&str>,
    alert_id: &str,
    port_list_id: &str,
    scan_config_id: &str,
    scanner_id: &str,
    allow_scan_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_scan(
        root,
        ScanKind::Delivery,
        host,
        target_id,
        Some(alert_id),
        port_list_id,
        scan_config_id,
        scanner_id,
        allow_scan_control,
        dry_run,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
        &operation_key(),
        "",
    )
}

fn runtime_operator_uuid(root: &Path, runner: &dyn CommandRunner) -> Result<String, String> {
    let environment = direct_runtime_environment(root, runner)
        .map_err(|_| "direct native API runtime configuration could not be loaded".to_string())?;
    let value = environment_value(&environment, OPERATOR_UUID_ENV)
        .unwrap_or_default()
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(
            "The direct API operator UUID is required for deterministic ownership and cleanup decisions."
                .into(),
        );
    }
    validate_operator_uuid(&value, OPERATOR_UUID_ENV)
}

fn operation_key() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = OPERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:032x}-{:08x}-{sequence:016x}", std::process::id())
}

#[allow(clippy::too_many_arguments)]
fn command_scan(
    root: &Path,
    kind: ScanKind,
    host: Option<&str>,
    target_id: Option<&str>,
    alert_id: Option<&str>,
    port_list_id: &str,
    scan_config_id: &str,
    scanner_id: &str,
    allow_scan_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    operation_key: &str,
    operator_uuid: &str,
) -> ResultEnvelope {
    let command = kind.command();
    let effective_dry_run = dry_run || (kind.defaults_to_dry_run() && !allow_scan_control);
    let mut details = json!({
        "dry_run": effective_dry_run,
        "target_id": null,
        "target_name": null,
        "task_name": null,
        "task_id": null,
        "report_id": null,
        "cleanup": {"attempted": false},
    });
    let validated = match validate_arguments(
        host,
        target_id,
        alert_id,
        port_list_id,
        scan_config_id,
        scanner_id,
    ) {
        Ok(arguments) => arguments,
        Err(error) => {
            return finish(
                root,
                runner,
                kind,
                "Native scan request rejected before runtime access.",
                vec![Finding::new("fail", &format!("{command}.arguments"), error)],
                details,
                status_only,
            );
        }
    };
    let target_body = validated
        .host
        .as_ref()
        .map(|host| target_body(host, &validated.port_list_id, operation_key));
    let task_subject = validated
        .host
        .as_deref()
        .or(validated.target_id.as_deref())
        .expect("exactly one target source was validated");
    let planned_task = task_body(
        task_subject,
        validated
            .target_id
            .as_deref()
            .unwrap_or("<created-target-id>"),
        &validated.scan_config_id,
        &validated.scanner_id,
        operation_key,
        validated.alert_id.as_deref(),
    );
    details["host"] = validated.host.clone().map_or(Value::Null, Value::from);
    details["port_list_id"] = validated
        .host
        .as_ref()
        .map(|_| Value::String(validated.port_list_id.clone()))
        .unwrap_or(Value::Null);
    details["scan_config_id"] = Value::String(validated.scan_config_id.clone());
    details["scanner_id"] = Value::String(validated.scanner_id.clone());
    details["alert_id"] = validated.alert_id.clone().map_or(Value::Null, Value::from);
    details["target_id"] = validated.target_id.clone().map_or(Value::Null, Value::from);
    details["target_name"] = target_body
        .as_ref()
        .and_then(|body| body.get("name"))
        .cloned()
        .unwrap_or(Value::Null);
    details["task_name"] = planned_task["name"].clone();
    details["planned_task"] = planned_task.clone();
    if let Some(body) = &target_body {
        details["planned_target"] = body.clone();
    }

    if effective_dry_run {
        details["status"] = Value::String("dry_run".into());
        details["operation_status"] = Value::String("dry_run".into());
        return finish(
            root,
            runner,
            kind,
            "Native scan request dry run completed without runtime access.",
            vec![Finding::new(
                "pass",
                &format!("{command}.dry-run"),
                "Native scan request bodies were planned without runtime access.".into(),
            )],
            details,
            status_only,
        );
    }
    if !allow_scan_control {
        return finish(
            root,
            runner,
            kind,
            "Native scan request rejected before runtime access.",
            vec![Finding::new(
                "fail",
                &format!("{command}.scan-control-intent"),
                "Creating and starting a scan requires --allow-scan-control.".into(),
            )],
            details,
            status_only,
        );
    }

    let operator_uuid = if operator_uuid.trim().is_empty() {
        runtime_operator_uuid(root, runner).unwrap_or_default()
    } else {
        validate_operator_uuid(operator_uuid.trim(), OPERATOR_UUID_ENV)
            .unwrap_or_else(|_| operator_uuid.trim().to_string())
    };
    let mut findings = Vec::new();
    let mut config_recorded = false;
    let preflight = preflight(
        root,
        runner,
        api,
        command,
        &validated,
        &operator_uuid,
        &mut findings,
        &mut config_recorded,
    );
    if !preflight {
        let direct_rejected = findings.iter().any(|finding| {
            finding.check.ends_with(".direct-config-shape")
                || finding.check.ends_with(".direct-token-strength")
        });
        return finish(
            root,
            runner,
            kind,
            if direct_rejected {
                "Direct native API scan request rejected before runtime access."
            } else {
                "Native scan request rejected during reference preflight; no writes were attempted."
            },
            findings,
            details,
            status_only,
        );
    }

    let mut target_id = validated.target_id.clone();
    let mut target_created_by_command = false;
    if let Some(body) = target_body.as_ref() {
        let reply = match api_call(
            root,
            runner,
            api,
            command,
            "/api/v1/targets",
            "POST",
            Some(body),
            &mut findings,
            &mut config_recorded,
        ) {
            Some(reply) => reply,
            None => {
                set_operation_status(&mut details, "target_create_outcome_unconfirmed");
                return finish(
                    root,
                    runner,
                    kind,
                    "Native target creation outcome is unconfirmed; deterministic names were retained for reconciliation.",
                    findings,
                    details,
                    status_only,
                );
            }
        };
        let expected_name = body["name"].as_str().unwrap_or_default();
        let mut created_id = accepted_created_id(&reply, expected_name);
        let ambiguous = created_id.is_none() && ambiguous_create(&reply);
        findings.push(probe_finding(
            if created_id.is_some() {
                "pass"
            } else if ambiguous {
                "warn"
            } else {
                "fail"
            },
            &format!("{command}.target-create"),
            if created_id.is_some() {
                "Native API created the scan target."
            } else if ambiguous {
                "Native API target create response was ambiguous; deterministic reconciliation is required."
            } else {
                "Native API target creation was rejected."
            },
            &reply,
            json!({"target_id":created_id}),
        ));
        if ambiguous {
            let expected = json!({
                "host": validated.host,
                "port_list_id": validated.port_list_id,
            });
            if let Some(reconciled) = reconcile_named(
                root,
                runner,
                api,
                command,
                "targets",
                expected_name,
                &operator_uuid,
                &expected,
                &mut findings,
                &mut config_recorded,
            ) {
                created_id = reconciled
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(valid_uuid);
            }
        }
        let Some(created_id) = created_id else {
            set_operation_status(
                &mut details,
                if ambiguous {
                    "target_create_outcome_unconfirmed"
                } else {
                    "target_create_failed"
                },
            );
            return finish(
                root,
                runner,
                kind,
                if ambiguous {
                    "Native target creation outcome is unconfirmed; deterministic names were retained for reconciliation."
                } else {
                    "Native scan request failed while creating the target."
                },
                findings,
                details,
                status_only,
            );
        };
        target_id = Some(created_id.clone());
        target_created_by_command = !ambiguous;
        details["target_id"] = Value::String(created_id);
    }

    let target_id = target_id.expect("validated or created target id");
    let task = task_body(
        task_subject,
        &target_id,
        &validated.scan_config_id,
        &validated.scanner_id,
        operation_key,
        validated.alert_id.as_deref(),
    );
    let task_reply = match api_call(
        root,
        runner,
        api,
        command,
        "/api/v1/tasks",
        "POST",
        Some(&task),
        &mut findings,
        &mut config_recorded,
    ) {
        Some(reply) => reply,
        None => {
            set_operation_status(&mut details, "task_create_outcome_unconfirmed");
            return finish(
                root,
                runner,
                kind,
                "Native task creation outcome is unconfirmed; target and deterministic names were retained for reconciliation.",
                findings,
                details,
                status_only,
            );
        }
    };
    let expected_task_name = task["name"].as_str().unwrap_or_default();
    let mut task_id = accepted_created_id(&task_reply, expected_task_name);
    let task_ambiguous = task_id.is_none() && ambiguous_create(&task_reply);
    findings.push(probe_finding(
        if task_id.is_some() {
            "pass"
        } else if task_ambiguous {
            "warn"
        } else {
            "fail"
        },
        &format!("{command}.task-create"),
        if task_id.is_some() {
            "Native API created the scan task."
        } else if task_ambiguous {
            "Native API task create response was ambiguous; deterministic reconciliation is required."
        } else {
            "Native API task creation was rejected."
        },
        &task_reply,
        json!({"task_id":task_id}),
    ));
    if task_ambiguous {
        let expected = json!({
            "target_id": target_id,
            "config_id": validated.scan_config_id,
            "scanner_id": validated.scanner_id,
        });
        if let Some(reconciled) = reconcile_named(
            root,
            runner,
            api,
            command,
            "tasks",
            expected_task_name,
            &operator_uuid,
            &expected,
            &mut findings,
            &mut config_recorded,
        ) {
            task_id = reconciled
                .get("id")
                .and_then(Value::as_str)
                .and_then(valid_uuid);
        }
    }
    let Some(task_id) = task_id else {
        if target_created_by_command && !task_ambiguous {
            let cleanup = cleanup_target(
                root,
                runner,
                api,
                command,
                &target_id,
                &mut findings,
                &mut config_recorded,
            );
            details["cleanup"] = cleanup;
        }
        set_operation_status(
            &mut details,
            if task_ambiguous {
                "task_create_outcome_unconfirmed"
            } else {
                "task_create_failed"
            },
        );
        return finish(
            root,
            runner,
            kind,
            if task_ambiguous {
                "Native task creation outcome is unconfirmed; target and deterministic names were retained for reconciliation."
            } else {
                "Native scan request failed while creating the task; created-target cleanup was attempted when applicable."
            },
            findings,
            details,
            status_only,
        );
    };
    details["task_id"] = Value::String(task_id.clone());

    if let Some(alert_id) = validated.alert_id.as_deref() {
        let path = format!("/api/v1/alerts/{}", percent_encode_component(alert_id));
        let Some(reply) = api_call(
            root,
            runner,
            api,
            command,
            &path,
            "GET",
            None,
            &mut findings,
            &mut config_recorded,
        ) else {
            set_operation_status(&mut details, "prepared_not_started");
            return finish(
                root,
                runner,
                kind,
                "Native scan was prepared but not started because delivery eligibility could not be re-proven.",
                findings,
                details,
                status_only,
            );
        };
        let eligible = reply_ok(&reply, 200)
            && alert_eligible(
                reply.parsed.as_ref(),
                alert_id,
                &operator_uuid,
                Some(&task_id),
            );
        findings.push(probe_finding(
            if eligible { "pass" } else { "fail" },
            &format!("{command}.pre-start-alert"),
            if eligible {
                "Alert remains active, operator-owned, delivery-capable, and attached to the prepared task."
            } else {
                "Alert eligibility or task attachment changed after task creation; the prepared task and target were retained without starting."
            },
            &reply,
            json!({"alert_id":alert_id,"task_id":task_id}),
        ));
        if !eligible {
            set_operation_status(&mut details, "prepared_not_started");
            return finish(
                root,
                runner,
                kind,
                "Native scan was prepared but not started because delivery eligibility could not be re-proven.",
                findings,
                details,
                status_only,
            );
        }
    }

    let start_path = format!("/api/v1/tasks/{}/start", percent_encode_component(&task_id));
    let Some(start_reply) = api_call(
        root,
        runner,
        api,
        command,
        &start_path,
        "POST",
        None,
        &mut findings,
        &mut config_recorded,
    ) else {
        set_operation_status(&mut details, "start_outcome_unconfirmed");
        return finish(
            root,
            runner,
            kind,
            "Native scan start outcome is unconfirmed; task and target were retained.",
            findings,
            details,
            status_only,
        );
    };
    let object = start_reply.parsed.as_ref().and_then(Value::as_object);
    let report_id = object
        .and_then(|object| object.get("report_id"))
        .and_then(Value::as_str)
        .and_then(valid_uuid);
    let started = reply_ok(&start_reply, 202)
        && object
            .and_then(|object| object.get("task_id"))
            .and_then(Value::as_str)
            == Some(task_id.as_str())
        && object
            .and_then(|object| object.get("status"))
            .and_then(Value::as_str)
            == Some("requested")
        && report_id.is_some();
    findings.push(probe_finding(
        if started { "pass" } else { "fail" },
        &format!("{command}.task-start"),
        if started {
            "Native API accepted the scan request."
        } else {
            "Native API task start failed or returned an invalid acknowledgement; the prepared task and target were retained."
        },
        &start_reply,
        json!({"task_id":task_id,"report_id":report_id}),
    ));
    if started {
        details["report_id"] = report_id.map_or(Value::Null, Value::from);
        set_operation_status(&mut details, "requested");
        return finish(
            root,
            runner,
            kind,
            "Native scan request accepted.",
            findings,
            details,
            status_only,
        );
    }

    let follow_up_path = format!("/api/v1/tasks/{}", percent_encode_component(&task_id));
    let follow_up = api_call(
        root,
        runner,
        api,
        command,
        &follow_up_path,
        "GET",
        None,
        &mut findings,
        &mut config_recorded,
    );
    let object = follow_up
        .as_ref()
        .and_then(|reply| reply.parsed.as_ref())
        .and_then(Value::as_object);
    let observed_status = object
        .and_then(|object| object.get("status"))
        .and_then(Value::as_str);
    let current_report = object.and_then(|object| object.get("current_report"));
    let observed_report_id = current_report
        .and_then(Value::as_object)
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .and_then(valid_uuid);
    let confirmed_not_started = follow_up.as_ref().is_some_and(|reply| reply_ok(reply, 200))
        && object
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            == Some(task_id.as_str())
        && observed_status == Some("New")
        && current_report == Some(&Value::Null);
    let outcome = if confirmed_not_started {
        "prepared_not_started"
    } else {
        "start_outcome_unconfirmed"
    };
    if let Some(reply) = follow_up.as_ref() {
        findings.push(probe_finding(
            if confirmed_not_started { "pass" } else { "warn" },
            &format!("{command}.start-follow-up"),
            if confirmed_not_started {
                "Task detail confirms New status with no current report after the non-accepted start response."
            } else {
                "Task start outcome could not be proven inactive after the non-accepted start response; task and target were retained."
            },
            reply,
            json!({
                "task_id":task_id,
                "observed_task_status":observed_status,
                "observed_report_id":observed_report_id,
            }),
        ));
        details["start_follow_up_http_status"] = reply.http_status.map_or(Value::Null, Value::from);
    } else {
        details["start_follow_up_http_status"] = Value::Null;
    }
    details["observed_task_status"] = observed_status.map_or(Value::Null, Value::from);
    details["observed_report_id"] = observed_report_id.clone().map_or(Value::Null, Value::from);
    details["report_id"] = observed_report_id.map_or(Value::Null, Value::from);
    set_operation_status(&mut details, outcome);
    finish(
        root,
        runner,
        kind,
        if confirmed_not_started {
            "Native scan task was prepared but not started; task and target were retained."
        } else {
            "Native scan start outcome is unconfirmed; task and target were retained."
        },
        findings,
        details,
        status_only,
    )
}

struct DiagnosticArguments {
    host: String,
    nvt_id: String,
    source_scan_config_id: String,
    port_list_id: String,
    scanner_id: String,
}

#[allow(clippy::too_many_arguments)]
fn command_diagnostic_scan(
    root: &Path,
    host: &str,
    nvt_id: &str,
    source_scan_config_id: &str,
    port_list_id: &str,
    scanner_id: &str,
    allow_scan_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    operator_override: Option<&str>,
) -> ResultEnvelope {
    let kind = ScanKind::Diagnostic;
    let command = kind.command();
    let mut details = json!({
        "host": null,
        "nvt_id": null,
        "source_scan_config_id": null,
        "scan_config_id": null,
        "scan_config_name": null,
        "port_list_id": null,
        "scanner_id": null,
        "target_id": null,
        "target_name": null,
        "task_id": null,
        "task_name": null,
        "report_id": null,
        "cleanup": {"attempted": false},
    });
    let arguments = match validate_diagnostic_arguments(
        host,
        nvt_id,
        source_scan_config_id,
        port_list_id,
        scanner_id,
    ) {
        Ok(arguments) => arguments,
        Err(error) => {
            return finish(
                root,
                runner,
                kind,
                "Native diagnostic NVT scan rejected before runtime access.",
                vec![Finding::new("fail", &format!("{command}.arguments"), error)],
                details,
                status_only,
            );
        }
    };
    let operation_key = diagnostic_operation_key(&arguments);
    let config_name = format!("YAFVS diagnostic NVT {operation_key}");
    let target_name = format!("YAFVS diagnostic target {operation_key}");
    let task_name = format!("YAFVS diagnostic task {operation_key}");
    details["host"] = Value::String(arguments.host.clone());
    details["nvt_id"] = Value::String(arguments.nvt_id.clone());
    details["source_scan_config_id"] = Value::String(arguments.source_scan_config_id.clone());
    details["port_list_id"] = Value::String(arguments.port_list_id.clone());
    details["scanner_id"] = Value::String(arguments.scanner_id.clone());
    details["operation_key"] = Value::String(operation_key.clone());
    details["scan_config_name"] = Value::String(config_name.clone());
    details["target_name"] = Value::String(target_name.clone());
    details["task_name"] = Value::String(task_name.clone());
    details["planned_selection"] = json!({
        "nvt_id": arguments.nvt_id,
        "prerequisite_nvt_ids": DIAGNOSTIC_PREREQUISITE_IDS,
    });
    details["planned_target"] = json!({
        "name": target_name,
        "hosts": [arguments.host],
        "port_list_id": arguments.port_list_id,
    });
    details["planned_task"] = json!({
        "name": task_name,
        "target_id": "<created-target-id>",
        "config_id": "<created-scan-config-id>",
        "scanner_id": arguments.scanner_id,
    });

    let effective_dry_run = dry_run || !allow_scan_control;
    details["dry_run"] = Value::Bool(effective_dry_run);
    if effective_dry_run {
        set_operation_status(&mut details, "dry_run");
        return finish(
            root,
            runner,
            kind,
            "Native diagnostic NVT scan dry run completed without runtime access.",
            vec![Finding::new(
                "pass",
                &format!("{command}.dry-run"),
                "Diagnostic NVT selection, target, task, and start were planned without runtime access."
                    .into(),
            )],
            details,
            status_only,
        );
    }

    let operator_uuid = operator_override
        .map(|value| validate_operator_uuid(value, OPERATOR_UUID_ENV))
        .unwrap_or_else(|| runtime_operator_uuid(root, runner));
    let operator_uuid = match operator_uuid {
        Ok(operator_uuid) => operator_uuid,
        Err(error) => {
            set_operation_status(&mut details, "operator_identity_missing");
            return finish(
                root,
                runner,
                kind,
                "Native diagnostic NVT scan rejected without operator identity.",
                vec![Finding::new(
                    "fail",
                    &format!("{command}.operator-identity"),
                    error,
                )],
                details,
                status_only,
            );
        }
    };
    let mut findings = Vec::new();
    let mut config_recorded = false;
    if !diagnostic_preflight(
        root,
        runner,
        api,
        &arguments,
        &operator_uuid,
        &mut findings,
        &mut config_recorded,
    ) {
        set_operation_status(&mut details, "preflight_failed");
        return finish(
            root,
            runner,
            kind,
            "Native diagnostic NVT scan rejected during reference preflight; no writes were attempted.",
            findings,
            details,
            status_only,
        );
    }

    let clone_path = format!(
        "/api/v1/scan-configs/{}/clone",
        percent_encode_component(&arguments.source_scan_config_id)
    );
    let clone_body = json!({"name":config_name,"comment":"YAFVS native diagnostic NVT scan"});
    let Some(clone_reply) = api_call(
        root,
        runner,
        api,
        command,
        &clone_path,
        "POST",
        Some(&clone_body),
        &mut findings,
        &mut config_recorded,
    ) else {
        set_operation_status(&mut details, "scan_config_clone_outcome_unconfirmed");
        return finish(
            root,
            runner,
            kind,
            "Native diagnostic scan-config clone outcome is unconfirmed; deterministic state was retained.",
            findings,
            details,
            status_only,
        );
    };
    let mut config_id = accepted_created_id(&clone_reply, &config_name);
    let config_created_by_command = config_id.is_some();
    let mut config_ambiguous = config_id.is_none() && ambiguous_create(&clone_reply);
    if config_id.is_none()
        && (config_ambiguous || clone_reply.http_status == Some(409))
        && let Some(reconciled) = reconcile_diagnostic_config(
            root,
            runner,
            api,
            &config_name,
            &operator_uuid,
            &mut findings,
            &mut config_recorded,
        )
    {
        config_id = Some(reconciled);
        config_ambiguous = false;
        details["config_reconciled"] = Value::Bool(true);
    }
    findings.push(probe_finding(
        if config_id.is_some() {
            "pass"
        } else if config_ambiguous {
            "warn"
        } else {
            "fail"
        },
        &format!("{command}.scan-config-clone"),
        if config_created_by_command {
            "Native API cloned the deterministic diagnostic scan config."
        } else if config_id.is_some() {
            "Native API reconciled the existing deterministic diagnostic scan config."
        } else if config_ambiguous {
            "Scan-config clone outcome is unconfirmed; deterministic config identity was retained."
        } else {
            "Native API scan-config clone failed."
        },
        &clone_reply,
        json!({"scan_config_id":config_id,"name":config_name}),
    ));
    let Some(config_id) = config_id else {
        set_operation_status(
            &mut details,
            if config_ambiguous {
                "scan_config_clone_outcome_unconfirmed"
            } else {
                "scan_config_clone_failed"
            },
        );
        return finish(
            root,
            runner,
            kind,
            if config_ambiguous {
                "Native diagnostic scan-config clone outcome is unconfirmed; deterministic state was retained."
            } else {
                "Native diagnostic scan-config clone failed."
            },
            findings,
            details,
            status_only,
        );
    };
    details["scan_config_id"] = Value::String(config_id.clone());

    let selection_path = format!(
        "/api/v1/scan-configs/{}/diagnostic-nvt-selection",
        percent_encode_component(&config_id)
    );
    let selection_body = json!({"nvt_id":arguments.nvt_id});
    let Some(selection_reply) = api_call(
        root,
        runner,
        api,
        command,
        &selection_path,
        "POST",
        Some(&selection_body),
        &mut findings,
        &mut config_recorded,
    ) else {
        set_operation_status(&mut details, "selection_outcome_unconfirmed");
        return finish(
            root,
            runner,
            kind,
            "Diagnostic NVT selection outcome is unconfirmed; the scan config was retained.",
            findings,
            details,
            status_only,
        );
    };
    let selection_ok =
        diagnostic_selection_accepted(&selection_reply, &config_id, &arguments.nvt_id);
    let selection_ambiguous = !selection_ok && ambiguous_create(&selection_reply);
    findings.push(probe_finding(
        if selection_ok {
            "pass"
        } else if selection_ambiguous {
            "warn"
        } else {
            "fail"
        },
        &format!("{command}.selection"),
        if selection_ok {
            "Native API selected the requested NVT and fixed Port scanners."
        } else if selection_ambiguous {
            "Diagnostic NVT selection outcome is unconfirmed; created config was retained."
        } else {
            "Native API diagnostic NVT selection failed."
        },
        &selection_reply,
        json!({
            "scan_config_id":config_id,
            "nvt_id":arguments.nvt_id,
            "prerequisite_nvt_ids":DIAGNOSTIC_PREREQUISITE_IDS,
        }),
    ));
    if !selection_ok {
        if config_created_by_command && !selection_ambiguous {
            details["cleanup"]["scan_config"] = cleanup_scan_config(
                root,
                runner,
                api,
                &config_id,
                &mut findings,
                &mut config_recorded,
            );
        }
        set_operation_status(
            &mut details,
            if selection_ambiguous {
                "selection_outcome_unconfirmed"
            } else {
                "selection_failed"
            },
        );
        return finish(
            root,
            runner,
            kind,
            if selection_ambiguous {
                "Diagnostic NVT selection outcome is unconfirmed; the scan config was retained."
            } else {
                "Diagnostic NVT selection failed; proven helper-created config cleanup was attempted."
            },
            findings,
            details,
            status_only,
        );
    }

    let mut diagnostic_target_body =
        target_body(&arguments.host, &arguments.port_list_id, &operation_key);
    diagnostic_target_body["name"] = Value::String(target_name.clone());
    diagnostic_target_body["comment"] = Value::String("YAFVS native diagnostic NVT target".into());
    let Some(target_reply) = api_call(
        root,
        runner,
        api,
        command,
        "/api/v1/targets",
        "POST",
        Some(&diagnostic_target_body),
        &mut findings,
        &mut config_recorded,
    ) else {
        set_operation_status(&mut details, "target_create_outcome_unconfirmed");
        return finish(
            root,
            runner,
            kind,
            "Diagnostic target creation outcome is unconfirmed; deterministic state was retained.",
            findings,
            details,
            status_only,
        );
    };
    let mut target_id = accepted_created_id(&target_reply, &target_name);
    let target_created_by_command = target_id.is_some();
    let target_ambiguous = target_id.is_none() && ambiguous_create(&target_reply);
    if target_ambiguous
        && let Some(reconciled) = reconcile_named(
            root,
            runner,
            api,
            command,
            "targets",
            &target_name,
            &operator_uuid,
            &json!({"host":arguments.host,"port_list_id":arguments.port_list_id}),
            &mut findings,
            &mut config_recorded,
        )
    {
        target_id = reconciled
            .get("id")
            .and_then(Value::as_str)
            .and_then(valid_uuid);
    }
    findings.push(probe_finding(
        if target_id.is_some() {
            "pass"
        } else if target_ambiguous {
            "warn"
        } else {
            "fail"
        },
        &format!("{command}.target-create"),
        if target_created_by_command {
            "Native API created the deterministic diagnostic target."
        } else if target_id.is_some() {
            "Native API reconciled the deterministic diagnostic target."
        } else if target_ambiguous {
            "Target creation outcome is unconfirmed; deterministic target identity was retained."
        } else {
            "Native API diagnostic target creation failed."
        },
        &target_reply,
        json!({"target_id":target_id,"target_name":target_name}),
    ));
    let Some(target_id) = target_id else {
        if !target_ambiguous && config_created_by_command {
            details["cleanup"]["scan_config"] = cleanup_scan_config(
                root,
                runner,
                api,
                &config_id,
                &mut findings,
                &mut config_recorded,
            );
        }
        set_operation_status(
            &mut details,
            if target_ambiguous {
                "target_create_outcome_unconfirmed"
            } else {
                "target_create_failed"
            },
        );
        return finish(
            root,
            runner,
            kind,
            if target_ambiguous {
                "Diagnostic target creation outcome is unconfirmed; deterministic state was retained."
            } else {
                "Diagnostic target creation failed; proven helper-created config cleanup was attempted."
            },
            findings,
            details,
            status_only,
        );
    };
    details["target_id"] = Value::String(target_id.clone());

    let diagnostic_task_body = json!({
        "name":task_name,
        "target_id":target_id,
        "config_id":config_id,
        "scanner_id":arguments.scanner_id,
    });
    let Some(task_reply) = api_call(
        root,
        runner,
        api,
        command,
        "/api/v1/tasks",
        "POST",
        Some(&diagnostic_task_body),
        &mut findings,
        &mut config_recorded,
    ) else {
        set_operation_status(&mut details, "task_create_outcome_unconfirmed");
        return finish(
            root,
            runner,
            kind,
            "Diagnostic task creation outcome is unconfirmed; deterministic config and target state were retained.",
            findings,
            details,
            status_only,
        );
    };
    let mut task_id = accepted_created_id(&task_reply, &task_name);
    let task_created_by_command = task_id.is_some();
    let task_ambiguous = task_id.is_none() && ambiguous_create(&task_reply);
    if task_ambiguous
        && let Some(reconciled) = reconcile_named(
            root,
            runner,
            api,
            command,
            "tasks",
            &task_name,
            &operator_uuid,
            &json!({
                "target_id":target_id,
                "config_id":config_id,
                "scanner_id":arguments.scanner_id,
            }),
            &mut findings,
            &mut config_recorded,
        )
    {
        task_id = reconciled
            .get("id")
            .and_then(Value::as_str)
            .and_then(valid_uuid);
    }
    findings.push(probe_finding(
        if task_id.is_some() {
            "pass"
        } else if task_ambiguous {
            "warn"
        } else {
            "fail"
        },
        &format!("{command}.task-create"),
        if task_created_by_command {
            "Native API created the deterministic diagnostic task."
        } else if task_id.is_some() {
            "Native API reconciled the deterministic diagnostic task."
        } else if task_ambiguous {
            "Task creation outcome is unconfirmed; config and target were retained."
        } else {
            "Native API diagnostic task creation failed."
        },
        &task_reply,
        json!({"task_id":task_id,"task_name":task_name}),
    ));
    let Some(task_id) = task_id else {
        if !task_ambiguous {
            if target_created_by_command {
                details["cleanup"]["target"] = cleanup_target(
                    root,
                    runner,
                    api,
                    command,
                    &target_id,
                    &mut findings,
                    &mut config_recorded,
                );
            }
            if config_created_by_command {
                details["cleanup"]["scan_config"] = cleanup_scan_config(
                    root,
                    runner,
                    api,
                    &config_id,
                    &mut findings,
                    &mut config_recorded,
                );
            }
        }
        set_operation_status(
            &mut details,
            if task_ambiguous {
                "task_create_outcome_unconfirmed"
            } else {
                "task_create_failed"
            },
        );
        return finish(
            root,
            runner,
            kind,
            if task_ambiguous {
                "Diagnostic task creation outcome is unconfirmed; deterministic config and target state were retained."
            } else {
                "Diagnostic task creation failed; proven helper-created resource cleanup was attempted."
            },
            findings,
            details,
            status_only,
        );
    };
    details["task_id"] = Value::String(task_id.clone());

    let start_path = format!("/api/v1/tasks/{}/start", percent_encode_component(&task_id));
    let Some(start_reply) = api_call(
        root,
        runner,
        api,
        command,
        &start_path,
        "POST",
        None,
        &mut findings,
        &mut config_recorded,
    ) else {
        set_operation_status(&mut details, "start_outcome_unconfirmed");
        return finish(
            root,
            runner,
            kind,
            "Diagnostic task start outcome is unconfirmed; deterministic config, target, and task state were retained.",
            findings,
            details,
            status_only,
        );
    };
    let object = start_reply.parsed.as_ref().and_then(Value::as_object);
    let report_id = object
        .and_then(|object| object.get("report_id"))
        .and_then(Value::as_str)
        .and_then(valid_uuid);
    let started = reply_ok(&start_reply, 202)
        && object
            .and_then(|object| object.get("task_id"))
            .and_then(Value::as_str)
            == Some(task_id.as_str())
        && object
            .and_then(|object| object.get("status"))
            .and_then(Value::as_str)
            == Some("requested")
        && report_id.is_some();
    findings.push(probe_finding(
        if started { "pass" } else { "fail" },
        &format!("{command}.start"),
        if started {
            "Native API accepted diagnostic task start."
        } else {
            "Diagnostic task start failed or returned an invalid acknowledgement; resources were retained."
        },
        &start_reply,
        json!({"task_id":task_id,"report_id":report_id}),
    ));
    if started {
        details["report_id"] = report_id.map_or(Value::Null, Value::from);
        set_operation_status(&mut details, "requested");
        return finish(
            root,
            runner,
            kind,
            "Native diagnostic NVT scan start accepted.",
            findings,
            details,
            status_only,
        );
    }

    let follow_up_path = format!("/api/v1/tasks/{}", percent_encode_component(&task_id));
    let follow_up = api_call(
        root,
        runner,
        api,
        command,
        &follow_up_path,
        "GET",
        None,
        &mut findings,
        &mut config_recorded,
    );
    let object = follow_up
        .as_ref()
        .and_then(|reply| reply.parsed.as_ref())
        .and_then(Value::as_object);
    let observed_status = object
        .and_then(|object| object.get("status"))
        .and_then(Value::as_str);
    let current_report = object.and_then(|object| object.get("current_report"));
    let observed_report_id = current_report
        .and_then(Value::as_object)
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        .and_then(valid_uuid);
    let confirmed_not_started = follow_up.as_ref().is_some_and(|reply| reply_ok(reply, 200))
        && object
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            == Some(task_id.as_str())
        && observed_status == Some("New")
        && current_report == Some(&Value::Null);
    if let Some(reply) = follow_up.as_ref() {
        findings.push(probe_finding(
            if confirmed_not_started { "pass" } else { "warn" },
            &format!("{command}.start-follow-up"),
            if confirmed_not_started {
                "Task detail confirms New status with no current report after the non-accepted start response."
            } else {
                "Task start outcome could not be proven inactive after the non-accepted start response; task and target were retained."
            },
            reply,
            json!({
                "task_id":task_id,
                "observed_task_status":observed_status,
                "observed_report_id":observed_report_id,
            }),
        ));
    }
    details["observed_task_status"] = observed_status.map_or(Value::Null, Value::from);
    details["observed_report_id"] = observed_report_id.clone().map_or(Value::Null, Value::from);
    details["report_id"] = observed_report_id.map_or(Value::Null, Value::from);
    set_operation_status(
        &mut details,
        if confirmed_not_started {
            "prepared_not_started"
        } else {
            "start_outcome_unconfirmed"
        },
    );
    finish(
        root,
        runner,
        kind,
        "Diagnostic task start outcome is unconfirmed; deterministic config, target, and task state were retained.",
        findings,
        details,
        status_only,
    )
}

fn validate_diagnostic_arguments(
    host: &str,
    nvt_id: &str,
    source_scan_config_id: &str,
    port_list_id: &str,
    scanner_id: &str,
) -> Result<DiagnosticArguments, String> {
    let host = validate_host(host)?;
    let nvt_id = nvt_id.trim();
    let parts = nvt_id.split('.').collect::<Vec<_>>();
    if parts.len() < 2
        || parts.first() != Some(&"1")
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("--nvt-id must be a numeric NVT OID".into());
    }
    Ok(DiagnosticArguments {
        host,
        nvt_id: nvt_id.into(),
        source_scan_config_id: validate_operator_uuid(
            source_scan_config_id,
            "--source-scan-config-id",
        )?,
        port_list_id: validate_operator_uuid(port_list_id, "--port-list-id")?,
        scanner_id: validate_operator_uuid(scanner_id, "--scanner-id")?,
    })
}

fn diagnostic_operation_key(arguments: &DiagnosticArguments) -> String {
    let input = format!(
        "{}\0{}\0{}",
        arguments.host, arguments.nvt_id, arguments.source_scan_config_id
    );
    format!("{:x}", Sha256::digest(input.as_bytes()))[..16].to_string()
}

struct ValidatedArguments {
    host: Option<String>,
    target_id: Option<String>,
    alert_id: Option<String>,
    port_list_id: String,
    scan_config_id: String,
    scanner_id: String,
}

fn validate_arguments(
    host: Option<&str>,
    target_id: Option<&str>,
    alert_id: Option<&str>,
    port_list_id: &str,
    scan_config_id: &str,
    scanner_id: &str,
) -> Result<ValidatedArguments, String> {
    if host.is_some() == target_id.is_some() {
        return Err("exactly one of --target-id or --host is required".into());
    }
    let host = host.map(validate_host).transpose()?;
    let target_id = target_id
        .map(|value| validate_operator_uuid(value, "--target-id"))
        .transpose()?;
    let alert_id = alert_id
        .map(|value| validate_operator_uuid(value, "--alert-id"))
        .transpose()?;
    let port_list_id = validate_operator_uuid(port_list_id, "--port-list-id")?;
    let scan_config_id = validate_operator_uuid(scan_config_id, "--scan-config-id")?;
    let scanner_id = validate_operator_uuid(scanner_id, "--scanner-id")?;
    Ok(ValidatedArguments {
        host,
        target_id,
        alert_id,
        port_list_id,
        scan_config_id,
        scanner_id,
    })
}

fn validate_host(host: &str) -> Result<String, String> {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed.contains('%') {
        return Err("--host must be one explicit IPv4 or IPv6 address".into());
    }
    IpAddr::from_str(trimmed).map(|address| address.to_string()).map_err(|_| {
        "--host must be one explicit IPv4 or IPv6 address; hostnames, CIDRs, and ranges are not allowed".into()
    })
}

fn target_body(host: &str, port_list_id: &str, operation_key: &str) -> Value {
    json!({
        "name": format!("Native scan target {host} {operation_key}"),
        "comment": "YAFVS native scan-new-system target",
        "port_list_id": port_list_id,
        "hosts": [host],
        "exclude_hosts": [],
        "alive_tests": [DEFAULT_ALIVE_TEST],
        "allow_simultaneous_ips": false,
        "reverse_lookup_only": false,
        "reverse_lookup_unify": false,
    })
}

fn task_body(
    subject: &str,
    target_id: &str,
    scan_config_id: &str,
    scanner_id: &str,
    operation_key: &str,
    alert_id: Option<&str>,
) -> Value {
    let mut body = Map::from_iter([
        (
            "name".into(),
            Value::String(format!("Native scan task {subject} {operation_key}")),
        ),
        ("target_id".into(), Value::String(target_id.into())),
        ("config_id".into(), Value::String(scan_config_id.into())),
        ("scanner_id".into(), Value::String(scanner_id.into())),
    ]);
    if let Some(alert_id) = alert_id {
        body.insert("alert_ids".into(), json!([alert_id]));
    }
    Value::Object(body)
}

#[allow(clippy::too_many_arguments)]
fn diagnostic_preflight(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    arguments: &DiagnosticArguments,
    operator_uuid: &str,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> bool {
    let checks = [
        (
            "nvt",
            arguments.nvt_id.as_str(),
            format!(
                "/api/v1/nvts/{}",
                percent_encode_component(&arguments.nvt_id)
            ),
        ),
        (
            "source-scan-config",
            arguments.source_scan_config_id.as_str(),
            format!(
                "/api/v1/scan-configs/{}",
                percent_encode_component(&arguments.source_scan_config_id)
            ),
        ),
        (
            "port-list",
            arguments.port_list_id.as_str(),
            format!(
                "/api/v1/port-lists/{}",
                percent_encode_component(&arguments.port_list_id)
            ),
        ),
        (
            "scanner",
            arguments.scanner_id.as_str(),
            format!(
                "/api/v1/scanners/{}",
                percent_encode_component(&arguments.scanner_id)
            ),
        ),
    ];
    let mut passed = true;
    for (resource, expected_id, path) in checks {
        let Some(reply) = api_call(
            root,
            runner,
            api,
            ScanKind::Diagnostic.command(),
            &path,
            "GET",
            None,
            findings,
            config_recorded,
        ) else {
            return false;
        };
        let object = reply.parsed.as_ref().and_then(Value::as_object);
        let mut typed = object
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            == Some(expected_id)
            && object
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty());
        let mut reason = String::new();
        if resource == "source-scan-config" {
            let eligibility = diagnostic_scan_config_eligibility(
                reply.parsed.as_ref(),
                expected_id,
                expected_id == EMPTY_SCAN_CONFIG_ID,
                operator_uuid,
            );
            typed &= eligibility.0;
            reason = eligibility.1;
        }
        if resource == "scanner" {
            typed &= object
                .and_then(|value| value.get("scanner_type"))
                .and_then(Value::as_i64)
                .is_some_and(|scanner_type| {
                    ScannerType::try_from(scanner_type).is_ok_and(ScannerType::is_scan_task_capable)
                });
        }
        let accepted = reply_ok(&reply, 200) && typed;
        let message = if accepted {
            "Native diagnostic preflight returned the expected resource.".to_string()
        } else if resource == "source-scan-config" {
            format!("Diagnostic source scan config rejected: {reason}.")
        } else {
            format!("Native {resource} preflight failed or was not eligible.")
        };
        findings.push(probe_finding(
            if accepted { "pass" } else { "fail" },
            &format!("{}.preflight.{resource}", ScanKind::Diagnostic.command()),
            &message,
            &reply,
            json!({"expected_id":expected_id}),
        ));
        passed &= accepted;
    }
    passed
}

fn diagnostic_scan_config_eligibility(
    value: Option<&Value>,
    scan_config_id: &str,
    source_is_default: bool,
    operator_uuid: &str,
) -> (bool, String) {
    let Some(config) = value.and_then(Value::as_object) else {
        return (
            false,
            "scan-config detail did not identify the requested source".into(),
        );
    };
    if config.get("id").and_then(Value::as_str) != Some(scan_config_id) {
        return (
            false,
            "scan-config detail did not identify the requested source".into(),
        );
    }
    if source_is_default {
        if config.get("predefined").and_then(Value::as_bool) != Some(true) {
            return (
                false,
                "the default diagnostic source is not proven to be predefined".into(),
            );
        }
        if config.get("writable").and_then(Value::as_bool) == Some(true) {
            return (
                false,
                "the default diagnostic source unexpectedly appears mutable".into(),
            );
        }
        return (true, "predefined Empty scan config".into());
    }
    if config.get("predefined").and_then(Value::as_bool) == Some(true) {
        return (
            false,
            "explicit diagnostic sources must not be predefined".into(),
        );
    }
    if config.get("writable").and_then(Value::as_bool) != Some(true) {
        return (
            false,
            "explicit diagnostic source is not proven mutable".into(),
        );
    }
    if config.get("in_use").and_then(Value::as_bool) == Some(true) {
        return (
            false,
            "explicit diagnostic source is already used by a task".into(),
        );
    }
    if config.get("owner_id").and_then(Value::as_str) != Some(operator_uuid) {
        return (
            false,
            "explicit diagnostic source ownership is not proven for the current operator".into(),
        );
    }
    (true, "operator-owned mutable scan config".into())
}

#[allow(clippy::too_many_arguments)]
fn reconcile_diagnostic_config(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    name: &str,
    operator_uuid: &str,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> Option<String> {
    let path = format!(
        "/api/v1/scan-configs?filter={}&page_size=100&sort=name",
        percent_encode_component(name)
    );
    let reply = api_call(
        root,
        runner,
        api,
        ScanKind::Diagnostic.command(),
        &path,
        "GET",
        None,
        findings,
        config_recorded,
    )?;
    let matches = reply
        .parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|item| {
            item.get("name").and_then(Value::as_str) == Some(name)
                && item.get("owner_id").and_then(Value::as_str) == Some(operator_uuid)
                && item
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(valid_uuid)
                    .is_some()
                && item.get("predefined").and_then(Value::as_bool) == Some(false)
                && item.get("writable").and_then(Value::as_bool) == Some(true)
                && item.get("in_use").and_then(Value::as_bool) != Some(true)
        })
        .collect::<Vec<_>>();
    let reconciled = (matches.len() == 1)
        .then(|| matches[0].get("id").and_then(Value::as_str))
        .flatten()
        .and_then(valid_uuid);
    findings.push(probe_finding(
        if reconciled.is_some() { "pass" } else { "warn" },
        &format!(
            "{}.scan-config-reconciliation",
            ScanKind::Diagnostic.command()
        ),
        if reconciled.is_some() {
            "Reconciled exactly one deterministic mutable scan config after an uncertain clone response."
        } else {
            "Could not reconcile exactly one deterministic scan config; helper-created state is retained."
        },
        &reply,
        json!({"name":name,"match_count":matches.len()}),
    ));
    reconciled
}

#[allow(clippy::too_many_arguments)]
fn cleanup_scan_config(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    scan_config_id: &str,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> Value {
    let command = ScanKind::Diagnostic.command();
    let mut cleanup = json!({
        "attempted": true,
        "scan_config_id": scan_config_id,
        "live_delete": "not_attempted",
        "trash_hard_delete": "not_attempted",
    });
    let live_path = format!(
        "/api/v1/scan-configs/{}",
        percent_encode_component(scan_config_id)
    );
    let live = api_call(
        root,
        runner,
        api,
        command,
        &live_path,
        "DELETE",
        None,
        findings,
        config_recorded,
    );
    let live_deleted = live.as_ref().is_some_and(|reply| reply_ok(reply, 204));
    cleanup["live_delete"] = Value::String(if live_deleted { "deleted" } else { "failed" }.into());
    cleanup["live_delete_http_status"] = live
        .as_ref()
        .and_then(|reply| reply.http_status)
        .map_or(Value::Null, Value::from);
    if let Some(reply) = live {
        findings.push(probe_finding(
            if live_deleted { "pass" } else { "fail" },
            &format!("{command}.cleanup.scan-config-live-delete"),
            if live_deleted {
                "Helper-created scan config was moved to trash after task creation failed."
            } else {
                "Helper-created scan config could not be moved to trash."
            },
            &reply,
            json!({"scan_config_id":scan_config_id}),
        ));
    }
    if !live_deleted {
        cleanup["trash_hard_delete"] = Value::String("skipped_live_delete_failed".into());
        return cleanup;
    }
    let trash_path = format!("{live_path}/trash");
    let trash = api_call(
        root,
        runner,
        api,
        command,
        &trash_path,
        "DELETE",
        None,
        findings,
        config_recorded,
    );
    let deleted = trash.as_ref().is_some_and(|reply| reply_ok(reply, 204));
    cleanup["trash_hard_delete"] = Value::String(if deleted { "deleted" } else { "failed" }.into());
    cleanup["trash_hard_delete_http_status"] = trash
        .as_ref()
        .and_then(|reply| reply.http_status)
        .map_or(Value::Null, Value::from);
    if let Some(reply) = trash {
        findings.push(probe_finding(
            if deleted { "pass" } else { "fail" },
            &format!("{command}.cleanup.scan-config-trash-hard-delete"),
            if deleted {
                "Helper-created scan config was hard-deleted from trash."
            } else {
                "Helper-created scan config remains in trash because hard deletion failed."
            },
            &reply,
            json!({"scan_config_id":scan_config_id}),
        ));
    }
    cleanup
}

fn diagnostic_selection_accepted(reply: &ApiReply, scan_config_id: &str, nvt_id: &str) -> bool {
    let object = reply.parsed.as_ref().and_then(Value::as_object);
    reply_ok(reply, 200)
        && object
            .and_then(|object| object.get("config_id"))
            .and_then(Value::as_str)
            == Some(scan_config_id)
        && object
            .and_then(|object| object.get("nvt_id"))
            .and_then(Value::as_str)
            == Some(nvt_id)
        && object
            .and_then(|object| object.get("status"))
            .and_then(Value::as_str)
            == Some("selected")
}

#[allow(clippy::too_many_arguments)]
fn preflight(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    command: &str,
    arguments: &ValidatedArguments,
    operator_uuid: &str,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> bool {
    let mut checks = Vec::new();
    if let Some(target_id) = &arguments.target_id {
        checks.push((
            "target",
            target_id.as_str(),
            format!("/api/v1/targets/{}", percent_encode_component(target_id)),
        ));
    } else {
        checks.push((
            "port-list",
            arguments.port_list_id.as_str(),
            format!(
                "/api/v1/port-lists/{}",
                percent_encode_component(&arguments.port_list_id)
            ),
        ));
    }
    checks.extend([
        (
            "scan-config",
            arguments.scan_config_id.as_str(),
            format!(
                "/api/v1/scan-configs/{}",
                percent_encode_component(&arguments.scan_config_id)
            ),
        ),
        (
            "scanner",
            arguments.scanner_id.as_str(),
            format!(
                "/api/v1/scanners/{}",
                percent_encode_component(&arguments.scanner_id)
            ),
        ),
    ]);
    if let Some(alert_id) = &arguments.alert_id {
        checks.push((
            "alert",
            alert_id.as_str(),
            format!("/api/v1/alerts/{}", percent_encode_component(alert_id)),
        ));
    }
    let mut passed = true;
    for (resource, expected_id, path) in checks {
        let Some(reply) = api_call(
            root,
            runner,
            api,
            command,
            &path,
            "GET",
            None,
            findings,
            config_recorded,
        ) else {
            return false;
        };
        let object = reply.parsed.as_ref().and_then(Value::as_object);
        let mut typed = object
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            == Some(expected_id)
            && object
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty());
        if resource == "scanner" {
            typed &= object
                .and_then(|value| value.get("scanner_type"))
                .and_then(Value::as_i64)
                .is_some_and(|scanner_type| {
                    ScannerType::try_from(scanner_type).is_ok_and(ScannerType::is_scan_task_capable)
                });
        }
        if resource == "alert" {
            typed &= alert_eligible(reply.parsed.as_ref(), expected_id, operator_uuid, None);
        }
        if resource == "target" && arguments.alert_id.is_some() {
            typed &= object
                .and_then(|value| value.get("owner_id"))
                .and_then(Value::as_str)
                == Some(operator_uuid);
        }
        let accepted = reply_ok(&reply, 200) && typed;
        let message = if accepted {
            format!("Native {resource} preflight returned the expected typed resource.")
        } else {
            format!(
                "Native {resource} preflight failed, returned the wrong resource, or was not valid for this scan request."
            )
        };
        findings.push(probe_finding(
            if accepted { "pass" } else { "fail" },
            &format!("{command}.preflight.{resource}"),
            &message,
            &reply,
            json!({"expected_id":expected_id}),
        ));
        passed &= accepted;
    }
    passed
}

#[allow(clippy::too_many_arguments)]
fn api_call(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    command: &str,
    path: &str,
    method: &str,
    body: Option<&Value>,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> Option<ApiReply> {
    match api.call(root, path, method, body, command, runner) {
        Ok(mut reply) => {
            if !*config_recorded {
                findings.push(
                    reply
                        .config
                        .take()
                        .expect("guarded API replies retain one config finding"),
                );
                *config_recorded = true;
            }
            Some(reply)
        }
        Err(mut errors) => {
            findings.append(&mut errors);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_named(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    command: &str,
    collection: &str,
    name: &str,
    operator_uuid: &str,
    expected: &Value,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> Option<Map<String, Value>> {
    let path = format!(
        "/api/v1/{collection}?filter={}&page_size=100&sort=name",
        percent_encode_component(name)
    );
    let reply = api_call(
        root,
        runner,
        api,
        command,
        &path,
        "GET",
        None,
        findings,
        config_recorded,
    )?;
    let items = reply
        .parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("items"))
        .and_then(Value::as_array);
    let matches = items
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|item| {
            item.get("name").and_then(Value::as_str) == Some(name)
                && item.get("owner_id").and_then(Value::as_str) == Some(operator_uuid)
                && if collection == "targets" {
                    item.get("hosts") == Some(&json!([expected["host"]]))
                        && item
                            .get("port_list")
                            .and_then(Value::as_object)
                            .and_then(|port_list| port_list.get("id"))
                            == Some(&expected["port_list_id"])
                } else {
                    [
                        ("target", "target_id"),
                        ("config", "config_id"),
                        ("scanner", "scanner_id"),
                    ]
                    .into_iter()
                    .all(|(reference, key)| {
                        item.get(reference)
                            .and_then(Value::as_object)
                            .and_then(|object| object.get("id"))
                            == Some(&expected[key])
                    })
                }
        })
        .cloned()
        .collect::<Vec<_>>();
    let reconciled = (matches.len() == 1).then(|| matches[0].clone());
    let singular = &collection[..collection.len() - 1];
    let message = if reconciled.is_some() {
        format!(
            "Reconciled exactly one operator-owned {singular} after an ambiguous create response."
        )
    } else {
        format!(
            "Could not reconcile exactly one operator-owned {singular} after an ambiguous create response; resources are retained."
        )
    };
    findings.push(probe_finding(
        if reconciled.is_some() { "pass" } else { "warn" },
        &format!("{command}.{singular}-create-reconciliation"),
        &message,
        &reply,
        json!({"match_count":matches.len()}),
    ));
    reconciled
}

#[allow(clippy::too_many_arguments)]
fn cleanup_target(
    root: &Path,
    runner: &dyn CommandRunner,
    api: &dyn ScanApi,
    command: &str,
    target_id: &str,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
) -> Value {
    let mut cleanup = json!({
        "attempted": true,
        "target_id": target_id,
        "live_delete": "not_attempted",
        "trash_hard_delete": "not_attempted",
    });
    let live_path = format!("/api/v1/targets/{}", percent_encode_component(target_id));
    let live = api_call(
        root,
        runner,
        api,
        command,
        &live_path,
        "DELETE",
        None,
        findings,
        config_recorded,
    );
    let live_deleted = live.as_ref().is_some_and(|reply| reply_ok(reply, 204));
    cleanup["live_delete"] = Value::String(if live_deleted { "deleted" } else { "failed" }.into());
    cleanup["live_delete_http_status"] = live
        .as_ref()
        .and_then(|reply| reply.http_status)
        .map_or(Value::Null, Value::from);
    if let Some(reply) = live {
        findings.push(probe_finding(
            if live_deleted { "pass" } else { "fail" },
            &format!("{command}.cleanup.target-live-delete"),
            if live_deleted {
                "Created target was live-deleted after task creation failed."
            } else {
                "Created target could not be live-deleted after task creation failed."
            },
            &reply,
            json!({"target_id":target_id}),
        ));
    }
    if !live_deleted {
        cleanup["trash_hard_delete"] = Value::String("skipped_live_delete_failed".into());
        return cleanup;
    }
    let trash_path = format!("{live_path}/trash");
    let trash = api_call(
        root,
        runner,
        api,
        command,
        &trash_path,
        "DELETE",
        None,
        findings,
        config_recorded,
    );
    let deleted = trash.as_ref().is_some_and(|reply| reply_ok(reply, 204));
    cleanup["trash_hard_delete"] = Value::String(if deleted { "deleted" } else { "failed" }.into());
    cleanup["trash_hard_delete_http_status"] = trash
        .as_ref()
        .and_then(|reply| reply.http_status)
        .map_or(Value::Null, Value::from);
    if let Some(reply) = trash {
        findings.push(probe_finding(
            if deleted { "pass" } else { "fail" },
            &format!("{command}.cleanup.target-trash-hard-delete"),
            if deleted {
                "Created target was hard-deleted from trash after task creation failed."
            } else {
                "Created target was moved to trash but could not be hard-deleted."
            },
            &reply,
            json!({"target_id":target_id}),
        ));
    }
    cleanup
}

fn alert_eligible(
    value: Option<&Value>,
    alert_id: &str,
    operator_uuid: &str,
    task_id: Option<&str>,
) -> bool {
    let Some(alert) = value.and_then(Value::as_object) else {
        return false;
    };
    let task_attached = task_id.is_none_or(|task_id| {
        alert
            .get("tasks")
            .and_then(Value::as_array)
            .is_some_and(|tasks| {
                tasks
                    .iter()
                    .any(|task| task.get("id").and_then(Value::as_str) == Some(task_id))
            })
    });
    alert.get("id").and_then(Value::as_str) == Some(alert_id)
        && alert.get("owner_id").and_then(Value::as_str) == Some(operator_uuid)
        && alert.get("active").and_then(Value::as_bool) == Some(true)
        && alert
            .get("method")
            .and_then(Value::as_object)
            .and_then(|method| method.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|method| matches!(method.to_ascii_uppercase().as_str(), "EMAIL" | "SMB"))
        && task_attached
}

fn accepted_created_id(reply: &ApiReply, expected_name: &str) -> Option<String> {
    if !reply_ok(reply, 201) {
        return None;
    }
    let object = reply.parsed.as_ref()?.as_object()?;
    if object.get("name").and_then(Value::as_str) != Some(expected_name) {
        return None;
    }
    object
        .get("id")
        .and_then(Value::as_str)
        .and_then(valid_uuid)
}

fn valid_uuid(value: &str) -> Option<String> {
    validate_operator_uuid(value, "response id").ok()
}

fn reply_ok(reply: &ApiReply, expected_status: i64) -> bool {
    !reply.oversized && reply.output.success && reply.http_status == Some(expected_status)
}

fn ambiguous_create(reply: &ApiReply) -> bool {
    !reply.output.success
        || reply.http_status.is_none()
        || reply.http_status.is_some_and(|status| status >= 500)
        || reply
            .http_status
            .is_some_and(|status| (200..300).contains(&status))
}

fn response_summary(reply: &ApiReply) -> Value {
    let Some(object) = reply.parsed.as_ref().and_then(Value::as_object) else {
        return json!({"parsed":false});
    };
    let mut summary = Map::from_iter([("parsed".into(), Value::Bool(true))]);
    if let Some(items) = object.get("items").and_then(Value::as_array) {
        summary.insert("item_count_in_response".into(), Value::from(items.len()));
    }
    Value::Object(summary)
}

fn probe_finding(
    status: &str,
    check: &str,
    message: &str,
    reply: &ApiReply,
    additional: Value,
) -> Finding {
    let mut details = Map::from_iter([
        (
            "exit_code".into(),
            reply.output.exit_code.map_or(Value::Null, Value::from),
        ),
        (
            "http_status".into(),
            reply.http_status.map_or(Value::Null, Value::from),
        ),
        ("response_summary".into(), response_summary(reply)),
    ]);
    if let Some(additional) = additional.as_object() {
        details.extend(additional.clone());
    }
    Finding::new(status, check, message.into()).with_details(Value::Object(details))
}

fn set_operation_status(details: &mut Value, status: &str) {
    details["status"] = Value::String(status.into());
    details["operation_status"] = Value::String(status.into());
}

fn finish(
    root: &Path,
    runner: &dyn CommandRunner,
    kind: ScanKind,
    summary: &str,
    findings: Vec<Finding>,
    mut details: Value,
    status_only: bool,
) -> ResultEnvelope {
    let command = kind.command();
    if kind == ScanKind::Delivery {
        let selected = [
            "dry_run",
            "status",
            "operation_status",
            "host",
            "port_list_id",
            "scan_config_id",
            "scanner_id",
            "alert_id",
            "target_id",
            "target_name",
            "task_name",
            "task_id",
            "report_id",
            "observed_task_status",
            "observed_report_id",
            "start_follow_up_http_status",
            "cleanup",
        ];
        details = Value::Object(
            selected
                .into_iter()
                .map(|key| (key.into(), details.get(key).cloned().unwrap_or(Value::Null)))
                .collect(),
        );
    }
    let mut result = make_result(metadata(root, command, runner), summary.into(), findings)
        .with_details(details);
    if status_only {
        let source = result
            .details
            .as_ref()
            .cloned()
            .unwrap_or_else(|| json!({}));
        let keys = if kind == ScanKind::Diagnostic {
            vec![
                "host",
                "nvt_id",
                "source_scan_config_id",
                "scan_config_id",
                "scan_config_name",
                "port_list_id",
                "scanner_id",
                "target_id",
                "target_name",
                "task_id",
                "task_name",
                "report_id",
                "operation_key",
                "status",
                "operation_status",
                "cleanup",
                "observed_task_status",
                "observed_report_id",
            ]
        } else {
            vec![
                "host",
                "dry_run",
                "status",
                "operation_status",
                "port_list_id",
                "scan_config_id",
                "scanner_id",
                "alert_id",
                "target_id",
                "target_name",
                "task_name",
                "task_id",
                "report_id",
                "observed_task_status",
                "observed_report_id",
                "start_follow_up_http_status",
                "cleanup",
            ]
        };
        result.details = Some(Value::Object(
            keys.into_iter()
                .map(|key| (key.into(), source.get(key).cloned().unwrap_or(Value::Null)))
                .collect(),
        ));
        result.findings = result
            .findings
            .iter()
            .filter(|finding| finding.status != "pass")
            .map(compact_finding)
            .collect();
        if result.findings.is_empty() {
            result.findings.push(Finding::new(
                "pass",
                &format!("{command}.status-only"),
                "Native scan request completed; identifiers summarized.".into(),
            ));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::sync::Mutex;

    const TARGET_ID: &str = "11111111-1111-4111-8111-111111111111";
    const TASK_ID: &str = "22222222-2222-4222-8222-222222222222";
    const REPORT_ID: &str = "33333333-3333-4333-8333-333333333333";
    const ALERT_ID: &str = "44444444-4444-4444-8444-444444444444";
    const OPERATOR_ID: &str = "55555555-5555-4555-8555-555555555555";
    const CONFIG_ID: &str = "66666666-6666-4666-8666-666666666666";
    const NVT_ID: &str = "1.3.6.1.4.1.25623.1.0.106223";

    #[derive(Clone)]
    struct Scripted {
        method: &'static str,
        path_prefix: &'static str,
        success: bool,
        status: Option<i64>,
        payload: Value,
    }

    struct MockApi {
        scripted: Mutex<VecDeque<Scripted>>,
        calls: Mutex<Vec<(String, String, Option<Value>)>>,
    }

    impl MockApi {
        fn new(scripted: impl IntoIterator<Item = Scripted>) -> Self {
            Self {
                scripted: Mutex::new(scripted.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ScanApi for MockApi {
        fn call(
            &self,
            _root: &Path,
            path: &str,
            method: &str,
            body: Option<&Value>,
            command: &str,
            _runner: &dyn CommandRunner,
        ) -> Result<ApiReply, Vec<Finding>> {
            self.calls
                .lock()
                .unwrap()
                .push((method.into(), path.into(), body.cloned()));
            let scripted = self.scripted.lock().unwrap().pop_front().unwrap();
            assert_eq!(method, scripted.method);
            assert!(path.starts_with(scripted.path_prefix), "{path}");
            Ok(ApiReply {
                output: ProcessOutput {
                    success: scripted.success,
                    exit_code: Some(if scripted.success { 0 } else { 28 }),
                    stdout: String::new(),
                    stderr: String::new(),
                },
                parsed: Some(scripted.payload),
                http_status: scripted.status,
                oversized: false,
                config: Some(Finding::new(
                    "pass",
                    &format!("{command}.direct-config-shape"),
                    "ok".into(),
                )),
            })
        }
    }

    struct Runner;
    impl CommandRunner for Runner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }
        fn run_with(
            &self,
            _program: &str,
            _args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            None
        }
    }

    fn scripted(
        method: &'static str,
        path_prefix: &'static str,
        status: i64,
        payload: Value,
    ) -> Scripted {
        Scripted {
            method,
            path_prefix,
            success: true,
            status: Some(status),
            payload,
        }
    }

    fn preflight(host_mode: bool, delivery: bool) -> Vec<Scripted> {
        let mut rows = vec![
            scripted(
                "GET",
                if host_mode {
                    "/api/v1/port-lists/"
                } else {
                    "/api/v1/targets/"
                },
                200,
                if host_mode {
                    json!({"id":IANA_TCP_UDP_PORT_LIST_ID,"name":"IANA"})
                } else {
                    json!({"id":TARGET_ID,"name":"Existing","owner_id":OPERATOR_ID})
                },
            ),
            scripted(
                "GET",
                "/api/v1/scan-configs/",
                200,
                json!({"id":FULL_AND_FAST_SCAN_CONFIG_ID,"name":"Full and fast"}),
            ),
            scripted(
                "GET",
                "/api/v1/scanners/",
                200,
                json!({"id":DEFAULT_SCANNER_ID,"name":"OpenVAS","scanner_type":2}),
            ),
        ];
        if delivery {
            rows.push(scripted(
                "GET",
                "/api/v1/alerts/",
                200,
                json!({"id":ALERT_ID,"name":"Delivery","owner_id":OPERATOR_ID,"active":true,"method":{"type":"EMAIL"}}),
            ));
        }
        rows
    }

    fn diagnostic_preflight_script() -> Vec<Scripted> {
        vec![
            scripted(
                "GET",
                "/api/v1/nvts/",
                200,
                json!({"id":NVT_ID,"name":"Diagnostic NVT"}),
            ),
            scripted(
                "GET",
                "/api/v1/scan-configs/",
                200,
                json!({
                    "id":EMPTY_SCAN_CONFIG_ID,
                    "name":"Empty",
                    "predefined":true,
                    "writable":false,
                    "in_use":false,
                }),
            ),
            scripted(
                "GET",
                "/api/v1/port-lists/",
                200,
                json!({"id":IANA_TCP_UDP_PORT_LIST_ID,"name":"IANA"}),
            ),
            scripted(
                "GET",
                "/api/v1/scanners/",
                200,
                json!({"id":DEFAULT_SCANNER_ID,"name":"OpenVAS","scanner_type":2}),
            ),
        ]
    }

    #[test]
    fn invalid_arguments_and_dry_run_never_access_runtime() {
        let api = MockApi::new([]);
        let invalid = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::NewSystem,
            Some("192.0.2.0/24"),
            None,
            None,
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(invalid.status, "fail");
        let dry = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::NewSystem,
            Some("2001:db8::10"),
            None,
            None,
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            false,
            true,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(dry.status, "pass");
        assert_eq!(dry.details.as_ref().unwrap()["status"], "dry_run");
        assert_eq!(
            dry.details.as_ref().unwrap()["planned_target"]["hosts"],
            json!(["2001:db8::10"])
        );
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn new_system_preflights_creates_and_starts_in_order() {
        let mut script = preflight(true, false);
        script.extend([
            scripted(
                "POST",
                "/api/v1/targets",
                201,
                json!({"id":TARGET_ID,"name":"Native scan target 192.0.2.10 fixed"}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks",
                201,
                json!({"id":TASK_ID,"name":"Native scan task 192.0.2.10 fixed"}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks/",
                202,
                json!({"task_id":TASK_ID,"report_id":REPORT_ID,"status":"requested"}),
            ),
        ]);
        let api = MockApi::new(script);
        let result = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::NewSystem,
            Some("192.0.2.10"),
            None,
            None,
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["status"], "requested");
        assert_eq!(result.details.as_ref().unwrap()["report_id"], REPORT_ID);
        assert_eq!(
            api.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(method, path, _)| (method.as_str(), path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    "GET",
                    "/api/v1/port-lists/4a4717fe-57d2-11e1-9a26-406186ea4fc5"
                ),
                (
                    "GET",
                    "/api/v1/scan-configs/daba56c8-73ec-11df-a475-002264764cea"
                ),
                (
                    "GET",
                    "/api/v1/scanners/08b69003-5fc2-4037-a479-93b440211c73"
                ),
                ("POST", "/api/v1/targets"),
                ("POST", "/api/v1/tasks"),
                (
                    "POST",
                    "/api/v1/tasks/22222222-2222-4222-8222-222222222222/start"
                ),
            ]
        );
    }

    #[test]
    fn rejected_task_create_cleans_only_a_proven_created_target() {
        let mut script = preflight(true, false);
        script.extend([
            scripted(
                "POST",
                "/api/v1/targets",
                201,
                json!({"id":TARGET_ID,"name":"Native scan target 192.0.2.10 fixed"}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks",
                409,
                json!({"error":{"code":"conflict"}}),
            ),
            scripted("DELETE", "/api/v1/targets/", 204, json!({})),
            scripted("DELETE", "/api/v1/targets/", 204, json!({})),
        ]);
        let api = MockApi::new(script);
        let result = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::NewSystem,
            Some("192.0.2.10"),
            None,
            None,
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.details.as_ref().unwrap()["status"],
            "task_create_failed"
        );
        assert_eq!(
            result.details.as_ref().unwrap()["cleanup"]["trash_hard_delete"],
            "deleted"
        );
    }

    #[test]
    fn failed_start_rechecks_task_and_never_cleans_resources() {
        let mut script = preflight(true, false);
        script.extend([
            scripted(
                "POST",
                "/api/v1/targets",
                201,
                json!({"id":TARGET_ID,"name":"Native scan target 192.0.2.10 fixed"}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks",
                201,
                json!({"id":TASK_ID,"name":"Native scan task 192.0.2.10 fixed"}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks/",
                409,
                json!({"error":{"code":"conflict"}}),
            ),
            scripted(
                "GET",
                "/api/v1/tasks/",
                200,
                json!({"id":TASK_ID,"status":"New","current_report":null}),
            ),
        ]);
        let api = MockApi::new(script);
        let result = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::NewSystem,
            Some("192.0.2.10"),
            None,
            None,
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(
            result.details.as_ref().unwrap()["operation_status"],
            "prepared_not_started"
        );
        assert!(
            api.calls
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _, _)| method != "DELETE")
        );
    }

    #[test]
    fn delivery_defaults_to_dry_run_and_omits_planned_bodies() {
        let api = MockApi::new([]);
        let result = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::Delivery,
            None,
            Some(TARGET_ID),
            Some(ALERT_ID),
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            false,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(result.details.as_ref().unwrap()["status"], "dry_run");
        assert!(
            result
                .details
                .as_ref()
                .unwrap()
                .get("planned_task")
                .is_none()
        );
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn delivery_rechecks_eligibility_after_task_creation() {
        let mut script = preflight(false, true);
        script.extend([
            scripted(
                "POST",
                "/api/v1/tasks",
                201,
                json!({"id":TASK_ID,"name":format!("Native scan task {TARGET_ID} fixed")}),
            ),
            scripted(
                "GET",
                "/api/v1/alerts/",
                200,
                json!({"id":ALERT_ID,"name":"Disabled","owner_id":OPERATOR_ID,"active":false,"method":{"type":"EMAIL"},"tasks":[{"id":TASK_ID}]}),
            ),
        ]);
        let api = MockApi::new(script);
        let result = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::Delivery,
            None,
            Some(TARGET_ID),
            Some(ALERT_ID),
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(
            result.details.as_ref().unwrap()["operation_status"],
            "prepared_not_started"
        );
        assert!(
            api.calls
                .lock()
                .unwrap()
                .iter()
                .all(|(_, path, _)| !path.ends_with("/start"))
        );
    }

    #[test]
    fn ambiguous_target_create_reconciles_exact_identity() {
        let mut script = preflight(true, true);
        script.extend([
            scripted("POST", "/api/v1/targets", 500, json!({"error":{"code":"db"}})),
            scripted(
                "GET",
                "/api/v1/targets?",
                200,
                json!({"items":[{
                    "id":TARGET_ID,
                    "name":"Native scan target 192.0.2.10 fixed",
                    "owner_id":OPERATOR_ID,
                    "hosts":["192.0.2.10"],
                    "port_list":{"id":IANA_TCP_UDP_PORT_LIST_ID}
                }],"page":{"total":1}}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks",
                201,
                json!({"id":TASK_ID,"name":"Native scan task 192.0.2.10 fixed"}),
            ),
            scripted(
                "GET",
                "/api/v1/alerts/",
                200,
                json!({"id":ALERT_ID,"name":"Delivery","owner_id":OPERATOR_ID,"active":true,"method":{"type":"SMB"},"tasks":[{"id":TASK_ID}]}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks/",
                202,
                json!({"task_id":TASK_ID,"report_id":REPORT_ID,"status":"requested"}),
            ),
        ]);
        let api = MockApi::new(script);
        let result = command_scan(
            Path::new("/srv/YAFVS"),
            ScanKind::Delivery,
            Some("192.0.2.10"),
            None,
            Some(ALERT_ID),
            IANA_TCP_UDP_PORT_LIST_ID,
            FULL_AND_FAST_SCAN_CONFIG_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            "fixed",
            OPERATOR_ID,
        );
        assert_eq!(result.status, "warn");
        assert_eq!(result.details.as_ref().unwrap()["status"], "requested");
        assert_eq!(result.details.as_ref().unwrap()["target_id"], TARGET_ID);
    }

    #[test]
    fn diagnostic_invalid_and_default_dry_run_never_access_runtime() {
        let api = MockApi::new([]);
        let invalid = command_diagnostic_scan(
            Path::new("/srv/YAFVS"),
            "192.0.2.0/24",
            "bad",
            EMPTY_SCAN_CONFIG_ID,
            IANA_TCP_UDP_PORT_LIST_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            Some(OPERATOR_ID),
        );
        assert_eq!(invalid.status, "fail");
        let dry = command_diagnostic_scan(
            Path::new("/srv/YAFVS"),
            "192.0.2.10",
            NVT_ID,
            EMPTY_SCAN_CONFIG_ID,
            IANA_TCP_UDP_PORT_LIST_ID,
            DEFAULT_SCANNER_ID,
            false,
            false,
            false,
            &Runner,
            &api,
            Some(OPERATOR_ID),
        );
        assert_eq!(dry.status, "pass");
        assert_eq!(dry.details.as_ref().unwrap()["status"], "dry_run");
        assert_eq!(
            dry.details.as_ref().unwrap()["planned_selection"]["prerequisite_nvt_ids"],
            json!(DIAGNOSTIC_PREREQUISITE_IDS)
        );
        assert_eq!(
            dry.details.as_ref().unwrap()["operation_key"],
            diagnostic_operation_key(
                &validate_diagnostic_arguments(
                    "192.0.2.10",
                    NVT_ID,
                    EMPTY_SCAN_CONFIG_ID,
                    IANA_TCP_UDP_PORT_LIST_ID,
                    DEFAULT_SCANNER_ID,
                )
                .unwrap()
            )
        );
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn diagnostic_preflights_clones_selects_creates_and_starts_in_order() {
        let mut script = diagnostic_preflight_script();
        script.extend([
            scripted(
                "POST",
                "/api/v1/scan-configs/",
                201,
                json!({"id":CONFIG_ID,"name":format!("YAFVS diagnostic NVT {}", diagnostic_operation_key(&validate_diagnostic_arguments("192.0.2.10", NVT_ID, EMPTY_SCAN_CONFIG_ID, IANA_TCP_UDP_PORT_LIST_ID, DEFAULT_SCANNER_ID).unwrap()))}),
            ),
            scripted(
                "POST",
                "/api/v1/scan-configs/",
                200,
                json!({"config_id":CONFIG_ID,"nvt_id":NVT_ID,"status":"selected"}),
            ),
            scripted(
                "POST",
                "/api/v1/targets",
                201,
                json!({"id":TARGET_ID,"name":format!("YAFVS diagnostic target {}", diagnostic_operation_key(&validate_diagnostic_arguments("192.0.2.10", NVT_ID, EMPTY_SCAN_CONFIG_ID, IANA_TCP_UDP_PORT_LIST_ID, DEFAULT_SCANNER_ID).unwrap()))}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks",
                201,
                json!({"id":TASK_ID,"name":format!("YAFVS diagnostic task {}", diagnostic_operation_key(&validate_diagnostic_arguments("192.0.2.10", NVT_ID, EMPTY_SCAN_CONFIG_ID, IANA_TCP_UDP_PORT_LIST_ID, DEFAULT_SCANNER_ID).unwrap()))}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks/",
                202,
                json!({"task_id":TASK_ID,"report_id":REPORT_ID,"status":"requested"}),
            ),
        ]);
        let api = MockApi::new(script);
        let result = command_diagnostic_scan(
            Path::new("/srv/YAFVS"),
            "192.0.2.10",
            NVT_ID,
            EMPTY_SCAN_CONFIG_ID,
            IANA_TCP_UDP_PORT_LIST_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            Some(OPERATOR_ID),
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["status"], "requested");
        assert_eq!(
            result.details.as_ref().unwrap()["scan_config_id"],
            CONFIG_ID
        );
        assert_eq!(result.details.as_ref().unwrap()["target_id"], TARGET_ID);
        assert_eq!(result.details.as_ref().unwrap()["task_id"], TASK_ID);
        assert_eq!(result.details.as_ref().unwrap()["report_id"], REPORT_ID);
        assert_eq!(
            api.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(method, path, _)| (method.as_str(), path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("GET", "/api/v1/nvts/1.3.6.1.4.1.25623.1.0.106223"),
                (
                    "GET",
                    "/api/v1/scan-configs/085569ce-73ed-11df-83c3-002264764cea"
                ),
                (
                    "GET",
                    "/api/v1/port-lists/4a4717fe-57d2-11e1-9a26-406186ea4fc5"
                ),
                (
                    "GET",
                    "/api/v1/scanners/08b69003-5fc2-4037-a479-93b440211c73"
                ),
                (
                    "POST",
                    "/api/v1/scan-configs/085569ce-73ed-11df-83c3-002264764cea/clone"
                ),
                (
                    "POST",
                    "/api/v1/scan-configs/66666666-6666-4666-8666-666666666666/diagnostic-nvt-selection"
                ),
                ("POST", "/api/v1/targets"),
                ("POST", "/api/v1/tasks"),
                (
                    "POST",
                    "/api/v1/tasks/22222222-2222-4222-8222-222222222222/start"
                ),
            ]
        );
    }

    #[test]
    fn diagnostic_task_failure_cleans_only_positively_created_resources() {
        let key = diagnostic_operation_key(
            &validate_diagnostic_arguments(
                "192.0.2.10",
                NVT_ID,
                EMPTY_SCAN_CONFIG_ID,
                IANA_TCP_UDP_PORT_LIST_ID,
                DEFAULT_SCANNER_ID,
            )
            .unwrap(),
        );
        let mut script = diagnostic_preflight_script();
        script.extend([
            scripted(
                "POST",
                "/api/v1/scan-configs/",
                201,
                json!({"id":CONFIG_ID,"name":format!("YAFVS diagnostic NVT {key}")}),
            ),
            scripted(
                "POST",
                "/api/v1/scan-configs/",
                200,
                json!({"config_id":CONFIG_ID,"nvt_id":NVT_ID,"status":"selected"}),
            ),
            scripted(
                "POST",
                "/api/v1/targets",
                201,
                json!({"id":TARGET_ID,"name":format!("YAFVS diagnostic target {key}")}),
            ),
            scripted(
                "POST",
                "/api/v1/tasks",
                409,
                json!({"error":{"code":"conflict"}}),
            ),
            scripted("DELETE", "/api/v1/targets/", 204, json!({})),
            scripted("DELETE", "/api/v1/targets/", 204, json!({})),
            scripted("DELETE", "/api/v1/scan-configs/", 204, json!({})),
            scripted("DELETE", "/api/v1/scan-configs/", 204, json!({})),
        ]);
        let api = MockApi::new(script);
        let result = command_diagnostic_scan(
            Path::new("/srv/YAFVS"),
            "192.0.2.10",
            NVT_ID,
            EMPTY_SCAN_CONFIG_ID,
            IANA_TCP_UDP_PORT_LIST_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            Some(OPERATOR_ID),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.details.as_ref().unwrap()["operation_status"],
            "task_create_failed"
        );
        assert_eq!(
            result.details.as_ref().unwrap()["cleanup"]["target"]["trash_hard_delete"],
            "deleted"
        );
        assert_eq!(
            result.details.as_ref().unwrap()["cleanup"]["scan_config"]["trash_hard_delete"],
            "deleted"
        );
    }

    #[test]
    fn diagnostic_reconciled_config_is_never_cleaned_after_selection_failure() {
        let key = diagnostic_operation_key(
            &validate_diagnostic_arguments(
                "192.0.2.10",
                NVT_ID,
                EMPTY_SCAN_CONFIG_ID,
                IANA_TCP_UDP_PORT_LIST_ID,
                DEFAULT_SCANNER_ID,
            )
            .unwrap(),
        );
        let mut script = diagnostic_preflight_script();
        script.extend([
            scripted(
                "POST",
                "/api/v1/scan-configs/",
                500,
                json!({"error":{"code":"database"}}),
            ),
            scripted(
                "GET",
                "/api/v1/scan-configs?",
                200,
                json!({"items":[{
                    "id":CONFIG_ID,
                    "name":format!("YAFVS diagnostic NVT {key}"),
                    "owner_id":OPERATOR_ID,
                    "predefined":false,
                    "writable":true,
                    "in_use":false,
                }]}),
            ),
            scripted(
                "POST",
                "/api/v1/scan-configs/",
                409,
                json!({"error":{"code":"conflict"}}),
            ),
        ]);
        let api = MockApi::new(script);
        let result = command_diagnostic_scan(
            Path::new("/srv/YAFVS"),
            "192.0.2.10",
            NVT_ID,
            EMPTY_SCAN_CONFIG_ID,
            IANA_TCP_UDP_PORT_LIST_ID,
            DEFAULT_SCANNER_ID,
            true,
            false,
            false,
            &Runner,
            &api,
            Some(OPERATOR_ID),
        );
        assert_eq!(
            result.details.as_ref().unwrap()["operation_status"],
            "selection_failed"
        );
        assert!(
            api.calls
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _, _)| method != "DELETE")
        );
    }
}
