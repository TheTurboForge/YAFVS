// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::guarded_direct_api_call;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::path::Path;

pub fn command_native_start_task(
    root: &Path,
    task_id: &str,
    allow: bool,
    status_only: bool,
) -> ResultEnvelope {
    command(
        root,
        "native-start-task",
        task_id,
        allow,
        status_only,
        &SystemCommandRunner,
    )
}
pub fn command_native_stop_task(
    root: &Path,
    task_id: &str,
    allow: bool,
    status_only: bool,
) -> ResultEnvelope {
    command(
        root,
        "native-stop-task",
        task_id,
        allow,
        status_only,
        &SystemCommandRunner,
    )
}
fn envelope(
    root: &Path,
    command: &str,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(metadata(root, command, runner), summary.into(), findings)
}
fn command(
    root: &Path,
    command: &str,
    task_id: &str,
    allow: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let start = command == "native-start-task";
    let action = if start { "start" } else { "stop" };
    let task_id = match validate_operator_uuid(task_id, "--task-id") {
        Ok(value) => value,
        Err(message) => {
            return envelope(
                root,
                command,
                runner,
                &format!("Native task {action} rejected before runtime access."),
                vec![Finding::new(
                    "fail",
                    &format!("{command}.arguments"),
                    message,
                )],
            );
        }
    };
    if !allow {
        let message = if start {
            "Starting a task requires --allow-write-control because it creates a report and queues scanner execution."
        } else {
            "Stopping a task requires --allow-write-control because it controls scanner task execution."
        };
        return envelope(
            root,
            command,
            runner,
            &format!("Native task {action} rejected before runtime access."),
            vec![Finding::new(
                "fail",
                &format!("{command}.write-control-intent"),
                message.into(),
            )],
        );
    }
    let call = match guarded_direct_api_call(
        root,
        &format!("/api/v1/tasks/{task_id}/{action}"),
        "POST",
        None,
        None,
        &format!("{command}.direct-config-shape"),
        &format!("{command}.direct-token-strength"),
        runner,
    ) {
        Ok(call) => call,
        Err(findings) => {
            let token_rejection = findings
                .iter()
                .any(|finding| finding.check.ends_with(".direct-token-strength"));
            let summary = if !start && token_rejection {
                "Native task stop rejected before runtime access.".to_string()
            } else {
                format!("Direct native API task {action} rejected before runtime access.")
            };
            return envelope(root, command, runner, &summary, findings);
        }
    };
    finish(root, command, start, task_id, status_only, runner, call)
}

fn finish(
    root: &Path,
    command: &str,
    start: bool,
    task_id: String,
    status_only: bool,
    runner: &dyn CommandRunner,
    call: super::native_api_request::GuardedDirectApiCall,
) -> ResultEnvelope {
    let object = call.parsed.as_ref().and_then(Value::as_object);
    let report_id = object
        .and_then(|item| item.get("report_id"))
        .and_then(Value::as_str);
    let task_status = object
        .and_then(|item| item.get("status"))
        .and_then(Value::as_str);
    let accepted = !call.oversized
        && call.output.success
        && object.is_some_and(|item| item.get("task_id").and_then(Value::as_str) == Some(&task_id))
        && if start {
            report_id.is_some_and(|id| validate_operator_uuid(id, "report_id").is_ok())
                && task_status == Some("requested")
                && call.http_status == Some(202)
        } else {
            task_status == Some("stopped") && call.http_status == Some(200)
        };
    let (message, summary, status_message) = if start {
        (
            if accepted {
                "Native API accepted the task start and returned the queued report id."
            } else {
                "Native API task start failed or returned an invalid acknowledgement."
            },
            if accepted {
                "Native task start accepted."
            } else {
                "Native task start failed."
            },
            "Native task start accepted; acknowledgement summarized.",
        )
    } else {
        (
            if accepted {
                "Native API verified that scanner work is absent and stopped the task."
            } else {
                "Native API task stop failed or returned an invalid acknowledgement."
            },
            if accepted {
                "Native task stop completed."
            } else {
                "Native task stop failed."
            },
            "Native task stop accepted; acknowledgement summarized.",
        )
    };
    let mut details =
        json!({"http_status": call.http_status, "task_id": task_id, "task_status": task_status});
    if start {
        details["report_id"] = report_id.map_or(Value::Null, Value::from);
    }
    let mut result = envelope(
        root,
        command,
        runner,
        summary,
        vec![
            call.config,
            Finding::new(
                if accepted { "pass" } else { "fail" },
                &format!("{command}.request"),
                message.into(),
            )
            .with_details(details.clone()),
        ],
    )
    .with_details(details);
    if status_only {
        result.findings = result
            .findings
            .iter()
            .filter(|item| item.status != "pass")
            .map(compact_finding)
            .collect();
        if result.findings.is_empty() {
            result.findings.push(Finding::new(
                "pass",
                &format!("{command}.status-only"),
                status_message.into(),
            ));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Runner {
        calls: Mutex<Vec<String>>,
    }
    impl CommandRunner for Runner {
        fn run(&self, p: &str, _: &[&str]) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(p.into());
            (p == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn refusals_make_no_runtime_request() {
        for (command_name, expected_check) in [
            (
                "native-start-task",
                "native-start-task.write-control-intent",
            ),
            ("native-stop-task", "native-stop-task.write-control-intent"),
        ] {
            let runner = Runner::default();
            let result = command(
                Path::new("/tmp/no-request"),
                command_name,
                "11111111-1111-4111-8111-111111111111",
                false,
                false,
                &runner,
            );
            assert_eq!(result.findings[0].check, expected_check);
            assert!(
                runner
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|program| program == "git")
            );
        }
    }

    #[test]
    fn invalid_stop_task_id_makes_no_runtime_request() {
        let runner = Runner::default();
        let result = command(
            Path::new("/tmp/no-request"),
            "native-stop-task",
            "not-a-uuid",
            true,
            false,
            &runner,
        );
        assert_eq!(result.findings[0].check, "native-stop-task.arguments");
        assert!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|program| program == "git")
        );
    }
    fn call(body: Value, status: i64) -> super::super::native_api_request::GuardedDirectApiCall {
        super::super::native_api_request::GuardedDirectApiCall {
            output: ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: format!("{body}\n{status}"),
                stderr: String::new(),
            },
            parsed: Some(body),
            http_status: Some(status),
            oversized: false,
            config: Finding::new(
                "pass",
                "native-start-task.direct-config-shape",
                "valid".into(),
            ),
        }
    }

    #[test]
    fn start_acknowledgement_is_exact_and_does_not_retain_response_body() {
        let runner = Runner::default();
        let task_id = "11111111-1111-4111-8111-111111111111";
        let result = finish(
            Path::new("/srv/YAFVS"),
            "native-start-task",
            true,
            task_id.into(),
            true,
            &runner,
            call(
                json!({
                    "task_id": task_id,
                    "report_id": "22222222-2222-4222-8222-222222222222",
                    "status": "requested",
                    "secret": "not-reported"
                }),
                202,
            ),
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.findings[0].check, "native-start-task.status-only");
        assert_eq!(result.details.as_ref().unwrap()["http_status"], 202);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("not-reported")
        );
    }

    #[test]
    fn start_and_stop_reject_incomplete_or_wrong_acknowledgements() {
        let runner = Runner::default();
        let task_id = "11111111-1111-4111-8111-111111111111";
        let incomplete_start = finish(
            Path::new("/srv/YAFVS"),
            "native-start-task",
            true,
            task_id.into(),
            false,
            &runner,
            call(json!({"task_id": task_id, "status": "requested"}), 202),
        );
        assert_eq!(incomplete_start.status, "fail");

        let requested_stop = finish(
            Path::new("/srv/YAFVS"),
            "native-stop-task",
            false,
            task_id.into(),
            false,
            &runner,
            call(json!({"task_id": task_id, "status": "requested"}), 202),
        );
        assert_eq!(requested_stop.status, "fail");

        let stopped = finish(
            Path::new("/srv/YAFVS"),
            "native-stop-task",
            false,
            task_id.into(),
            false,
            &runner,
            call(json!({"task_id": task_id, "status": "stopped"}), 200),
        );
        assert_eq!(stopped.status, "pass");
    }
}
