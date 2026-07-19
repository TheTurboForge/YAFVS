// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{
    GuardedDirectApiCall, MAX_REQUEST_BODY_BYTES, guarded_direct_api_call,
};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use serde::Serialize;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const COMMAND: &str = "native-update-task-target";
const MAX_HOST_ENTRIES: usize = 4095;
const MAX_HOSTS_FILE_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct ReplaceTargetBody<'a> {
    hosts: &'a [String],
    #[serde(skip_serializing_if = "slice_is_empty")]
    exclude_hosts: &'a [String],
}

fn slice_is_empty(values: &&[String]) -> bool {
    values.is_empty()
}

#[allow(clippy::too_many_arguments)]
pub fn command_native_update_task_target(
    repo_root: &Path,
    task_id: &str,
    hosts: &[String],
    hosts_file: Option<&Path>,
    exclude_hosts: &[String],
    allow_write_control: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        repo_root,
        task_id,
        hosts,
        hosts_file,
        exclude_hosts,
        allow_write_control,
        status_only,
        &SystemCommandRunner,
    )
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
}

fn argument_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    message: impl Into<String>,
) -> ResultEnvelope {
    result(
        repo_root,
        runner,
        "Native task-target replacement rejected before runtime access.",
        vec![Finding::new(
            "fail",
            "native-update-task-target.arguments",
            message.into(),
        )],
    )
}

#[allow(clippy::too_many_arguments)]
fn command_with_runner(
    repo_root: &Path,
    task_id: &str,
    hosts: &[String],
    hosts_file: Option<&Path>,
    exclude_hosts: &[String],
    allow_write_control: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let task_id = match validate_operator_uuid(task_id, "--task-id") {
        Ok(value) => value,
        Err(message) => return argument_failure(repo_root, runner, message),
    };
    let supplied_hosts = trimmed_values(hosts);
    if supplied_hosts.is_empty() == hosts_file.is_none() {
        return argument_failure(
            repo_root,
            runner,
            "provide exactly one of --host or --hosts-file",
        );
    }
    let resolved_hosts = match hosts_file {
        Some(path) => match load_hosts_csv(path) {
            Ok(values) => values,
            Err(message) => return argument_failure(repo_root, runner, message),
        },
        None => supplied_hosts,
    };
    let resolved_exclude_hosts = trimmed_values(exclude_hosts);
    if resolved_hosts.len() > MAX_HOST_ENTRIES {
        return argument_failure(
            repo_root,
            runner,
            format!("hosts must contain at most {MAX_HOST_ENTRIES} values"),
        );
    }
    if resolved_exclude_hosts.len() > MAX_HOST_ENTRIES {
        return argument_failure(
            repo_root,
            runner,
            format!("exclude hosts must contain at most {MAX_HOST_ENTRIES} values"),
        );
    }
    if !allow_write_control {
        return result(
            repo_root,
            runner,
            "Native task-target replacement rejected before runtime access.",
            vec![Finding::new(
                "fail",
                "native-update-task-target.write-control-intent",
                "Replacing a task target requires --allow-write-control because it creates a target and rebinds a task.".into(),
            )],
        );
    }
    let body = match request_body(&resolved_hosts, &resolved_exclude_hosts) {
        Ok(body) => body,
        Err(message) => return argument_failure(repo_root, runner, message),
    };
    let call = match guarded_direct_api_call(
        repo_root,
        &format!("/api/v1/tasks/{task_id}/replace-target"),
        "POST",
        None,
        Some(&body),
        "native-update-task-target.direct-config-shape",
        "native-update-task-target.direct-token-strength",
        runner,
    ) {
        Ok(call) => call,
        Err(findings) => {
            let token_rejection = findings
                .iter()
                .any(|finding| finding.check.ends_with(".direct-token-strength"));
            return result(
                repo_root,
                runner,
                if token_rejection {
                    "Native task-target replacement rejected before runtime access."
                } else {
                    "Direct native API task-target replacement rejected before runtime access."
                },
                findings,
            );
        }
    };
    finish(repo_root, runner, task_id, status_only, call)
}

fn trimmed_values(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn load_hosts_csv(path: &Path) -> Result<Vec<String>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read hosts CSV file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read hosts CSV file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("failed to read hosts CSV file: path is not a regular file".into());
    }
    if metadata.len() > MAX_HOSTS_FILE_BYTES as u64 {
        return Err(format!(
            "failed to read hosts CSV file: file exceeds the {MAX_HOSTS_FILE_BYTES} byte limit"
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_HOSTS_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read hosts CSV file: {error}"))?;
    if bytes.len() > MAX_HOSTS_FILE_BYTES {
        return Err(format!(
            "failed to read hosts CSV file: file exceeds the {MAX_HOSTS_FILE_BYTES} byte limit"
        ));
    }
    let mut hosts = Vec::new();
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes.as_slice());
    for record in reader.records() {
        let record = record.map_err(|error| format!("failed to read hosts CSV file: {error}"))?;
        let Some(host) = record.get(0).map(str::trim).filter(|host| !host.is_empty()) else {
            continue;
        };
        hosts.push(host.to_string());
        if hosts.len() > MAX_HOST_ENTRIES {
            return Err(format!(
                "hosts CSV file must contain at most {MAX_HOST_ENTRIES} nonempty first-column values"
            ));
        }
    }
    if hosts.is_empty() {
        Err("hosts CSV file must contain a nonempty first-column host value".into())
    } else {
        Ok(hosts)
    }
}

fn request_body(hosts: &[String], exclude_hosts: &[String]) -> Result<String, String> {
    let body = serde_json::to_string(&ReplaceTargetBody {
        hosts,
        exclude_hosts,
    })
    .map_err(|error| format!("failed to serialize task-target request: {error}"))?;
    if body.len() > MAX_REQUEST_BODY_BYTES {
        Err(format!(
            "request body JSON exceeds the {MAX_REQUEST_BODY_BYTES} byte limit"
        ))
    } else {
        Ok(body)
    }
}

fn finish(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    task_id: String,
    status_only: bool,
    call: GuardedDirectApiCall,
) -> ResultEnvelope {
    let object = call.parsed.as_ref().and_then(Value::as_object);
    let old_target_id = object
        .and_then(|item| item.get("old_target_id"))
        .and_then(Value::as_str)
        .filter(|value| validate_operator_uuid(value, "old_target_id").is_ok());
    let new_target_id = object
        .and_then(|item| item.get("new_target_id"))
        .and_then(Value::as_str)
        .filter(|value| validate_operator_uuid(value, "new_target_id").is_ok());
    let task_status = object
        .and_then(|item| item.get("status"))
        .and_then(Value::as_str)
        .filter(|value| *value == "replaced");
    let old_target_disposition = object
        .and_then(|item| item.get("old_target_disposition"))
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "trashed" | "retained"));
    let accepted = !call.oversized
        && call.output.success
        && call.http_status == Some(200)
        && object.is_some_and(|item| item.get("task_id").and_then(Value::as_str) == Some(&task_id))
        && old_target_id.is_some()
        && new_target_id.is_some()
        && task_status == Some("replaced")
        && old_target_disposition.is_some();
    let details = json!({
        "task_id": task_id,
        "old_target_id": old_target_id,
        "new_target_id": new_target_id,
        "task_status": task_status,
        "old_target_disposition": old_target_disposition,
        "http_status": call.http_status,
    });
    let mut outcome = result(
        repo_root,
        runner,
        if accepted {
            "Native task-target replacement completed."
        } else {
            "Native task-target replacement failed."
        },
        vec![
            call.config,
            Finding::new(
                if accepted { "pass" } else { "fail" },
                "native-update-task-target.request",
                if accepted {
                    "Native API atomically cloned and rebound the task target without starting a scan.".into()
                } else {
                    "Native API task-target replacement failed or returned an invalid acknowledgement.".into()
                },
            )
            .with_details(details.clone()),
        ],
    )
    .with_details(details);
    if status_only {
        outcome.findings = outcome
            .findings
            .iter()
            .filter(|finding| finding.status != "pass")
            .map(compact_finding)
            .collect();
        if outcome.findings.is_empty() {
            outcome.findings.push(Finding::new(
                "pass",
                "native-update-task-target.status-only",
                "Native task-target replacement acknowledgement summarized.".into(),
            ));
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::os::unix::fs::symlink;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct Runner {
        calls: Mutex<Vec<String>>,
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(program.into());
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }
    }

    fn fixture() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-task-target-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn call(body: Value, status: i64) -> GuardedDirectApiCall {
        GuardedDirectApiCall {
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
                "native-update-task-target.direct-config-shape",
                "valid".into(),
            ),
        }
    }

    fn valid_call() -> GuardedDirectApiCall {
        call(
            json!({
                "task_id": "11111111-1111-4111-8111-111111111111",
                "old_target_id": "22222222-2222-4222-8222-222222222222",
                "new_target_id": "33333333-3333-4333-8333-333333333333",
                "status": "replaced",
                "old_target_disposition": "trashed",
                "secret": "not-retained",
            }),
            200,
        )
    }

    #[test]
    fn arguments_and_write_intent_fail_before_runtime_access() {
        for (task_id, hosts, allow, expected) in [
            (
                "not-a-uuid",
                vec!["192.0.2.10".into()],
                true,
                "native-update-task-target.arguments",
            ),
            (
                "11111111-1111-4111-8111-111111111111",
                Vec::new(),
                true,
                "native-update-task-target.arguments",
            ),
            (
                "11111111-1111-4111-8111-111111111111",
                vec!["192.0.2.10".into()],
                false,
                "native-update-task-target.write-control-intent",
            ),
        ] {
            let runner = Runner::default();
            let result = command_with_runner(
                Path::new("/tmp/no-request"),
                task_id,
                &hosts,
                None,
                &[],
                allow,
                false,
                &runner,
            );
            assert_eq!(result.findings[0].check, expected);
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
    fn csv_uses_trimmed_first_field_and_refuses_links_or_oversize_files() {
        let root = fixture();
        let csv = root.join("hosts.csv");
        std::fs::write(&csv, "\n\"quoted,host\",ignored\n,ignored\n 192.0.2.11 \n").unwrap();
        assert_eq!(
            load_hosts_csv(&csv).unwrap(),
            vec!["quoted,host", "192.0.2.11"]
        );
        let link = root.join("link.csv");
        symlink(&csv, &link).unwrap();
        assert!(load_hosts_csv(&link).is_err());
        let oversized = root.join("oversized.csv");
        std::fs::write(&oversized, vec![b'x'; MAX_HOSTS_FILE_BYTES + 1]).unwrap();
        assert!(load_hosts_csv(&oversized).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn entry_and_body_limits_fail_before_runtime_access() {
        let runner = Runner::default();
        let hosts = (0..=MAX_HOST_ENTRIES)
            .map(|index| format!("host-{index}"))
            .collect::<Vec<_>>();
        let result = command_with_runner(
            Path::new("/tmp/no-request"),
            "11111111-1111-4111-8111-111111111111",
            &hosts,
            None,
            &[],
            true,
            false,
            &runner,
        );
        assert_eq!(
            result.findings[0].check,
            "native-update-task-target.arguments"
        );
        let huge = vec!["x".repeat(MAX_REQUEST_BODY_BYTES)];
        assert!(request_body(&huge, &[]).is_err());
    }

    #[test]
    fn canonical_body_omits_empty_excludes_and_preserves_field_order() {
        assert_eq!(
            request_body(&["192.0.2.10".into()], &[]).unwrap(),
            r#"{"hosts":["192.0.2.10"]}"#
        );
        assert_eq!(
            request_body(
                &["192.0.2.10".into(), "192.0.2.11".into()],
                &["192.0.2.11".into()]
            )
            .unwrap(),
            r#"{"hosts":["192.0.2.10","192.0.2.11"],"exclude_hosts":["192.0.2.11"]}"#
        );
    }

    #[test]
    fn acknowledgement_is_exact_compact_and_non_disclosing() {
        let runner = Runner::default();
        let result = finish(
            Path::new("/srv/YAFVS"),
            &runner,
            "11111111-1111-4111-8111-111111111111".into(),
            true,
            valid_call(),
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.findings[0].check,
            "native-update-task-target.status-only"
        );
        assert_eq!(result.details.as_ref().unwrap()["http_status"], 200);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("not-retained")
        );

        let untrusted = finish(
            Path::new("/srv/YAFVS"),
            &runner,
            "11111111-1111-4111-8111-111111111111".into(),
            false,
            call(
                json!({
                    "task_id": "11111111-1111-4111-8111-111111111111",
                    "old_target_id": "untrusted-old-target",
                    "new_target_id": "untrusted-new-target",
                    "status": "untrusted-status",
                    "old_target_disposition": "untrusted-disposition",
                }),
                200,
            ),
        );
        let serialized = serde_json::to_string(&untrusted).unwrap();
        assert_eq!(untrusted.status, "fail");
        assert!(!serialized.contains("untrusted-"));

        for invalid in [
            call(
                json!({
                    "task_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "old_target_id": "22222222-2222-4222-8222-222222222222",
                    "new_target_id": "33333333-3333-4333-8333-333333333333",
                    "status": "replaced",
                    "old_target_disposition": "trashed",
                }),
                200,
            ),
            call(
                json!({
                    "task_id": "11111111-1111-4111-8111-111111111111",
                    "old_target_id": "not-a-uuid",
                    "new_target_id": "33333333-3333-4333-8333-333333333333",
                    "status": "replaced",
                    "old_target_disposition": "trashed",
                }),
                200,
            ),
            call(
                json!({
                    "task_id": "11111111-1111-4111-8111-111111111111",
                    "old_target_id": "22222222-2222-4222-8222-222222222222",
                    "new_target_id": "33333333-3333-4333-8333-333333333333",
                    "status": "pending",
                    "old_target_disposition": "trashed",
                }),
                200,
            ),
            call(
                json!({
                    "task_id": "11111111-1111-4111-8111-111111111111",
                    "old_target_id": "22222222-2222-4222-8222-222222222222",
                    "new_target_id": "33333333-3333-4333-8333-333333333333",
                    "status": "replaced",
                    "old_target_disposition": "moved",
                }),
                200,
            ),
            call(
                json!({
                    "task_id": "11111111-1111-4111-8111-111111111111",
                    "old_target_id": "22222222-2222-4222-8222-222222222222",
                    "new_target_id": "33333333-3333-4333-8333-333333333333",
                    "status": "replaced",
                    "old_target_disposition": "retained",
                }),
                202,
            ),
        ] {
            assert_eq!(
                finish(
                    Path::new("/srv/YAFVS"),
                    &runner,
                    "11111111-1111-4111-8111-111111111111".into(),
                    false,
                    invalid,
                )
                .status,
                "fail"
            );
        }
    }
}
