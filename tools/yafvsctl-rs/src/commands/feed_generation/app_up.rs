// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Native receipt-pinned application startup; Python remains the stable owner.

use super::artifact_identity::app_runtime_artifact_manifest;
use super::compose_identity::compose_contract_manifest;
use super::deployment::APP_SERVICES;
use super::service_runtime::ServiceRuntime;
use super::{
    command_feed_generation_runtime_guard_with_runner, require_current_app_deployment_snapshot,
};
use crate::commands::common::{compact_finding, metadata, output_tail, runtime_dir};
use crate::commands::compose::runtime_app_environment;
use crate::commands::production_posture::rendered_app_execution_mount_finding;
use crate::commands::runtime_certs::runtime_certificate_findings;
use crate::commands::runtime_feed_keyring::command_runtime_feed_keyring_init_with_runner;
use crate::commands::runtime_init::command_runtime_init_with;
use crate::commands::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
};
use crate::commands::runtime_scanner_redis::command_unlocked as scanner_redis_unlocked;
use crate::commands::runtime_setup::ensure_runtime_setup;
use crate::commands::up::command_up_with_runner;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "runtime-app-up";
const APP_START_TIMEOUT: Duration = Duration::from_secs(900);
const SOCKET_WAIT_ATTEMPTS: usize = 20;

pub fn command_runtime_app_up(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    let mut sleep = std::thread::sleep;
    command_with(
        repo_root,
        status_only,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
        &mut sleep,
    )
}

fn command_with(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
    timeout: Duration,
    sleep: &mut dyn FnMut(Duration),
) -> ResultEnvelope {
    match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
        Ok(_lock) => compact_if_requested(command_unlocked(repo_root, runner, sleep), status_only),
        Err(error) => compact_if_requested(lock_failure(repo_root, runner, error), status_only),
    }
}

fn command_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    sleep: &mut dyn FnMut(Duration),
) -> ResultEnvelope {
    let mut findings = ensure_runtime_setup(repo_root, runner);
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Application runtime startup stopped at safe runtime setup.",
            findings,
        );
    }
    let environment = match runtime_app_environment(repo_root) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.secrets",
                format!("Application runtime secrets could not be prepared safely: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Application runtime startup stopped at safe runtime setup.",
                findings,
            );
        }
    };
    let deployment = match require_current_app_deployment_snapshot(repo_root, runner, &environment)
    {
        Ok(deployment) => deployment,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.app-deployment-receipt",
                error,
            ));
            return result(
                repo_root,
                runner,
                "Application runtime startup stopped before app startup.",
                findings,
            );
        }
    };
    let receipt = deployment.receipt;
    let image_ids = deployment.image_ids;
    findings.push(Finding::new("pass", "runtime.app-deployment-receipt", "Prepared receipt retains all five exact image IDs and current artifact/Compose identity.".into()).with_details(json!({"service_count": image_ids.len()})));
    let runtime = ServiceRuntime::new(repo_root, runner, &environment, &image_ids);
    findings.push(base_compose_finding(
        &runtime,
        &["config".into(), "--quiet".into()],
        "compose.config",
        "Compose config validation",
        Duration::from_secs(120),
    ));
    findings.push(rendered_app_execution_mount_finding(
        repo_root,
        &environment,
        runner,
    ));
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Application runtime startup stopped at mount prerequisites.",
            findings,
        );
    }

    append_result(
        &mut findings,
        "runtime.infrastructure",
        command_up_with_runner(repo_root, runner),
    );
    findings.push(base_compose_finding(
        &runtime,
        &[
            "up".into(),
            "-d".into(),
            "--no-deps".into(),
            "--force-recreate".into(),
            "--wait".into(),
            "--wait-timeout".into(),
            "60".into(),
            "mosquitto".into(),
        ],
        "compose.mqtt-broker-refresh",
        "Refresh mosquitto",
        Duration::from_secs(120),
    ));
    let database = command_runtime_init_with(repo_root, runner, sleep);
    append_result(&mut findings, "runtime.database-init", database);
    append_result(
        &mut findings,
        "feed-generation.current",
        command_feed_generation_runtime_guard_with_runner(repo_root, false, runner),
    );
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Application runtime startup stopped before app startup because infrastructure or feed attestation failed.",
            findings,
        );
    }

    append_result(
        &mut findings,
        "runtime.scanner-redis",
        scanner_redis_unlocked(repo_root, runner, false, Some(&image_ids), 20, sleep),
    );
    append_result(
        &mut findings,
        "runtime.feed-keyring",
        command_runtime_feed_keyring_init_with_runner(repo_root, runner),
    );
    for mut finding in runtime_certificate_findings(repo_root) {
        if finding.status != "pass" {
            finding.status = "fail".into();
        }
        findings.push(finding);
    }
    findings.extend(gsad_transition_findings(repo_root, runner, &environment));
    findings.push(compose_finding(
        &runtime,
        &[
            "--profile".into(),
            "app".into(),
            "config".into(),
            "--quiet".into(),
        ],
        "compose.app-image-override",
        "Pinned application image Compose validation",
        Duration::from_secs(120),
    ));
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Application runtime startup stopped at prerequisites.",
            findings,
        );
    }
    findings.extend(identity_findings(
        repo_root,
        runner,
        &environment,
        &receipt,
        &image_ids,
        "before-start",
    ));
    if failed(&findings) {
        return result(
            repo_root,
            runner,
            "Application runtime startup stopped because deployment identity changed before container start.",
            findings,
        );
    }
    match runtime.start_pinned_services(&APP_SERVICES, "compose.app-up", APP_START_TIMEOUT) {
        Ok(outcome) => findings.extend(outcome.findings),
        Err(error) => findings.push(Finding::new("fail", "compose.app-up", error)),
    }
    findings.extend(identity_findings(
        repo_root,
        runner,
        &environment,
        &receipt,
        &image_ids,
        "after-start",
    ));
    let drifted = findings
        .iter()
        .any(|finding| finding.check.ends_with("after-start") && finding.status == "fail");
    if drifted {
        match runtime.stop_apps("runtime.app.identity-failure-stop") {
            Ok(outcome) => findings.extend(outcome.findings),
            Err(error) => findings.push(Finding::new(
                "fail",
                "runtime.app.identity-failure-stop",
                error,
            )),
        }
        return result(
            repo_root,
            runner,
            "Application deployment identity changed during startup; application services were stopped.",
            findings,
        );
    }
    findings.extend(service_evidence(&runtime));
    findings.push(gvmd_control_socket_finding(repo_root, sleep));
    result(
        repo_root,
        runner,
        "Application runtime startup attempted.",
        findings,
    )
}

fn base_compose_finding(
    runtime: &ServiceRuntime<'_>,
    arguments: &[String],
    check: &str,
    label: &str,
    timeout: Duration,
) -> Finding {
    process_finding(
        runtime.run_compose(arguments, timeout).as_ref(),
        check,
        label,
    )
}

fn identity_findings(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    receipt: &serde_json::Value,
    images: &BTreeMap<String, String>,
    phase: &str,
) -> Vec<Finding> {
    let artifact_ok =
        app_runtime_artifact_manifest(repo_root).ok().as_ref() == receipt.get("runtime_artifacts");
    let compose_ok = compose_contract_manifest(repo_root, runner, environment, images)
        .ok()
        .as_ref()
        == receipt.get("compose_contract");
    vec![
        Finding::new(
            if artifact_ok { "pass" } else { "fail" },
            &format!("runtime.app.artifacts-{phase}"),
            if artifact_ok {
                "Runtime artifacts retain the prepared identity."
            } else {
                "Runtime artifacts differ from the original prepared receipt."
            }
            .into(),
        ),
        Finding::new(
            if compose_ok { "pass" } else { "fail" },
            &format!("runtime.app.compose-{phase}"),
            if compose_ok {
                "Rendered app Compose contract retains the prepared identity."
            } else {
                "Rendered app Compose contract differs from the original prepared receipt."
            }
            .into(),
        ),
    ]
}

fn gsad_transition_findings(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> Vec<Finding> {
    let command = crate::commands::compose::compose_command(
        repo_root,
        &["port".into(), "gsad".into(), "9392".into()],
    );
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    let observed = runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(environment),
            Some(Duration::from_secs(120)),
        )
        .filter(|output| output.success);
    let Some(observed) = observed else {
        return Vec::new();
    };
    let observed_hosts = observed
        .stdout
        .lines()
        .filter_map(published_host)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let external_hosts = observed_hosts
        .iter()
        .filter(|host| {
            let normalized = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
            !matches!(normalized.as_str(), "localhost" | "::1") && !normalized.starts_with("127.")
        })
        .cloned()
        .collect::<Vec<_>>();
    let requested = environment
        .get(&OsString::from("YAFVS_GSAD_HOSTS"))
        .or_else(|| environment.get(&OsString::from("YAFVS_GSAD_HOST")))
        .and_then(|value| value.to_str())
        .unwrap_or("127.0.0.1");
    let keeps_external = requested.split(',').any(|host| {
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        !matches!(host.as_str(), "localhost" | "::1") && !host.starts_with("127.")
    });
    if !external_hosts.is_empty() && !keeps_external {
        vec![
            Finding::new(
                "warn",
                "gsad.host-binding.transition",
                "gsad is currently published externally but this runtime-app-up request will only retain loopback bindings; set YAFVS_GSAD_HOSTS to retain intended access.".into(),
            )
            .with_details(json!({
                "current_published_hosts": observed_hosts,
                "requested_hosts": requested.split(',').map(str::trim).filter(|host| !host.is_empty()).collect::<Vec<_>>(),
                "lost_external_hosts": external_hosts,
                "host_env": "YAFVS_GSAD_HOST",
                "hosts_env": "YAFVS_GSAD_HOSTS",
            })),
        ]
    } else {
        Vec::new()
    }
}

fn published_host(binding: &str) -> Option<&str> {
    let (host, port) = binding.trim().rsplit_once(':')?;
    (port == "19392" && !host.is_empty()).then_some(host)
}

fn compose_finding(
    runtime: &ServiceRuntime<'_>,
    arguments: &[String],
    check: &str,
    label: &str,
    timeout: Duration,
) -> Finding {
    process_finding(
        runtime.run_pinned_compose(arguments, timeout).as_ref(),
        check,
        label,
    )
}

fn process_finding(output: Result<&ProcessOutput, &String>, check: &str, label: &str) -> Finding {
    let exit = output.map(|item| item.exit_code.unwrap_or(1)).unwrap_or(1);
    let tail = output
        .map(|item| output_tail(&item.stdout, 40))
        .unwrap_or_default();
    Finding::new(
        if exit == 0 { "pass" } else { "fail" },
        check,
        format!("{label} exit code {exit}."),
    )
    .with_details(json!({"output_tail": tail}))
}

fn append_result(findings: &mut Vec<Finding>, check: &str, result: ResultEnvelope) {
    findings.push(
        Finding::new(&result.status, check, result.summary)
            .with_details(json!({"status": result.status})),
    );
}

fn failed(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn service_evidence(runtime: &ServiceRuntime<'_>) -> Vec<Finding> {
    APP_SERVICES
        .iter()
        .map(|service| match runtime.app_service_running(service) {
            Ok(true) => Finding::new(
                "pass",
                "runtime.app.running",
                format!("{service} container is running."),
            )
            .with_details(json!({"service": service, "logs_tail": []})),
            Ok(false) => Finding::new(
                "warn",
                "runtime.app.running",
                format!("{service} container is not running."),
            )
            .with_details(json!({
                "service": service,
                "logs_tail": runtime.app_service_log_tail(service, 80).unwrap_or_default(),
            })),
            Err(error) => Finding::new(
                "fail",
                "runtime.app.running",
                format!("{service} container state could not be verified: {error}"),
            )
            .with_details(json!({"service": service, "logs_tail": []})),
        })
        .collect()
}

fn gvmd_control_socket_finding(repo_root: &Path, sleep: &mut dyn FnMut(Duration)) -> Finding {
    gvmd_control_socket_finding_with_attempts(repo_root, sleep, SOCKET_WAIT_ATTEMPTS)
}

fn gvmd_control_socket_finding_with_attempts(
    repo_root: &Path,
    sleep: &mut dyn FnMut(Duration),
    attempts: usize,
) -> Finding {
    let path = runtime_dir(repo_root).join("run/gvmd-control/yafvs-control.sock");
    let check = || {
        std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_socket())
            && UnixStream::connect(&path).is_ok()
    };
    let mut ready = check();
    for _ in 0..attempts {
        if ready {
            break;
        }
        sleep(Duration::from_secs(1));
        ready = check();
    }
    Finding::new(
        if ready { "pass" } else { "fail" },
        "runtime.gvmd-control-socket",
        if ready {
            "gvmd native control Unix socket is live."
        } else {
            "gvmd native control Unix socket did not become live within 20 seconds."
        }
        .into(),
    )
    .with_path(&path.display().to_string())
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
    let finding = match error {
        RuntimeLockError::Timeout { name, operation, holder } => Finding::new("fail", "feed-generation.activation-lock", format!("Timed out waiting for runtime lock '{name}'; another operation may still be running.")).with_details(json!({"operation": operation, "holder": holder})),
        RuntimeLockError::Setup(error) => Finding::new("fail", "feed-generation.activation-lock", format!("Feed lifecycle lock failed closed: {error}")),
    };
    result(
        repo_root,
        runner,
        "Application runtime startup stopped while waiting for the feed lifecycle lock.",
        vec![finding],
    )
}

fn compact_if_requested(mut result: ResultEnvelope, status_only: bool) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    let findings = std::mem::take(&mut result.findings);
    let non_pass = findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let checks = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.check.as_str(),
                "compose.config"
                    | "production.app-execution-mounts"
                    | "feed-generation.current"
                    | "runtime.infrastructure"
                    | "runtime.database-init"
                    | "runtime.scanner-redis"
                    | "runtime.feed-keyring"
                    | "compose.app-up"
                    | "runtime.gvmd-control-socket"
            )
        })
        .map(|finding| (finding.check.clone(), finding.status.clone()))
        .collect::<BTreeMap<_, _>>();
    let services = findings
        .iter()
        .filter(|finding| finding.check == "runtime.app.running")
        .filter_map(|finding| {
            finding
                .details
                .as_ref()
                .and_then(|details| details["service"].as_str())
                .map(|service| (service.to_owned(), finding.status.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    result.details = Some(
        json!({"finding_count": findings.len(), "non_pass_count": non_pass.len(), "artifact_count": result.artifacts.len(), "important_checks": checks, "service_status": services}),
    );
    result.findings = if non_pass.is_empty() {
        vec![Finding::new(
            "pass",
            "runtime-app-up.status-only",
            "Application runtime startup passed; no non-pass findings.".into(),
        )]
    } else {
        non_pass
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use crate::result::Metadata;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("yafvsctl-app-up-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let repo = root.join("YAFVS");
            fs::create_dir_all(repo.join("compose")).unwrap();
            fs::write(repo.join("compose/dev.yaml"), "services: {}\n").unwrap();
            Self { root, repo }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct Runner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }

        fn run_with(
            &self,
            program: &str,
            arguments: &[&str],
            _: Option<&Path>,
            _: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program.to_owned())
                    .chain(arguments.iter().map(|argument| (*argument).to_owned()))
                    .collect(),
            );
            None
        }
    }

    fn envelope(findings: Vec<Finding>) -> ResultEnvelope {
        ResultEnvelope {
            status: "fail".into(),
            summary: "test".into(),
            findings,
            artifacts: vec!["/runtime".into()],
            metadata: Metadata {
                command: COMMAND.into(),
                generated_at: "2026-07-20T00:00:00+00:00".into(),
                repo_root: "/repo".into(),
                head: None,
            },
            details: None,
        }
    }

    #[test]
    fn status_only_keeps_counts_important_checks_service_status_and_non_pass_findings() {
        let result = compact_if_requested(
            envelope(vec![
                Finding::new("pass", "compose.config", "ok".into()),
                Finding::new("warn", "runtime.app.running", "not running".into())
                    .with_details(json!({"service": "gvmd", "logs_tail": ["bounded"]})),
            ]),
            true,
        );
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check, "runtime.app.running");
        let details = result.details.unwrap();
        assert_eq!(details["finding_count"], 2);
        assert_eq!(details["non_pass_count"], 1);
        assert_eq!(details["important_checks"]["compose.config"], "pass");
        assert_eq!(details["service_status"]["gvmd"], "warn");
    }

    #[test]
    fn process_evidence_retains_only_a_bounded_tail() {
        let output = ProcessOutput {
            success: false,
            exit_code: Some(1),
            stdout: (0..80)
                .map(|line| format!("line-{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            stderr: String::new(),
        };
        let finding = process_finding(Ok(&output), "compose.app-up", "app up");
        assert_eq!(
            finding.details.unwrap()["output_tail"]
                .as_array()
                .unwrap()
                .len(),
            40
        );
    }

    #[test]
    fn unsafe_runtime_setup_stops_before_secrets_or_processes() {
        let fixture = Fixture::new("unsafe-setup");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = Runner::default();
        let mut sleep = |_| {};
        let result = command_with(&fixture.repo, false, &runner, Duration::ZERO, &mut sleep);
        assert_eq!(result.status, "fail");
        assert!(runner.calls.lock().unwrap().is_empty());
        assert!(!fixture.root.join("YAFVS-runtime/state/secrets").exists());
    }

    #[test]
    fn feed_lock_contention_stops_before_processes() {
        let fixture = Fixture::new("feed-lock");
        let _holder = RuntimeOperationLock::acquire(
            &fixture.repo,
            FEED_ACTIVATION_LOCK,
            "test-holder",
            Duration::ZERO,
        )
        .unwrap();
        let runner = Runner::default();
        let mut sleep = |_| {};
        let result = command_with(&fixture.repo, false, &runner, Duration::ZERO, &mut sleep);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn missing_control_socket_waits_for_the_exact_bound() {
        let fixture = Fixture::new("socket");
        let mut waits = Vec::new();
        let finding = gvmd_control_socket_finding_with_attempts(
            &fixture.repo,
            &mut |delay| waits.push(delay),
            3,
        );
        assert_eq!(finding.status, "fail");
        assert_eq!(waits, vec![Duration::from_secs(1); 3]);
    }

    #[test]
    fn published_gsad_hosts_require_the_expected_host_port() {
        assert_eq!(published_host("127.0.0.1:19392"), Some("127.0.0.1"));
        assert_eq!(published_host("[::1]:19392"), Some("[::1]"));
        assert_eq!(published_host("0.0.0.0:9392"), None);
        assert_eq!(published_host("--format:19392"), Some("--format"));
    }
}
