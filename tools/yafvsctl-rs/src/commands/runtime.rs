// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::path::Path;
use std::time::Duration;

const RUNTIME_SERVICES: [&str; 3] = ["postgres", "redis-openvas", "mosquitto"];
const APP_SERVICES: [&str; 5] = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"];

pub fn command_runtime_plan(repo_root: &Path) -> ResultEnvelope {
    let root = runtime_dir(repo_root);
    let compose = "compose/dev.yaml";
    let gsad = gsad_hosts()
        .into_iter()
        .map(|host| format!("{host}:19392:9392"))
        .collect::<Vec<_>>();
    let findings = vec![
        Finding::new(
            "pass",
            "runtime.compose",
            "Development Compose file path is defined.".to_string(),
        )
        .with_path(compose),
        Finding::new(
            "pass",
            "runtime.state",
            format!(
                "Persistent runtime state lives outside the repository at {}.",
                root.display()
            ),
        )
        .with_path(&root.display().to_string()),
        Finding::new(
            "pass",
            "runtime.services",
            "Default runtime services are infrastructure: Postgres, scanner Redis, and Mosquitto."
                .to_string(),
        )
        .with_details(json!({ "services": RUNTIME_SERVICES })),
        Finding::new(
            "pass",
            "runtime.app-services",
            "Experimental application services are available behind the app profile.".to_string(),
        )
        .with_details(json!({ "services": APP_SERVICES })),
        Finding::new(
            "pass",
            "runtime.ports",
            "Infrastructure ports are loopback-only; gsad defaults to loopback but can be explicitly bound with YAFVS_GSAD_HOST or YAFVS_GSAD_HOSTS."
                .to_string(),
        )
        .with_details(json!({
            "postgres": "127.0.0.1:15432:5432",
            "mosquitto": "127.0.0.1:1883:1883",
            "gsad": gsad,
        })),
        Finding::new(
            "pass",
            "runtime.scanner-redis",
            "OpenVAS scanner KB Redis uses a runtime Unix socket, not host TCP exposure."
                .to_string(),
        )
        .with_path(&root.join("run/redis-openvas/redis.sock").display().to_string()),
        Finding::new(
            "pass",
            "runtime.feed-cache",
            "Community feed downloads use a persistent host-local cache outside the repository."
                .to_string(),
        )
        .with_path(
            &root
                .join("feed-cache/community/22.04/var-lib")
                .display()
                .to_string(),
        ),
        Finding::new(
            "pass",
            "runtime.feed-generation",
            "Runtime services consume only the journaled active immutable feed generation."
                .to_string(),
        )
        .with_path(&root.join("feed-store/current").display().to_string()),
        Finding::new(
            "pass",
            "runtime.feed-keyring",
            "OSPD and Notus share a persistent feed signature keyring under runtime state."
                .to_string(),
        )
        .with_path(&root.join("state/feed-gnupg").display().to_string()),
        Finding::new(
            "pass",
            "runtime.pg-gvm",
            "Postgres pg-gvm extension initialization is handled by just runtime-init after pg-gvm is built."
                .to_string(),
        ),
        Finding::new(
            "pass",
            "runtime.certs",
            "Certificate initialization is handled by just runtime-certs-init and persists outside the repository."
                .to_string(),
        ),
        Finding::new(
            "warn",
            "runtime.deferred",
            "Scan execution remains guarded and requires scanner capability checks.".to_string(),
        ),
    ];
    make_result(
        metadata(repo_root, "runtime-plan", &SystemCommandRunner),
        "Persistent Docker runtime plan collected.".to_string(),
        findings,
    )
    .with_artifacts(vec![root.display().to_string(), compose.to_string()])
}

pub fn command_down(repo_root: &Path) -> ResultEnvelope {
    command_down_with_runner_and_timeout(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_down_with_runner_and_timeout(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, "down", timeout) {
        Ok(_lock) => {
            let finding = compose_result_finding(
                repo_root,
                runner,
                "compose.down",
                "docker compose down",
                &[
                    "--profile".to_string(),
                    "app".to_string(),
                    "--profile".to_string(),
                    "tools".to_string(),
                    "down".to_string(),
                ],
            );
            make_result(
                metadata(repo_root, "down", runner),
                "Runtime infrastructure shutdown attempted.".to_string(),
                vec![finding],
            )
        }
        Err(error) => shutdown_lock_failure(
            repo_root,
            runner,
            "down",
            "Runtime shutdown stopped while waiting for the feed lifecycle lock.",
            "Runtime shutdown stopped because the feed lifecycle lock failed closed.",
            runtime_dir(repo_root).display().to_string(),
            error,
        ),
    }
}

pub fn command_runtime_app_down(repo_root: &Path) -> ResultEnvelope {
    command_runtime_app_down_with_runner_and_timeout(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_runtime_app_down_with_runner_and_timeout(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    match RuntimeOperationLock::acquire(
        repo_root,
        FEED_ACTIVATION_LOCK,
        "runtime-app-down",
        timeout,
    ) {
        Ok(_lock) => {
            let mut stop_args = vec![
                "--profile".to_string(),
                "app".to_string(),
                "stop".to_string(),
            ];
            stop_args.extend(APP_SERVICES.iter().map(|service| (*service).to_string()));
            let mut rm_args = vec![
                "--profile".to_string(),
                "app".to_string(),
                "rm".to_string(),
                "-f".to_string(),
            ];
            rm_args.extend(APP_SERVICES.iter().map(|service| (*service).to_string()));
            let findings = vec![
                compose_result_finding(
                    repo_root,
                    runner,
                    "compose.app-stop",
                    "docker compose app stop",
                    &stop_args,
                ),
                compose_result_finding(
                    repo_root,
                    runner,
                    "compose.app-rm",
                    "docker compose app rm",
                    &rm_args,
                ),
            ];
            make_result(
                metadata(repo_root, "runtime-app-down", runner),
                "Application runtime shutdown attempted.".to_string(),
                findings,
            )
            .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
        }
        Err(error) => shutdown_lock_failure(
            repo_root,
            runner,
            "runtime-app-down",
            "Application runtime shutdown stopped while waiting for the feed lifecycle lock.",
            "Application runtime shutdown stopped because the feed lifecycle lock failed closed.",
            runtime_lock_dir(repo_root).display().to_string(),
            error,
        ),
    }
}

fn compose_result_finding(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    check: &str,
    message_prefix: &str,
    arguments: &[String],
) -> Finding {
    let command = compose_command(repo_root, arguments);
    let argument_refs = command.iter().map(String::as_str).collect::<Vec<_>>();
    let output = runner.run_with(
        "docker",
        &argument_refs,
        Some(repo_root),
        Some(&runtime_environment(repo_root)),
        None,
    );
    let exit_code = output
        .as_ref()
        .and_then(|output| output.exit_code)
        .unwrap_or(1);
    let tail = output
        .as_ref()
        .map(|output| output_tail(&output.stdout, 80))
        .unwrap_or_default();
    Finding::new(
        if exit_code == 0 { "pass" } else { "fail" },
        check,
        format!("{message_prefix} exit code {exit_code}."),
    )
    .with_details(json!({ "output_tail": tail }))
}

fn shutdown_lock_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    command_name: &str,
    timeout_summary: &str,
    setup_summary: &str,
    artifact: String,
    error: RuntimeLockError,
) -> ResultEnvelope {
    let (summary, finding) = match error {
        RuntimeLockError::Timeout { name, operation, holder } => (
            timeout_summary,
            Finding::new(
                "fail",
                "feed-generation.activation-lock",
                format!(
                    "Timed out waiting for runtime lock '{name}'; another operation may still be running."
                ),
            )
            .with_details(json!({ "operation": operation, "holder": holder })),
        ),
        RuntimeLockError::Setup(error) => (
            setup_summary,
            Finding::new(
                "fail",
                "feed-generation.activation-lock",
                format!("Feed lifecycle lock failed closed: {error}"),
            ),
        ),
    };
    make_result(
        metadata(repo_root, command_name, runner),
        summary.to_string(),
        vec![finding],
    )
    .with_artifacts(vec![artifact])
}

pub fn command_logs(repo_root: &Path, service: Option<&str>, lines: i64) -> ResultEnvelope {
    command_logs_with_runner(repo_root, service, lines, &SystemCommandRunner)
}

fn command_logs_with_runner(
    repo_root: &Path,
    service: Option<&str>,
    lines: i64,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    if lines < 1 {
        return make_result(
            metadata(repo_root, "logs", runner),
            "Runtime logs were not collected.".to_string(),
            vec![
                Finding::new(
                    "fail",
                    "compose.logs.invalid_lines",
                    "--lines must be 1 or greater.".to_string(),
                )
                .with_details(json!({ "service": service, "lines": lines })),
            ],
        );
    }

    let mut arguments = vec!["logs".to_string(), "--tail".to_string(), lines.to_string()];
    if let Some(service) = service {
        arguments.push(service.to_string());
    }
    let command = compose_command(repo_root, &arguments);
    let argument_refs = command.iter().map(String::as_str).collect::<Vec<_>>();
    let output = runner.run_with(
        "docker",
        &argument_refs,
        Some(repo_root),
        Some(&runtime_environment(repo_root)),
        None,
    );
    let exit_code = output
        .as_ref()
        .and_then(|output| output.exit_code)
        .unwrap_or(1);
    let tail = output
        .as_ref()
        .map(|output| output_tail(&output.stdout, lines as usize))
        .unwrap_or_default();
    let mut message = format!("docker compose logs exit code {exit_code}.");
    if !tail.is_empty() {
        message.push('\n');
        message.push_str(&tail.join("\n"));
    }
    make_result(
        metadata(repo_root, "logs", runner),
        "Runtime logs collected.".to_string(),
        vec![
            Finding::new(
                if exit_code == 0 { "pass" } else { "fail" },
                "compose.logs",
                message,
            )
            .with_details(json!({ "service": service, "lines": lines, "output_tail": tail })),
        ],
    )
}

fn gsad_hosts() -> Vec<String> {
    let plural = env::var("YAFVS_GSAD_HOSTS").ok();
    let hosts = split_hosts(plural.as_deref());
    if !hosts.is_empty() {
        return hosts;
    }
    let singular = env::var("YAFVS_GSAD_HOST").ok();
    let hosts = split_hosts(singular.as_deref());
    if hosts.is_empty() {
        vec!["127.0.0.1".to_string()]
    } else {
        hosts
    }
}

fn split_hosts(value: Option<&str>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .filter(|host| seen.insert((*host).to_string()))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvs-runtime-command-{name}-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let repo = root.join("YAFVS");
            fs::create_dir_all(&repo).unwrap();
            Self { root, repo }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RecordedDockerCall {
        args: Vec<String>,
        cwd: Option<PathBuf>,
        environment_supplied: bool,
        timeout: Option<Duration>,
    }

    struct RecordingRunner {
        outputs: Mutex<Vec<ProcessOutput>>,
        calls: Mutex<Vec<RecordedDockerCall>>,
    }

    impl RecordingRunner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn docker_calls(&self) -> MutexGuard<'_, Vec<RecordedDockerCall>> {
            self.calls.lock().unwrap()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".to_string(),
                stderr: String::new(),
            })
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            cwd: Option<&Path>,
            environment: Option<&std::collections::BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            if program != "docker" {
                return self.run(program, args);
            }
            self.calls.lock().unwrap().push(RecordedDockerCall {
                args: args
                    .iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
                cwd: cwd.map(Path::to_path_buf),
                environment_supplied: environment.is_some_and(|environment| {
                    environment.contains_key(&OsString::from("YAFVS_RUNTIME_DIR"))
                }),
                timeout,
            });
            let mut outputs = self.outputs.lock().unwrap();
            (!outputs.is_empty()).then(|| outputs.remove(0))
        }
    }

    fn output(exit_code: i32, lines: usize) -> ProcessOutput {
        ProcessOutput {
            success: exit_code == 0,
            exit_code: Some(exit_code),
            stdout: (0..lines)
                .map(|line| format!("line-{line}"))
                .collect::<Vec<_>>()
                .join("\n"),
            stderr: String::new(),
        }
    }

    struct LogsRunner;

    impl CommandRunner for LogsRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".to_string(),
                stderr: String::new(),
            })
        }

        fn run_with(
            &self,
            program: &str,
            _args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&std::collections::BTreeMap<OsString, OsString>>,
            _timeout: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            if program == "docker" {
                return Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: "one\ntwo\nthree\n".to_string(),
                    stderr: String::new(),
                });
            }
            self.run(program, &[])
        }
    }

    #[test]
    fn host_splitting_preserves_first_seen_order() {
        assert_eq!(
            split_hosts(Some("127.0.0.1, localhost,127.0.0.1")),
            vec!["127.0.0.1", "localhost"]
        );
    }

    #[test]
    fn logs_retain_only_the_requested_tail() {
        let result =
            command_logs_with_runner(Path::new("/srv/YAFVS"), Some("gvmd"), 2, &LogsRunner);
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.findings[0].message,
            "docker compose logs exit code 0.\ntwo\nthree"
        );
        assert_eq!(
            result.findings[0].details,
            Some(json!({ "service": "gvmd", "lines": 2, "output_tail": ["two", "three"] }))
        );
    }

    #[test]
    fn logs_reject_non_positive_line_counts_without_running_docker() {
        let result = command_logs_with_runner(Path::new("/srv/YAFVS"), None, 0, &LogsRunner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "compose.logs.invalid_lines");
    }

    #[test]
    fn down_uses_the_locked_compose_command_and_retains_the_last_eighty_lines() {
        let fixture = Fixture::new("down");
        let runner = RecordingRunner::new(vec![output(0, 100)]);

        let result = command_down_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);

        assert_eq!(result.status, "pass");
        assert_eq!(result.summary, "Runtime infrastructure shutdown attempted.");
        assert_eq!(result.artifacts, Vec::<String>::new());
        assert_eq!(result.findings[0].check, "compose.down");
        assert_eq!(
            result.findings[0].message,
            "docker compose down exit code 0."
        );
        assert_eq!(
            result.findings[0].details,
            Some(
                json!({ "output_tail": (20..100).map(|line| format!("line-{line}")).collect::<Vec<_>>() })
            )
        );
        assert_eq!(
            *runner.docker_calls(),
            vec![RecordedDockerCall {
                args: vec![
                    "compose".into(),
                    "-f".into(),
                    fixture.repo.join("compose/dev.yaml").display().to_string(),
                    "--profile".into(),
                    "app".into(),
                    "--profile".into(),
                    "tools".into(),
                    "down".into(),
                ],
                cwd: Some(fixture.repo.clone()),
                environment_supplied: true,
                timeout: None,
            }]
        );
    }

    #[test]
    fn app_down_removes_services_after_a_stop_failure() {
        let fixture = Fixture::new("app-down");
        let runner = RecordingRunner::new(vec![output(9, 1), output(0, 1)]);

        let result = command_runtime_app_down_with_runner_and_timeout(
            &fixture.repo,
            &runner,
            Duration::ZERO,
        );

        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "Application runtime shutdown attempted.");
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].status, "fail");
        assert_eq!(result.findings[0].check, "compose.app-stop");
        assert_eq!(
            result.findings[0].message,
            "docker compose app stop exit code 9."
        );
        assert_eq!(result.findings[1].status, "pass");
        assert_eq!(result.findings[1].check, "compose.app-rm");
        assert_eq!(
            result.findings[1].message,
            "docker compose app rm exit code 0."
        );
        assert_eq!(
            result.artifacts,
            vec![runtime_dir(&fixture.repo).display().to_string()]
        );
        let calls = runner.docker_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0].args,
            vec![
                "compose",
                "-f",
                &fixture.repo.join("compose/dev.yaml").display().to_string(),
                "--profile",
                "app",
                "stop",
                "gvmd",
                "ospd-openvas",
                "notus-scanner",
                "gsad",
                "yafvs-api",
            ]
        );
        assert_eq!(
            calls[1].args,
            vec![
                "compose",
                "-f",
                &fixture.repo.join("compose/dev.yaml").display().to_string(),
                "--profile",
                "app",
                "rm",
                "-f",
                "gvmd",
                "ospd-openvas",
                "notus-scanner",
                "gsad",
                "yafvs-api",
            ]
        );
        assert!(
            calls
                .iter()
                .all(|call| call.cwd == Some(fixture.repo.clone())
                    && call.environment_supplied
                    && call.timeout.is_none())
        );
    }

    #[test]
    fn down_timeout_does_not_invoke_docker_and_has_the_stable_envelope() {
        let fixture = Fixture::new("down-timeout");
        let _holder = RuntimeOperationLock::acquire(
            &fixture.repo,
            FEED_ACTIVATION_LOCK,
            "holder",
            Duration::ZERO,
        )
        .unwrap();
        let runner = RecordingRunner::new(vec![]);

        let result = command_down_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);

        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime shutdown stopped while waiting for the feed lifecycle lock."
        );
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert_eq!(
            result.findings[0].message,
            "Timed out waiting for runtime lock 'feed-generation-activation'; another operation may still be running."
        );
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["operation"],
            "down"
        );
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["holder"]["operation"],
            "holder"
        );
        assert_eq!(
            result.artifacts,
            vec![runtime_dir(&fixture.repo).display().to_string()]
        );
        assert!(runner.docker_calls().is_empty());
    }

    #[test]
    fn app_down_timeout_does_not_invoke_docker_and_uses_the_lock_dir_artifact() {
        let fixture = Fixture::new("app-down-timeout");
        let _holder = RuntimeOperationLock::acquire(
            &fixture.repo,
            FEED_ACTIVATION_LOCK,
            "holder",
            Duration::ZERO,
        )
        .unwrap();
        let runner = RecordingRunner::new(vec![]);

        let result = command_runtime_app_down_with_runner_and_timeout(
            &fixture.repo,
            &runner,
            Duration::ZERO,
        );

        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Application runtime shutdown stopped while waiting for the feed lifecycle lock."
        );
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert_eq!(
            result.findings[0].message,
            "Timed out waiting for runtime lock 'feed-generation-activation'; another operation may still be running."
        );
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["operation"],
            "runtime-app-down"
        );
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["holder"]["operation"],
            "holder"
        );
        assert_eq!(
            result.artifacts,
            vec![runtime_lock_dir(&fixture.repo).display().to_string()]
        );
        assert!(runner.docker_calls().is_empty());
    }

    #[test]
    fn app_down_lock_setup_failure_fails_closed_without_docker() {
        let fixture = Fixture::new("app-down-lock-setup");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = RecordingRunner::new(vec![]);

        let result = command_runtime_app_down_with_runner_and_timeout(
            &fixture.repo,
            &runner,
            Duration::ZERO,
        );

        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Application runtime shutdown stopped because the feed lifecycle lock failed closed."
        );
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(
            result.findings[0]
                .message
                .starts_with("Feed lifecycle lock failed closed:")
        );
        assert_eq!(
            result.artifacts,
            vec![runtime_lock_dir(&fixture.repo).display().to_string()]
        );
        assert!(runner.docker_calls().is_empty());
    }

    #[test]
    fn down_lock_setup_failure_uses_the_runtime_dir_artifact() {
        let fixture = Fixture::new("down-lock-setup");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = RecordingRunner::new(vec![]);

        let result = command_down_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);

        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime shutdown stopped because the feed lifecycle lock failed closed."
        );
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(
            result.findings[0]
                .message
                .starts_with("Feed lifecycle lock failed closed:")
        );
        assert_eq!(
            result.artifacts,
            vec![runtime_dir(&fixture.repo).display().to_string()]
        );
        assert!(runner.docker_calls().is_empty());
    }

    #[test]
    fn down_reports_a_failed_compose_exit() {
        let fixture = Fixture::new("down-failure");
        let runner = RecordingRunner::new(vec![output(7, 1)]);

        let result = command_down_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);

        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].status, "fail");
        assert_eq!(result.findings[0].check, "compose.down");
        assert_eq!(
            result.findings[0].message,
            "docker compose down exit code 7."
        );
        assert_eq!(
            result.findings[0].details,
            Some(json!({ "output_tail": ["line-0"] }))
        );
    }

    #[test]
    fn down_reports_an_unavailable_docker_process_without_panicking() {
        let fixture = Fixture::new("down-process-unavailable");
        let runner = RecordingRunner::new(vec![]);

        let result = command_down_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);

        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "compose.down");
        assert_eq!(
            result.findings[0].message,
            "docker compose down exit code 1."
        );
        assert_eq!(
            result.findings[0].details,
            Some(json!({ "output_tail": [] }))
        );
        assert_eq!(runner.docker_calls().len(), 1);
    }
}
