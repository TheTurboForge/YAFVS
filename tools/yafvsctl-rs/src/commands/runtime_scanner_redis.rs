// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guarded scanner Redis and OpenVAS runtime-configuration initialization.

use super::common::{metadata, runtime_dir};
use super::compose::{compose_command, runtime_app_environment, runtime_lifecycle_environment};
use super::feed_generation::{
    pinned_app_compose_command, prepare_openvas_runtime_config, require_current_app_deployment,
};
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use super::runtime_setup::ensure_runtime_setup;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "runtime-scanner-redis-init";
const REDIS_SOCKET: &str = "/run/redis-openvas/redis.sock";
const READY_ATTEMPTS: usize = 20;
const READY_INTERVAL: Duration = Duration::from_secs(1);

pub fn command_runtime_scanner_redis_init(repo_root: &Path) -> ResultEnvelope {
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
    match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
        Ok(_lock) => {
            let mut sleep = std::thread::sleep;
            command_unlocked(repo_root, runner, true, None, READY_ATTEMPTS, &mut sleep)
        }
        Err(error) => lock_failure(repo_root, runner, error),
    }
}

pub(crate) fn command_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    probe_openvas: bool,
    prepared_image_ids: Option<&BTreeMap<String, String>>,
    ready_attempts: usize,
    sleep: &mut dyn FnMut(Duration),
) -> ResultEnvelope {
    let mut findings = ensure_runtime_setup(repo_root, runner);
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Scanner Redis initialization stopped before service startup.",
            findings,
            None,
        );
    }
    let environment = match runtime_lifecycle_environment(repo_root) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.mqtt-secrets",
                format!("Runtime MQTT secrets could not be prepared: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Scanner Redis initialization stopped before service startup.",
                findings,
                None,
            );
        }
    };
    let config = run_compose(
        repo_root,
        runner,
        &environment,
        &["config".into(), "--quiet".into()],
        None,
    );
    findings.push(process_finding(
        &config,
        "compose.config",
        "Compose config validation",
        Some("compose/dev.yaml"),
    ));
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Scanner Redis initialization stopped before service startup.",
            findings,
            None,
        );
    }

    let up = run_compose(
        repo_root,
        runner,
        &environment,
        &["up".into(), "-d".into(), "redis-openvas".into()],
        None,
    );
    findings.push(process_finding(
        &up,
        "redis-openvas.up",
        "docker compose up redis-openvas",
        None,
    ));
    if !process_succeeded(&up) {
        return result(
            repo_root,
            runner,
            "Scanner Redis initialization stopped at service startup.",
            findings,
            None,
        );
    }

    let mut ping = None;
    let attempts = ready_attempts.max(1);
    for attempt in 0..attempts {
        if container_running(repo_root, runner, &environment, "redis-openvas") {
            ping = run_compose(
                repo_root,
                runner,
                &environment,
                &[
                    "exec".into(),
                    "-T".into(),
                    "redis-openvas".into(),
                    "redis-cli".into(),
                    "-s".into(),
                    REDIS_SOCKET.into(),
                    "ping".into(),
                ],
                Some(Duration::from_secs(120)),
            );
            if ping.as_ref().is_some_and(|output| {
                output.success && output.stdout.lines().any(|line| line.trim() == "PONG")
            }) {
                break;
            }
        }
        if attempt + 1 < attempts {
            sleep(READY_INTERVAL);
        }
    }
    let ready = ping.as_ref().is_some_and(|output| {
        output.success && output.stdout.lines().any(|line| line.trim() == "PONG")
    });
    findings.push(
        Finding::new(
            if ready { "pass" } else { "fail" },
            "redis-openvas.ready",
            format!(
                "scanner Redis Unix socket ping exit code {}.",
                ping.as_ref()
                    .and_then(|output| output.exit_code)
                    .map_or_else(|| "unavailable".to_string(), |code| code.to_string())
            ),
        )
        .with_path(
            &runtime_dir(repo_root)
                .join("run/redis-openvas/redis.sock")
                .display()
                .to_string(),
        )
        .with_details(json!({
            "response": if ready { "PONG" } else { "" },
        })),
    );

    let openvas_config = match prepare_openvas_runtime_config(repo_root) {
        Ok(config) => {
            findings.push(
                Finding::new(
                    "pass",
                    "openvas.config",
                    "OpenVAS runtime config points db_address and feed plugin paths to runtime state."
                        .into(),
                )
                .with_path(&config_artifact(repo_root, &config.path))
                .with_details(json!({ "mqtt_secret_created": config.secret_created })),
            );
            config
        }
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "openvas.config",
                    format!(
                        "OpenVAS runtime config could not be prepared safely: {}",
                        error.reason()
                    ),
                )
                .with_path(&error.path().display().to_string()),
            );
            return result(
                repo_root,
                runner,
                "Scanner Redis initialization stopped while preparing OpenVAS configuration.",
                findings,
                None,
            );
        }
    };
    if !probe_openvas {
        findings.push(Finding::new(
            "pass",
            "openvas.config-probe",
            "OpenVAS settings probe deferred until app services are built and started.".into(),
        ));
        return result(
            repo_root,
            runner,
            completion_summary(&findings),
            findings,
            Some(&openvas_config.path),
        );
    }

    let app_environment = match runtime_app_environment(repo_root) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "compose.app-images",
                format!("Application runtime environment is unavailable: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Scanner Redis initialization stopped because a verified application deployment receipt is unavailable.",
                findings,
                Some(&openvas_config.path),
            );
        }
    };
    let discovered_image_ids;
    let image_ids = if let Some(image_ids) = prepared_image_ids {
        findings.push(Finding::new(
            "pass",
            "compose.app-images",
            "OpenVAS settings probe uses caller-verified prepared application images without building."
                .into(),
        ));
        image_ids
    } else {
        discovered_image_ids = match require_current_app_deployment(
            repo_root,
            runner,
            &app_environment,
        ) {
            Ok(image_ids) => {
                findings.push(Finding::new(
                    "pass",
                    "compose.app-images",
                    "OpenVAS settings probe uses prepared application images without building."
                        .into(),
                ));
                image_ids
            }
            Err(error) => {
                findings.push(Finding::new("fail", "compose.app-images", error));
                return result(
                    repo_root,
                    runner,
                    "Scanner Redis initialization stopped because a verified application deployment receipt is unavailable.",
                    findings,
                    Some(&openvas_config.path),
                );
            }
        };
        &discovered_image_ids
    };
    let operation = [
        "--profile",
        "app",
        "run",
        "--rm",
        "-T",
        "--pull",
        "never",
        "ospd-openvas",
        "openvas",
        "-s",
    ]
    .map(str::to_owned);
    let command = match pinned_app_compose_command(repo_root, image_ids, &operation) {
        Ok(command) => command,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "compose.app-images",
                format!("Pinned OpenVAS settings command could not be prepared: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Scanner Redis initialization stopped before the OpenVAS settings probe.",
                findings,
                Some(&openvas_config.path),
            );
        }
    };
    let settings = run_docker_command(
        repo_root,
        runner,
        &app_environment,
        &command,
        Some(Duration::from_secs(300)),
    );
    findings.extend(openvas_settings_findings(&settings));
    result(
        repo_root,
        runner,
        completion_summary(&findings),
        findings,
        Some(&openvas_config.path),
    )
}

fn openvas_settings_findings(output: &Option<ProcessOutput>) -> Vec<Finding> {
    let exit_code = output
        .as_ref()
        .and_then(|output| output.exit_code)
        .unwrap_or(1);
    let lines = output
        .as_ref()
        .map(|output| output.stdout.lines().collect::<Vec<_>>())
        .unwrap_or_default();
    let db_lines = prefixed_lines(&lines, "db_address");
    let plugin_lines = prefixed_lines(&lines, "plugins_folder");
    let include_lines = prefixed_lines(&lines, "include_folders");
    let success = output.as_ref().is_some_and(|output| output.success);
    [
        (
            "openvas.db_address",
            "db_address",
            db_lines,
            "/runtime/run/redis-openvas/redis.sock",
        ),
        (
            "openvas.plugins_folder",
            "plugins_folder",
            plugin_lines,
            "/runtime/feeds/openvas/plugins",
        ),
        (
            "openvas.include_folders",
            "include_folders",
            include_lines,
            "/runtime/feeds/openvas/plugins",
        ),
    ]
    .into_iter()
    .map(|(check, label, relevant, expected)| {
        let passed = success && relevant.iter().any(|line| line.contains(expected));
        Finding::new(
            if passed { "pass" } else { "fail" },
            check,
            format!("openvas -s runtime {label} check exit code {exit_code}."),
        )
        .with_details(json!({ format!("{label}_lines"): relevant }))
    })
    .collect()
}

fn prefixed_lines(lines: &[&str], prefix: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|line| line.starts_with(prefix))
        .take(20)
        .map(|line| (*line).to_string())
        .collect()
}

fn container_running(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    service: &str,
) -> bool {
    let query = run_compose(
        repo_root,
        runner,
        environment,
        &["ps".into(), "-q".into(), service.into()],
        Some(Duration::from_secs(30)),
    );
    let Some(identifier) = query
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .map(str::to_owned)
        })
        .filter(|identifier| {
            (12..=64).contains(&identifier.len())
                && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    else {
        return false;
    };
    runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &identifier],
            Some(repo_root),
            Some(environment),
            Some(Duration::from_secs(30)),
        )
        .is_some_and(|output| output.success && output.stdout.trim() == "true")
}

fn run_compose(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    operation: &[String],
    timeout: Option<Duration>,
) -> Option<ProcessOutput> {
    let command = compose_command(repo_root, operation);
    run_docker_command(repo_root, runner, environment, &command, timeout)
}

fn run_docker_command(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    command: &[String],
    timeout: Option<Duration>,
) -> Option<ProcessOutput> {
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with(
        "docker",
        &arguments,
        Some(repo_root),
        Some(environment),
        timeout,
    )
}

fn process_finding(
    output: &Option<ProcessOutput>,
    check: &str,
    label: &str,
    path: Option<&str>,
) -> Finding {
    let exit_code = output
        .as_ref()
        .and_then(|output| output.exit_code)
        .unwrap_or(1);
    let mut finding = Finding::new(
        if exit_code == 0 { "pass" } else { "fail" },
        check,
        format!("{label} exit code {exit_code}."),
    );
    if let Some(path) = path {
        finding = finding.with_path(path);
    }
    finding
}

fn completion_summary(findings: &[Finding]) -> &'static str {
    if has_failure(findings) {
        "Scanner Redis initialization completed with failed checks."
    } else {
        "Scanner Redis initialization completed."
    }
}

fn process_succeeded(output: &Option<ProcessOutput>) -> bool {
    output.as_ref().is_some_and(|output| output.success)
}

fn has_failure(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn config_artifact(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(runtime_dir(repo_root))
        .unwrap_or(path)
        .display()
        .to_string()
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    config: Option<&Path>,
) -> ResultEnvelope {
    let mut artifacts = vec![runtime_dir(repo_root).display().to_string()];
    if let Some(config) = config {
        artifacts.push(config_artifact(repo_root, config));
    }
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_artifacts(artifacts)
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
            format!(
                "Timed out waiting for runtime lock {name:?}; another operation may still be running."
            ),
            json!({"operation": operation, "holder": holder}),
        ),
        RuntimeLockError::Setup(message) => (
            format!("Runtime feed lifecycle lock failed closed: {message}."),
            json!({}),
        ),
    };
    make_result(
        metadata(repo_root, COMMAND, runner),
        "Scanner Redis initialization stopped while waiting for the feed lifecycle lock.".into(),
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message).with_details(details),
        ],
    )
    .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Mutex;

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-runtime-scanner-redis-{name}-{}",
                std::process::id()
            ));
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

    #[derive(Clone, Debug)]
    struct Call {
        args: Vec<String>,
        environment: BTreeMap<OsString, OsString>,
    }

    struct Runner {
        calls: Mutex<Vec<Call>>,
        ready: bool,
        config_success: bool,
    }

    impl Runner {
        fn passing() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                ready: true,
                config_success: true,
            }
        }

        fn response(&self, args: &[&str]) -> ProcessOutput {
            let joined = args.join(" ");
            if joined.ends_with("config --quiet") {
                return output(if self.config_success { 0 } else { 1 }, "");
            }
            if joined.contains(" ps -q redis-openvas") {
                return output(0, &format!("{}\n", "a".repeat(64)));
            }
            if joined.starts_with("inspect -f") {
                return output(0, if self.ready { "true\n" } else { "false\n" });
            }
            if joined.contains("redis-cli") {
                return output(
                    if self.ready { 0 } else { 1 },
                    if self.ready { "PONG\n" } else { "" },
                );
            }
            if joined.contains("ospd-openvas openvas -s") {
                return output(
                    0,
                    "db_address = /runtime/run/redis-openvas/redis.sock\nplugins_folder = /runtime/feeds/openvas/plugins\ninclude_folders = /runtime/feeds/openvas/plugins\n",
                );
            }
            output(0, "")
        }
    }

    fn prepared_images() -> BTreeMap<String, String> {
        ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"]
            .into_iter()
            .enumerate()
            .map(|(index, service)| {
                (
                    service.to_owned(),
                    format!("sha256:{}", format!("{:x}", index + 1).repeat(64)),
                )
            })
            .collect()
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| output(0, "deadbee\n"))
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            if program != "docker" {
                return self.run(program, args);
            }
            self.calls.lock().unwrap().push(Call {
                args: args
                    .iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
                environment: environment.cloned().unwrap_or_default(),
            });
            Some(self.response(args))
        }
    }

    #[test]
    fn prepared_images_probe_in_exact_order_without_receipt_discovery() {
        let fixture = Fixture::new("prepared-probe");
        let runner = Runner::passing();
        let images = prepared_images();
        let result = command_unlocked(&fixture.repo, &runner, true, Some(&images), 1, &mut |_| {});
        assert_eq!(result.status, "pass", "{:?}", result.findings);
        let calls = runner.calls.lock().unwrap();
        let operations = calls
            .iter()
            .map(|call| call.args.join(" "))
            .collect::<Vec<_>>();
        assert_eq!(operations.len(), 6, "{operations:#?}");
        assert!(operations[0].ends_with("config --quiet"));
        assert!(operations[1].ends_with("up -d redis-openvas"));
        assert!(operations[2].ends_with("ps -q redis-openvas"));
        assert!(operations[3].starts_with("inspect -f"));
        assert!(operations[4].contains("redis-cli -s /run/redis-openvas/redis.sock ping"));
        assert!(operations[5].contains("--pull never ospd-openvas openvas -s"));
    }

    fn output(code: i32, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success: code == 0,
            exit_code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn process_findings_do_not_echo_untrusted_command_output() {
        let secret = "private-command-output";
        let finding = process_finding(
            &Some(output(1, secret)),
            "compose.config",
            "Compose config validation",
            None,
        );
        assert!(!serde_json::to_string(&finding).unwrap().contains(secret));
    }

    #[test]
    fn unsafe_runtime_secret_fails_before_docker_without_exposing_value() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("unsafe-secret");
        let setup_runner = Runner::passing();
        let setup = command_unlocked(&fixture.repo, &setup_runner, false, None, 1, &mut |_| {});
        assert_eq!(setup.status, "pass");
        let secret = fixture
            .root
            .join("YAFVS-runtime/secrets/mqtt-openvas-password");
        fs::remove_file(&secret).unwrap();
        let target = fixture.root.join("outside-secret");
        fs::write(&target, "do-not-expose").unwrap();
        symlink(&target, &secret).unwrap();

        let runner = Runner::passing();
        let result = command_unlocked(&fixture.repo, &runner, false, None, 1, &mut |_| {});
        assert_eq!(result.status, "fail");
        assert!(runner.calls.lock().unwrap().is_empty());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-expose")
        );
    }

    #[test]
    fn lock_contention_times_out_before_docker() {
        let fixture = Fixture::new("lock-contention");
        let _holder = RuntimeOperationLock::acquire(
            &fixture.repo,
            FEED_ACTIVATION_LOCK,
            "test-holder",
            Duration::ZERO,
        )
        .unwrap();
        let runner = Runner::passing();
        let result = command_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn lifecycle_managed_path_starts_exact_service_and_writes_private_config() {
        let fixture = Fixture::new("success");
        let runner = Runner::passing();
        let result = command_unlocked(&fixture.repo, &runner, false, None, 1, &mut |_| {});
        assert_eq!(result.status, "pass", "{:?}", result.findings);
        assert_eq!(result.summary, "Scanner Redis initialization completed.");
        assert_eq!(
            result.artifacts,
            vec![
                fixture.root.join("YAFVS-runtime").display().to_string(),
                "state/ospd/openvas.conf".to_string(),
            ]
        );
        let config = fixture.root.join("YAFVS-runtime/state/ospd/openvas.conf");
        assert!(fs::read_to_string(&config).unwrap().contains(REDIS_SOCKET));
        assert_eq!(
            fs::metadata(config).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| call.args.ends_with(&[
            "up".into(),
            "-d".into(),
            "redis-openvas".into(),
        ])));
        assert!(
            calls
                .iter()
                .any(|call| call.args.iter().any(|argument| argument == "redis-cli"))
        );
        assert!(calls.iter().all(|call| {
            !call
                .args
                .iter()
                .any(|argument| argument == "mqtt-openvas-password")
        }));
        assert!(calls.iter().all(|call| {
            !call
                .environment
                .contains_key(&OsString::from("YAFVS_MQTT_OPENVAS_PASSWORD"))
        }));
    }

    #[test]
    fn public_probe_requires_a_verified_deployment_after_config() {
        let fixture = Fixture::new("missing-deployment");
        let runner = Runner::passing();
        let result = command_unlocked(&fixture.repo, &runner, true, None, 1, &mut |_| {});
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Scanner Redis initialization stopped because a verified application deployment receipt is unavailable."
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "compose.app-images" && finding.status == "fail")
        );
        assert!(
            fixture
                .root
                .join("YAFVS-runtime/state/ospd/openvas.conf")
                .is_file()
        );
    }

    #[test]
    fn readiness_is_bounded_and_failure_still_writes_configuration() {
        let fixture = Fixture::new("not-ready");
        let runner = Runner {
            ready: false,
            ..Runner::passing()
        };
        let mut sleeps = 0;
        let result = command_unlocked(&fixture.repo, &runner, false, None, 3, &mut |_| sleeps += 1);
        assert_eq!(
            result.summary,
            "Scanner Redis initialization completed with failed checks."
        );
        assert_eq!(result.status, "fail");
        assert_eq!(sleeps, 2);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "redis-openvas.ready" && finding.status == "fail")
        );
        assert!(
            fixture
                .root
                .join("YAFVS-runtime/state/ospd/openvas.conf")
                .is_file()
        );
    }

    #[test]
    fn config_failure_stops_before_service_start() {
        let fixture = Fixture::new("config-failure");
        let runner = Runner {
            config_success: false,
            ..Runner::passing()
        };
        let result = command_unlocked(&fixture.repo, &runner, false, None, 1, &mut |_| {});
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Scanner Redis initialization stopped before service startup."
        );
        assert!(
            !runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.args.iter().any(|argument| argument == "up"))
        );
    }

    #[test]
    fn settings_evidence_keeps_only_expected_nonsecret_lines() {
        let output = Some(output(
            0,
            "db_address = /runtime/run/redis-openvas/redis.sock\nplugins_folder = /runtime/feeds/openvas/plugins\ninclude_folders = /runtime/feeds/openvas/plugins\nmqtt_pass = private-value\n",
        ));
        let findings = openvas_settings_findings(&output);
        assert!(findings.iter().all(|finding| finding.status == "pass"));
        assert!(
            !serde_json::to_string(&findings)
                .unwrap()
                .contains("private-value")
        );
    }

    #[test]
    fn unsafe_lock_setup_fails_before_docker() {
        let fixture = Fixture::new("lock-failure");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = Runner::passing();
        let result = command_with_runner_and_timeout(&fixture.repo, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(runner.calls.lock().unwrap().is_empty());
    }
}
