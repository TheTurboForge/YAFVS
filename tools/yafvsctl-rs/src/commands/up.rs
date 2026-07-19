// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_lifecycle_environment};
use super::runtime_setup::ensure_runtime_setup;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

const RUNTIME_SERVICES: [&str; 3] = ["postgres", "redis-openvas", "mosquitto"];

pub fn command_up(repo_root: &Path) -> ResultEnvelope {
    command_up_with_runner(repo_root, &SystemCommandRunner)
}

pub(crate) fn command_up_with_runner(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let mut findings = ensure_runtime_setup(repo_root, runner);
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "up", runner),
            "Runtime startup stopped before docker compose up.".to_string(),
            findings,
        )
        .with_artifacts(vec![runtime_dir(repo_root).display().to_string()]);
    }
    let environment = match runtime_lifecycle_environment(repo_root) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.mqtt-secrets",
                format!("Runtime MQTT secrets could not be prepared: {error}"),
            ));
            return make_result(
                metadata(repo_root, "up", runner),
                "Runtime startup stopped before docker compose up.".to_string(),
                findings,
            )
            .with_artifacts(vec![runtime_dir(repo_root).display().to_string()]);
        }
    };
    let config = run_compose(
        repo_root,
        runner,
        &environment,
        &["config".into(), "--quiet".into()],
    );
    findings.push(process_finding(
        &config,
        "compose.config",
        "Compose config validation",
        40,
        Some("compose/dev.yaml"),
    ));
    if findings.iter().any(|finding| finding.status == "fail") {
        return make_result(
            metadata(repo_root, "up", runner),
            "Runtime startup stopped before docker compose up.".to_string(),
            findings,
        )
        .with_artifacts(vec![runtime_dir(repo_root).display().to_string()]);
    }

    let up = run_compose(
        repo_root,
        runner,
        &environment,
        &[
            "up".into(),
            "-d".into(),
            "--build".into(),
            "postgres".into(),
            "redis-openvas".into(),
            "mosquitto".into(),
        ],
    );
    findings.push(process_finding(
        &up,
        "compose.up",
        "docker compose up",
        80,
        None,
    ));
    for service in RUNTIME_SERVICES {
        let running = container_running(repo_root, service, runner, &environment);
        findings.push(
            Finding::new(
                if running { "pass" } else { "fail" },
                "runtime.running",
                format!(
                    "{service} container is {}.",
                    if running { "running" } else { "not running" }
                ),
            )
            .with_details(json!({ "service": service })),
        );
    }
    make_result(
        metadata(repo_root, "up", runner),
        "Runtime infrastructure startup attempted.".to_string(),
        findings,
    )
    .with_artifacts(vec![runtime_dir(repo_root).display().to_string()])
}

fn run_compose(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    operation: &[String],
) -> Option<ProcessOutput> {
    let command = compose_command(repo_root, operation);
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with(
        "docker",
        &arguments,
        Some(repo_root),
        Some(environment),
        None,
    )
}

fn process_finding(
    output: &Option<ProcessOutput>,
    check: &str,
    label: &str,
    tail_lines: usize,
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
    )
    .with_details(json!({ "output_tail": output.as_ref().map(|output| output_tail(&output.stdout, tail_lines)).unwrap_or_default() }));
    if let Some(path) = path {
        finding = finding.with_path(path);
    }
    finding
}

fn container_running(
    repo_root: &Path,
    service: &str,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> bool {
    let arguments = compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]);
    let args = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(identifier) = runner
        .run_with("docker", &args, Some(repo_root), Some(environment), None)
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
        })
    else {
        return false;
    };
    if identifier.len() < 12
        || identifier.len() > 64
        || !identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &identifier],
            Some(repo_root),
            Some(environment),
            None,
        )
        .is_some_and(|output| output.success && output.stdout.trim() == "true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Mutex;

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }
    fn container_id(byte: char) -> String {
        format!("{}\n", byte.to_string().repeat(64))
    }
    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("yafvsctl-up-{name}-{}", std::process::id()));
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
    struct Call {
        args: Vec<String>,
        cwd: Option<PathBuf>,
        environment: bool,
    }
    struct Runner {
        outputs: Mutex<Vec<ProcessOutput>>,
        calls: Mutex<Vec<Call>>,
    }
    impl Runner {
        fn new(outputs: Vec<ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs),
                calls: Mutex::new(Vec::new()),
            }
        }
    }
    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| output(0, "deadbee\n"))
        }
        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            cwd: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            _: Option<std::time::Duration>,
        ) -> Option<ProcessOutput> {
            if program != "docker" {
                return self.run(program, args);
            }
            self.calls.lock().unwrap().push(Call {
                args: args.iter().map(|arg| (*arg).into()).collect(),
                cwd: cwd.map(Path::to_path_buf),
                environment: environment.is_some_and(|env| {
                    env.contains_key(&OsString::from("YAFVS_RUNTIME_DIR"))
                        && !env.contains_key(&OsString::from("YAFVS_MQTT_OPENVAS_PASSWORD"))
                }),
            });
            let mut outputs = self.outputs.lock().unwrap();
            (!outputs.is_empty()).then(|| outputs.remove(0))
        }
    }
    fn output(code: i32, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success: code == 0,
            exit_code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    fn prerequisites(fixture: &Fixture) {
        let _ = ensure_runtime_setup(&fixture.repo, &Runner::new(vec![]));
    }

    #[test]
    fn up_runs_exact_compose_order_with_clean_environment_and_proves_each_identity() {
        let fixture = Fixture::new("success");
        prerequisites(&fixture);
        let runner = Runner::new(vec![
            output(0, ""),
            output(0, ""),
            output(0, &container_id('a')),
            output(0, "true\n"),
            output(0, &container_id('b')),
            output(0, "true\n"),
            output(0, &container_id('c')),
            output(0, "true\n"),
        ]);
        let result = command_up_with_runner(&fixture.repo, &runner);
        assert_eq!(result.status, "pass");
        assert_eq!(result.summary, "Runtime infrastructure startup attempted.");
        assert_eq!(
            result.artifacts,
            vec![fixture.root.join("YAFVS-runtime").display().to_string()]
        );
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[0].args.last().unwrap(), "--quiet");
        assert_eq!(
            &calls[1].args[calls[1].args.len() - 6..],
            [
                "up",
                "-d",
                "--build",
                "postgres",
                "redis-openvas",
                "mosquitto"
            ]
        );
        assert!(calls
            .iter()
            .all(|call| call.cwd.as_deref() == Some(fixture.repo.as_path()) && call.environment));
        for secret_name in [
            "mqtt-openvas-password",
            "mqtt-notus-password",
            "mqtt-ospd-password",
            "mqtt-health-password",
        ] {
            let path = fixture.root.join("YAFVS-runtime/secrets").join(secret_name);
            assert!(path.is_file());
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.args.first().is_some_and(|arg| arg == "inspect"))
                .count(),
            3
        );
        assert!(
            result
                .findings
                .iter()
                .filter(|finding| finding.check == "runtime.running")
                .all(|finding| finding.status == "pass")
        );
    }

    #[test]
    fn failed_setup_short_circuits_before_secrets_and_processes() {
        let fixture = Fixture::new("setup-failure");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = Runner::new(vec![output(0, "")]);
        let result = command_up_with_runner(&fixture.repo, &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime startup stopped before docker compose up."
        );
        let calls = runner.calls.lock().unwrap();
        assert!(calls.is_empty());
        assert!(
            result
                .findings
                .iter()
                .any(|finding| { finding.check == "runtime.dir" && finding.status == "fail" })
        );
        assert!(!fixture.root.join("YAFVS-runtime/secrets").exists());
        assert!(!calls.iter().any(|call| call.args.contains(&"up".into())));
    }

    #[test]
    fn config_or_launch_process_failure_is_a_stable_failure_envelope() {
        let fixture = Fixture::new("process-failure");
        prerequisites(&fixture);
        let runner = Runner::new(vec![]);
        let result = command_up_with_runner(&fixture.repo, &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime startup stopped before docker compose up."
        );
        assert_eq!(result.findings.last().unwrap().check, "compose.config");
        assert_eq!(
            result.findings.last().unwrap().details,
            Some(json!({ "output_tail": [] }))
        );
    }

    #[test]
    fn up_failure_still_reports_independent_nonrunning_service_proofs() {
        let fixture = Fixture::new("up-failure");
        prerequisites(&fixture);
        let runner = Runner::new(vec![
            output(0, ""),
            output(17, "failed\n"),
            output(0, &container_id('a')),
            output(0, "false\n"),
            output(0, ""),
            output(0, &container_id('b')),
            output(0, "true\n"),
        ]);
        let result = command_up_with_runner(&fixture.repo, &runner);
        assert_eq!(result.status, "fail");
        assert_eq!(
            result
                .findings
                .iter()
                .find(|finding| finding.check == "compose.up")
                .unwrap()
                .status,
            "fail"
        );
        let states = result
            .findings
            .iter()
            .filter(|finding| finding.check == "runtime.running")
            .collect::<Vec<_>>();
        assert_eq!(states.len(), 3);
        assert_eq!(states[0].status, "fail");
        assert_eq!(states[1].status, "fail");
        assert_eq!(states[2].status, "pass");
    }

    #[test]
    fn invalid_container_identity_never_reaches_docker_inspect() {
        let fixture = Fixture::new("invalid-container-id");
        let runner = Runner::new(vec![output(0, "not-a-container-id\n")]);
        let environment = BTreeMap::new();

        assert!(!container_running(
            &fixture.repo,
            "postgres",
            &runner,
            &environment
        ));
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"ps".into()));
        assert!(!calls[0].args.contains(&"inspect".into()));
    }
}
