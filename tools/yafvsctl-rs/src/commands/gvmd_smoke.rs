// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_app_environment, runtime_environment};
use super::feed_generation::{
    command_feed_generation_runtime_guard, pinned_app_compose_command,
    require_current_app_deployment,
};
use super::runtime_health::pg_gvm_extension_finding;
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "gvmd-smoke";
const PG_GVM_DATABASE_QUERY: &str = concat!(
    "env PGPASSWORD=${POSTGRES_PASSWORD:-yafvs-dev} ",
    "psql -h postgres -U ${POSTGRES_USER:-yafvs} ",
    "-d ${POSTGRES_DB:-yafvs} -At -c ",
    "\"SELECT extversion FROM pg_extension WHERE extname = 'pg-gvm';\""
);

trait GvmdSmokeContext {
    fn active_feed(&mut self) -> Finding;
    fn pg_gvm(&mut self) -> Finding;
    fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String>;
    fn deployment(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<BTreeMap<String, String>, String>;
}

struct SystemContext<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
}

impl GvmdSmokeContext for SystemContext<'_> {
    fn active_feed(&mut self) -> Finding {
        command_feed_generation_runtime_guard(self.repo_root, false)
            .findings
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                Finding::new(
                    "fail",
                    "feed-generation.current",
                    "Active feed generation status was unavailable.".into(),
                )
            })
    }

    fn pg_gvm(&mut self) -> Finding {
        let environment = runtime_environment(self.repo_root);
        let database = environment
            .get(&OsString::from("POSTGRES_DB"))
            .map(|value| value.to_string_lossy().into_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "yafvs".into());
        pg_gvm_extension_finding(self.runner, self.repo_root, &environment, &database, false)
    }

    fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
        runtime_app_environment(self.repo_root)
            .map_err(|error| format!("Application runtime environment is unavailable: {error}"))
    }

    fn deployment(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<BTreeMap<String, String>, String> {
        require_current_app_deployment(self.repo_root, self.runner, environment)
    }
}

pub fn command_gvmd_smoke(repo_root: &Path) -> ResultEnvelope {
    command_gvmd_smoke_with_runner_and_timeout(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_gvmd_smoke_with_runner_and_timeout(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    timeout: Duration,
) -> ResultEnvelope {
    match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
        Ok(_lock) => {
            let mut context = SystemContext { repo_root, runner };
            command_gvmd_smoke_unlocked(repo_root, runner, &mut context)
        }
        Err(error) => lock_failure(repo_root, runner, error),
    }
}

fn command_gvmd_smoke_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    context: &mut dyn GvmdSmokeContext,
) -> ResultEnvelope {
    let mut findings = vec![context.active_feed()];
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "gvmd smoke stopped at feed activation prerequisites.",
            findings,
        );
    }

    let pg_gvm = context.pg_gvm();
    if pg_gvm.status != "pass" {
        findings.push(Finding::new(
            "fail",
            "gvmd.pg-gvm",
            "pg-gvm extension is not initialized; run just runtime-init before gvmd smoke.".into(),
        ));
        return result(
            repo_root,
            runner,
            "gvmd smoke stopped before service startup.",
            findings,
        );
    }

    let environment = match context.app_environment() {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new("fail", "runtime.app-environment", error));
            return result(
                repo_root,
                runner,
                "gvmd smoke stopped because the application environment is unavailable.",
                findings,
            );
        }
    };
    let image_ids = match context.deployment(&environment) {
        Ok(image_ids) => {
            findings.push(
                Finding::new(
                    "pass",
                    "runtime.app-deployment-receipt",
                    "Prepared application deployment receipt is valid for the gvmd smoke.".into(),
                )
                .with_path(
                    &runtime_dir(repo_root)
                        .join("state/app-deployment.json")
                        .display()
                        .to_string(),
                ),
            );
            image_ids
        }
        Err(error) => {
            findings.push(
                Finding::new("fail", "runtime.app-deployment-receipt", error).with_path(
                    &runtime_dir(repo_root)
                        .join("state/app-deployment.json")
                        .display()
                        .to_string(),
                ),
            );
            return result(
                repo_root,
                runner,
                "gvmd smoke stopped because no verified application deployment was prepared.",
                findings,
            );
        }
    };

    let up_arguments = [
        "--profile",
        "app",
        "up",
        "-d",
        "--no-deps",
        "--no-build",
        "--pull",
        "never",
        "gvmd",
    ]
    .map(str::to_owned);
    let up_command =
        match pinned_app_compose_command(repo_root, &environment, &image_ids, &up_arguments) {
            Ok(command) => command,
            Err(error) => {
                findings.push(Finding::new(
                    "fail",
                    "gvmd.up",
                    format!("Pinned gvmd Compose command could not be prepared: {error}"),
                ));
                return result(
                    repo_root,
                    runner,
                    "gvmd smoke stopped at container startup.",
                    findings,
                );
            }
        };
    let up = run_docker(
        runner,
        repo_root,
        &environment,
        &up_command,
        Duration::from_secs(120),
    );
    findings.push(process_finding(
        &up,
        "gvmd.up",
        "docker compose up gvmd",
        80,
    ));
    if up.exit_code != Some(0) {
        return result(
            repo_root,
            runner,
            "gvmd smoke stopped at container startup.",
            findings,
        );
    }

    let binary = run_compose_exec(
        runner,
        repo_root,
        &environment,
        &["sh", "-lc", "command -v gvmd && gvmd --version"],
    );
    findings.push(optional_process_finding(
        &binary,
        "gvmd.binary",
        "gvmd binary probe",
        binary.exit_code == Some(0),
    ));
    let database = run_compose_exec(
        runner,
        repo_root,
        &environment,
        &["sh", "-lc", PG_GVM_DATABASE_QUERY],
    );
    findings.push(optional_process_finding(
        &database,
        "gvmd.database",
        "gvmd profile DB probe",
        database.exit_code == Some(0) && !database.stdout.trim().is_empty(),
    ));
    findings.push(Finding::new(
        "warn",
        "gvmd.deferred",
        "This smoke does not start the full manager daemon yet; certificates, scanner registration, feeds, and runtime paths remain follow-up work."
            .into(),
    ));
    result(repo_root, runner, "gvmd profile smoke completed.", findings)
}

fn run_compose_exec(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    command: &[&str],
) -> ProcessOutput {
    let mut arguments = vec!["exec".to_owned(), "-T".to_owned(), "gvmd".to_owned()];
    arguments.extend(command.iter().map(|value| (*value).to_owned()));
    let command = compose_command(repo_root, &arguments);
    run_docker(
        runner,
        repo_root,
        environment,
        &command,
        Duration::from_secs(120),
    )
}

fn run_docker(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    environment: &BTreeMap<OsString, OsString>,
    arguments: &[String],
    timeout: Duration,
) -> ProcessOutput {
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(environment),
            Some(timeout),
        )
        .unwrap_or_else(unavailable_process)
}

fn unavailable_process() -> ProcessOutput {
    ProcessOutput {
        success: false,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: String::new(),
    }
}

fn process_finding(output: &ProcessOutput, check: &str, label: &str, tail: usize) -> Finding {
    let exit_code = output.exit_code.unwrap_or(1);
    Finding::new(
        if exit_code == 0 { "pass" } else { "fail" },
        check,
        format!("{label} exit code {exit_code}."),
    )
    .with_details(json!({"output_tail": output_tail(&output.stdout, tail)}))
}

fn optional_process_finding(
    output: &ProcessOutput,
    check: &str,
    label: &str,
    passed: bool,
) -> Finding {
    Finding::new(
        if passed { "pass" } else { "warn" },
        check,
        format!("{label} exit code {}.", output.exit_code.unwrap_or(1)),
    )
    .with_details(json!({"output_tail": output_tail(&output.stdout, 40)}))
}

fn has_failure(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
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
        "gvmd smoke stopped while waiting for the feed lifecycle lock.".into(),
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message).with_details(details),
        ],
    )
    .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct QueueRunner {
        outputs: Mutex<VecDeque<ProcessOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl QueueRunner {
        fn new(outputs: impl IntoIterator<Item = ProcessOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for QueueRunner {
        fn run(&self, _: &str, _: &[&str]) -> Option<ProcessOutput> {
            None
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _: Option<&Path>,
            _: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program.to_owned())
                    .chain(args.iter().map(|value| (*value).to_owned()))
                    .collect(),
            );
            self.outputs.lock().unwrap().pop_front()
        }
    }

    struct Context {
        feed: &'static str,
        pg_gvm: &'static str,
        deployment: Result<BTreeMap<String, String>, String>,
        environment_calls: usize,
        deployment_calls: usize,
    }

    impl Context {
        fn ready() -> Self {
            Self {
                feed: "pass",
                pg_gvm: "pass",
                deployment: Ok(
                    ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"]
                        .into_iter()
                        .enumerate()
                        .map(|(index, service)| {
                            (
                                service.to_owned(),
                                format!("sha256:{}", format!("{index:x}").repeat(64)),
                            )
                        })
                        .collect(),
                ),
                environment_calls: 0,
                deployment_calls: 0,
            }
        }
    }

    impl GvmdSmokeContext for Context {
        fn active_feed(&mut self) -> Finding {
            Finding::new(self.feed, "feed-generation.current", "feed".into())
        }

        fn pg_gvm(&mut self) -> Finding {
            Finding::new(self.pg_gvm, "postgres.pg-gvm", "pg-gvm".into())
        }

        fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
            self.environment_calls += 1;
            Ok(BTreeMap::new())
        }

        fn deployment(
            &mut self,
            _: &BTreeMap<OsString, OsString>,
        ) -> Result<BTreeMap<String, String>, String> {
            self.deployment_calls += 1;
            self.deployment.clone()
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

    fn fixture() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-gvmd-smoke-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        let state = root.join("YAFVS-runtime/state/feed-generation");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(
            root.join("YAFVS-runtime/state"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        (root, repo)
    }

    #[test]
    fn feed_failure_stops_before_every_later_prerequisite_and_process() {
        let (root, repo) = fixture();
        let runner = QueueRunner::new([]);
        let mut context = Context::ready();
        context.feed = "fail";
        let result = command_gvmd_smoke_unlocked(&repo, &runner, &mut context);
        assert_eq!(result.status, "fail");
        assert_eq!(context.environment_calls, 0);
        assert_eq!(context.deployment_calls, 0);
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_start_preserves_exact_commands_order_and_warning_contract() {
        let (root, repo) = fixture();
        let runner = QueueRunner::new([
            output(true, "started"),
            output(true, "/usr/sbin/gvmd\ngvmd 26"),
            output(false, ""),
        ]);
        let mut context = Context::ready();
        let result = command_gvmd_smoke_unlocked(&repo, &runner, &mut context);
        assert_eq!(result.status, "warn");
        assert_eq!(
            result
                .findings
                .iter()
                .map(|finding| finding.check.as_str())
                .collect::<Vec<_>>(),
            [
                "feed-generation.current",
                "runtime.app-deployment-receipt",
                "gvmd.up",
                "gvmd.binary",
                "gvmd.database",
                "gvmd.deferred",
            ]
        );
        assert_eq!(
            result.artifacts,
            [root.join("YAFVS-runtime").display().to_string()]
        );
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].windows(9).any(|window| {
            window
                == [
                    "--profile",
                    "app",
                    "up",
                    "-d",
                    "--no-deps",
                    "--no-build",
                    "--pull",
                    "never",
                    "gvmd",
                ]
        }));
        assert!(calls[1].ends_with(&[
            "exec".into(),
            "-T".into(),
            "gvmd".into(),
            "sh".into(),
            "-lc".into(),
            "command -v gvmd && gvmd --version".into(),
        ]));
        assert!(
            calls[2]
                .last()
                .unwrap()
                .contains("PGPASSWORD=${POSTGRES_PASSWORD")
        );
        assert!(
            !calls
                .iter()
                .flatten()
                .any(|value| value.contains("yafvs-dev") && value.contains("PGPASSWORD=yafvs-dev"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compose_failure_stops_before_in_container_probes() {
        let (root, repo) = fixture();
        let runner = QueueRunner::new([output(false, "compose failed")]);
        let mut context = Context::ready();
        let result = command_gvmd_smoke_unlocked(&repo, &runner, &mut context);
        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "gvmd smoke stopped at container startup.");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lock_setup_failure_fails_closed_without_runtime_processes() {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-gvmd-smoke-lock-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        fs::write(root.join("YAFVS-runtime"), b"not a directory").unwrap();
        let runner = QueueRunner::new([]);
        let result = command_gvmd_smoke_with_runner_and_timeout(&repo, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(runner.calls.lock().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
