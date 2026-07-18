// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded manager feed-import one-offs for a prepared application deployment.

use super::service_runtime::ServiceRuntime;
use super::transition::{StepOutcome, StepStatus};
use crate::result::Finding;
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::time::Duration;

const IMPORT_TIMEOUT: Duration = Duration::from_secs(7_200);
const IMPORTS: [(&str, &[&str]); 3] = [
    (
        "gvmd.rebuild-nvt",
        &[
            "--rebuild",
            "--osp-vt-update=/runtime/run/ospd/ospd-openvas.sock",
        ],
    ),
    ("gvmd.rebuild-gvmd-data", &["--rebuild-gvmd-data=all"]),
    ("gvmd.rebuild-scap", &["--rebuild-scap"]),
];

/// Runs the prepared manager feed imports and leaves all app containers removed.
///
/// Transition ordering and restarts remain the adapter's responsibility.
pub(super) fn import_manager_feed(runtime: &ServiceRuntime<'_>) -> StepOutcome {
    let environment = runtime.environment();
    let database = match required_identifier(environment, "POSTGRES_DB") {
        Ok(value) => value,
        Err(()) => return invalid_environment_outcome("POSTGRES_DB"),
    };
    let user = match required_identifier(environment, "POSTGRES_USER") {
        Ok(value) => value,
        Err(()) => return invalid_environment_outcome("POSTGRES_USER"),
    };
    let mut findings = Vec::new();
    let mut failed = false;
    for (check, step_arguments) in IMPORTS {
        let mut arguments = vec![
            "--profile".to_owned(),
            "app".to_owned(),
            "run".to_owned(),
            "--rm".to_owned(),
            "-T".to_owned(),
            "--pull".to_owned(),
            "never".to_owned(),
            "gvmd".to_owned(),
            "gvmd".to_owned(),
            format!("--database={database}"),
            "--db-host=postgres".to_owned(),
            "--db-port=5432".to_owned(),
            format!("--db-user={user}"),
            "--broker-address=mosquitto:1883".to_owned(),
            "--feed-lock-path=/runtime/run/feed-update.lock".to_owned(),
        ];
        arguments.extend(step_arguments.iter().map(|argument| (*argument).to_owned()));
        match runtime.run_pinned_compose(&arguments, IMPORT_TIMEOUT) {
            Ok(output) if output.success => findings.push(import_finding(
                StepStatus::Pass,
                check,
                output.exit_code,
                "Manager feed import step completed successfully.",
            )),
            Ok(output) => {
                findings.push(import_finding(
                    StepStatus::Fail,
                    check,
                    output.exit_code,
                    "Manager feed import step failed.",
                ));
                failed = true;
                break;
            }
            Err(_) => {
                findings.push(import_finding(
                    StepStatus::Fail,
                    check,
                    None,
                    "Manager feed import step could not be started.",
                ));
                failed = true;
                break;
            }
        }
    }
    let cleanup_check = if failed {
        "runtime.import-failure-stop"
    } else {
        "runtime.import-complete-stop"
    };
    match runtime.remove_apps(cleanup_check) {
        Ok(cleanup) => {
            failed |= cleanup.status != StepStatus::Pass;
            findings.extend(cleanup.findings);
        }
        Err(_) => {
            failed = true;
            findings.push(Finding::new(
                "fail",
                cleanup_check,
                "Application container removal after manager feed import could not be completed."
                    .to_owned(),
            ));
        }
    }
    StepOutcome::with_evidence(
        if failed {
            StepStatus::Fail
        } else {
            StepStatus::Pass
        },
        findings,
        Vec::new(),
    )
}

fn required_identifier<'a>(
    environment: &'a BTreeMap<OsString, OsString>,
    key: &str,
) -> Result<&'a str, ()> {
    match environment
        .get(OsStr::new(key))
        .and_then(|value| value.to_str())
    {
        Some(value)
            if !value.is_empty()
                && !value.starts_with('-')
                && !value.chars().any(char::is_control) =>
        {
            Ok(value)
        }
        _ => Err(()),
    }
}

fn invalid_environment_outcome(key: &str) -> StepOutcome {
    StepOutcome::with_evidence(
        StepStatus::Fail,
        vec![Finding::new(
            "fail",
            "runtime.manager-import-environment",
            format!("Required manager import environment value {key} is invalid."),
        )],
        Vec::new(),
    )
}

fn import_finding(
    status: StepStatus,
    check: &str,
    exit_code: Option<i32>,
    message: &str,
) -> Finding {
    Finding::new(
        match status {
            StepStatus::Pass => "pass",
            StepStatus::Warn => "warn",
            StepStatus::Fail => "fail",
        },
        check,
        message.to_owned(),
    )
    .with_details(json!({"exit_code": exit_code}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::feed_generation::deployment::APP_SERVICES;
    use crate::process::{CommandRunner, ProcessOutput};
    use std::collections::VecDeque;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Runner {
        outputs: Mutex<VecDeque<Option<ProcessOutput>>>,
        calls: Mutex<Vec<(Vec<String>, Option<Duration>)>>,
    }
    impl Runner {
        fn new(outputs: impl IntoIterator<Item = Option<ProcessOutput>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }
    impl CommandRunner for Runner {
        fn run(&self, _: &str, _: &[&str]) -> Option<ProcessOutput> {
            unreachable!()
        }
        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _: Option<&Path>,
            _: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            let mut command = vec![program.to_owned()];
            command.extend(args.iter().map(|argument| (*argument).to_owned()));
            self.calls.lock().unwrap().push((command, timeout));
            self.outputs.lock().unwrap().pop_front().flatten()
        }
    }
    fn output(success: bool, stdout: &str) -> Option<ProcessOutput> {
        Some(ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 42 }),
            stdout: stdout.into(),
            stderr: "private error".into(),
        })
    }
    fn environment() -> BTreeMap<OsString, OsString> {
        BTreeMap::from([
            (OsString::from("POSTGRES_DB"), OsString::from("gvmd")),
            (OsString::from("POSTGRES_USER"), OsString::from("gvm")),
        ])
    }
    fn images() -> BTreeMap<String, String> {
        APP_SERVICES
            .iter()
            .enumerate()
            .map(|(index, service)| {
                (
                    (*service).to_owned(),
                    format!("sha256:{}", format!("{index:x}").repeat(64)),
                )
            })
            .collect()
    }
    fn fixture_repo() -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "turbovas-manager-import-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("TurboVAS");
        std::fs::create_dir_all(&repo).unwrap();
        (base, repo)
    }

    fn runtime<'a>(
        repo: &'a Path,
        runner: &'a Runner,
        env: &'a BTreeMap<OsString, OsString>,
        images: &'a BTreeMap<String, String>,
    ) -> ServiceRuntime<'a> {
        ServiceRuntime::new(repo, runner, env, images)
    }
    fn cleanup_outputs() -> Vec<Option<ProcessOutput>> {
        let mut outputs = vec![output(true, "")];
        outputs.extend(APP_SERVICES.map(|_| output(true, "")));
        outputs
    }

    #[test]
    fn imports_in_order_with_exact_timeout_and_arguments() {
        let env = environment();
        let image_ids = images();
        let (base, repo) = fixture_repo();
        let mut outputs = vec![
            output(true, "private output"),
            output(true, "private output"),
            output(true, "private output"),
        ];
        outputs.extend(cleanup_outputs());
        let runner = Runner::new(outputs);
        let runtime = runtime(&repo, &runner, &env, &image_ids);
        let result = import_manager_feed(&runtime);
        assert_eq!(result.status, StepStatus::Pass);
        let calls = runner.calls.lock().unwrap();
        for (index, (_, step)) in IMPORTS.iter().enumerate() {
            let (command, timeout) = &calls[index];
            assert_eq!(command[0], "docker");
            assert_eq!(command[1], "compose");
            assert_eq!(command[2], "-f");
            assert_eq!(
                command[3],
                repo.join("compose/dev.yaml").display().to_string()
            );
            assert_eq!(command[4], "-f");
            assert_eq!(
                command[5],
                base.join("YAFVS-runtime/state/feed-generation/app-images.json")
                    .display()
                    .to_string()
            );
            let start = command
                .iter()
                .position(|argument| argument == "--profile")
                .unwrap();
            let expected = [
                "--profile",
                "app",
                "run",
                "--rm",
                "-T",
                "--pull",
                "never",
                "gvmd",
                "gvmd",
                "--database=gvmd",
                "--db-host=postgres",
                "--db-port=5432",
                "--db-user=gvm",
                "--broker-address=mosquitto:1883",
                "--feed-lock-path=/runtime/run/feed-update.lock",
            ];
            assert_eq!(&command[start..start + expected.len()], expected);
            assert_eq!(&command[start + expected.len()..], *step);
            assert_eq!(*timeout, Some(IMPORT_TIMEOUT));
        }
        assert_eq!(result.findings.len(), 4);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn failed_step_stops_later_imports_and_removes_every_app_container() {
        let env = environment();
        let image_ids = images();
        let (base, repo) = fixture_repo();
        let mut outputs = vec![output(false, "private output")];
        outputs.extend(cleanup_outputs());
        let runner = Runner::new(outputs);
        let runtime = runtime(&repo, &runner, &env, &image_ids);
        let result = import_manager_feed(&runtime);
        assert_eq!(result.status, StepStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| !finding.message.contains("private"))
        );
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 2 + APP_SERVICES.len());
        assert!(calls[1].0.iter().any(|argument| argument == "rm"));
        assert_eq!(result.findings[1].check, "runtime.import-failure-stop");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn successful_import_removes_every_app_container() {
        let env = environment();
        let image_ids = images();
        let (base, repo) = fixture_repo();
        let mut outputs = vec![
            output(true, "private output"),
            output(true, "private output"),
            output(true, "private output"),
        ];
        outputs.extend(cleanup_outputs());
        let runner = Runner::new(outputs);
        let runtime = runtime(&repo, &runner, &env, &image_ids);
        let result = import_manager_feed(&runtime);
        assert_eq!(result.status, StepStatus::Pass);
        assert_eq!(
            result.findings.last().unwrap().check,
            "runtime.import-complete-stop"
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 4 + APP_SERVICES.len());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn unsafe_database_or_user_is_rejected_without_running_commands() {
        for (key, value) in [("POSTGRES_DB", "-database"), ("POSTGRES_USER", "bad\nuser")] {
            let mut env = environment();
            env.insert(OsString::from(key), OsString::from(value));
            let image_ids = images();
            let (base, repo) = fixture_repo();
            let runner = Runner::new([]);
            let runtime = runtime(&repo, &runner, &env, &image_ids);
            let result = import_manager_feed(&runtime);
            assert_eq!(result.status, StepStatus::Fail);
            assert!(runner.calls.lock().unwrap().is_empty());
            std::fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn process_launch_failure_still_removes_every_app_container() {
        let env = environment();
        let image_ids = images();
        let (base, repo) = fixture_repo();
        let mut outputs = vec![None];
        outputs.extend(cleanup_outputs());
        let runner = Runner::new(outputs);
        let runtime = runtime(&repo, &runner, &env, &image_ids);

        let result = import_manager_feed(&runtime);

        assert_eq!(result.status, StepStatus::Fail);
        assert_eq!(result.findings[0].check, "gvmd.rebuild-nvt");
        assert_eq!(result.findings[1].check, "runtime.import-failure-stop");
        assert_eq!(runner.calls.lock().unwrap().len(), 2 + APP_SERVICES.len());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn unsafe_non_unicode_identifier_is_rejected_without_running_commands() {
        use std::os::unix::ffi::OsStringExt;

        let mut env = environment();
        env.insert(
            OsString::from("POSTGRES_DB"),
            OsString::from_vec(vec![0xff]),
        );
        let image_ids = images();
        let (base, repo) = fixture_repo();
        let runner = Runner::new([]);
        let runtime = runtime(&repo, &runner, &env, &image_ids);

        let result = import_manager_feed(&runtime);

        assert_eq!(result.status, StepStatus::Fail);
        assert!(runner.calls.lock().unwrap().is_empty());
        std::fs::remove_dir_all(base).unwrap();
    }
}
