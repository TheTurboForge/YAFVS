// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guarded manager migration and development-administrator initialization.

use super::common::{metadata, runtime_dir};
use super::compose::runtime_app_environment;
use super::feed_generation::{initialize_manager_with_images, require_current_app_deployment};
use super::runtime_certs::runtime_certificate_findings;
use super::runtime_init::command_runtime_init_with;
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "runtime-manager-init";
const RUNTIME_MANAGER_LOCK: &str = "runtime-manager";

pub fn command_runtime_manager_init(repo_root: &Path) -> ResultEnvelope {
    command_with(
        repo_root,
        &SystemCommandRunner,
        DEFAULT_RUNTIME_LOCK_TIMEOUT,
    )
}

fn command_with(repo_root: &Path, runner: &dyn CommandRunner, timeout: Duration) -> ResultEnvelope {
    let _feed_lock = match RuntimeOperationLock::acquire(
        repo_root,
        FEED_ACTIVATION_LOCK,
        COMMAND,
        timeout,
    ) {
        Ok(lock) => lock,
        Err(error) => {
            return lock_failure(
                repo_root,
                runner,
                error,
                "feed-generation.activation-lock",
                "Runtime manager initialization stopped while waiting for the feed lifecycle lock.",
            );
        }
    };
    let _manager_lock = match RuntimeOperationLock::acquire(
        repo_root,
        RUNTIME_MANAGER_LOCK,
        COMMAND,
        timeout,
    ) {
        Ok(lock) => lock,
        Err(error) => {
            return lock_failure(
                repo_root,
                runner,
                error,
                "runtime.manager-lock",
                "Runtime manager initialization stopped while waiting for another manager operation.",
            );
        }
    };
    let mut sleep = std::thread::sleep;
    command_unlocked(repo_root, runner, &mut sleep)
}

fn command_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    sleep: &mut dyn FnMut(Duration),
) -> ResultEnvelope {
    let database = command_runtime_init_with(repo_root, runner, sleep);
    let mut findings = vec![
        Finding::new(
            &database.status,
            "runtime.database-init",
            database.summary.clone(),
        )
        .with_details(json!({"status": database.status.clone()})),
    ];
    if database.status == "fail" {
        return result(
            repo_root,
            runner,
            "Manager initialization stopped at database prerequisites.",
            findings,
            database.artifacts,
        );
    }

    findings.extend(runtime_certificate_findings(repo_root));
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
                "Manager initialization stopped before application image verification.",
                findings,
                vec![runtime_dir(repo_root).display().to_string()],
            );
        }
    };
    let image_ids = match require_current_app_deployment(repo_root, runner, &environment) {
        Ok(image_ids) => image_ids,
        Err(error) => {
            findings.push(Finding::new("fail", "compose.app-image", error));
            return result(
                repo_root,
                runner,
                "Manager initialization stopped because a verified application deployment receipt was unavailable.",
                findings,
                vec![runtime_dir(repo_root).display().to_string()],
            );
        }
    };
    findings.push(Finding::new(
        "pass",
        "compose.app-image",
        "Manager initialization uses prepared application images without rebuilding.".into(),
    ));

    let (manager_passed, manager_findings, manager_artifacts) =
        initialize_manager_with_images(repo_root, runner, &environment, &image_ids);
    findings.extend(manager_findings);
    let summary = if manager_passed {
        "Runtime manager initialization completed."
    } else {
        manager_failure_summary(&findings)
    };
    let mut artifacts = vec![runtime_dir(repo_root).display().to_string()];
    for artifact in manager_artifacts {
        if !artifacts.contains(&artifact) {
            artifacts.push(artifact);
        }
    }
    result(repo_root, runner, summary, findings, artifacts)
}

fn manager_failure_summary(findings: &[Finding]) -> &'static str {
    let failed = |check| {
        findings
            .iter()
            .any(|finding| finding.check == check && finding.status == "fail")
    };
    if failed("gvmd.migrate") {
        "Manager initialization stopped at database migration."
    } else if failed("gvmd.migrate-version-preflight") {
        "Manager initialization stopped because the database schema version could not be verified."
    } else if failed("gvmd.migrate-version") {
        "Manager initialization stopped because the migrated database version does not match the source schema."
    } else if failed("gvmd.migrate-schema") {
        "Manager initialization stopped because the database schema does not match the shared Rust contract."
    } else if failed("manager.admin-uuid") {
        "Manager initialization stopped while verifying the development administrator."
    } else if failed("gvmd.create-admin") {
        "Manager initialization stopped at admin user creation."
    } else if failed("gvmd.admin-password") {
        "Manager initialization stopped at admin password update."
    } else if failed("gvmd.feed-owner") {
        "Manager initialization stopped at feed import owner update."
    } else {
        "Manager initialization stopped before completion."
    }
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    artifacts: Vec<String>,
) -> ResultEnvelope {
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
    check: &str,
    summary: &str,
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
            format!("Runtime manager lock failed closed: {message}."),
            json!({}),
        ),
    };
    make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        vec![Finding::new("fail", check, message).with_details(details)],
    )
    .with_artifacts(vec![runtime_lock_dir(repo_root).display().to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Mutex;

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-runtime-manager-{name}-{}",
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

    struct Runner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl Runner {
        fn new() -> Self {
            Self {
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
            Some(output(1, ""))
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

    #[test]
    fn unsafe_runtime_setup_stops_before_docker() {
        let fixture = Fixture::new("unsafe-setup");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = Runner::new();
        let result = command_with(&fixture.repo, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn feed_lock_contention_stops_before_docker() {
        let fixture = Fixture::new("feed-lock");
        let _holder = RuntimeOperationLock::acquire(
            &fixture.repo,
            FEED_ACTIVATION_LOCK,
            "test-holder",
            Duration::ZERO,
        )
        .unwrap();
        let runner = Runner::new();
        let result = command_with(&fixture.repo, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn manager_lock_contention_stops_before_docker() {
        let fixture = Fixture::new("manager-lock");
        let _holder = RuntimeOperationLock::acquire(
            &fixture.repo,
            RUNTIME_MANAGER_LOCK,
            "test-holder",
            Duration::ZERO,
        )
        .unwrap();
        let runner = Runner::new();
        let result = command_with(&fixture.repo, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "runtime.manager-lock");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn failure_summaries_are_specific_and_never_claim_completion() {
        let findings = vec![Finding::new("fail", "gvmd.admin-password", "failed".into())];
        assert_eq!(
            manager_failure_summary(&findings),
            "Manager initialization stopped at admin password update."
        );
        assert!(!manager_failure_summary(&findings).contains("completed"));

        let preflight = vec![Finding::new(
            "fail",
            "gvmd.migrate-version-preflight",
            "failed".into(),
        )];
        assert!(manager_failure_summary(&preflight).contains("could not be verified"));

        let fingerprint = vec![Finding::new("fail", "gvmd.migrate-schema", "failed".into())];
        assert!(manager_failure_summary(&fingerprint).contains("shared Rust contract"));
    }
}
