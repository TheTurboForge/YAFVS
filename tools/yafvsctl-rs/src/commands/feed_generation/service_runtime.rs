// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded Docker/Compose primitives for feed-transition application services.

use super::compose_identity::pinned_compose_command;
use super::deployment::APP_SERVICES;
use super::transition::{StepOutcome, StepStatus};
use crate::commands::compose::compose_command;
use crate::process::{CommandRunner, ProcessOutput};
use crate::result::Finding;
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

pub(super) const CONTROL_SERVICES: [&str; 3] = ["gvmd", "gsad", "turbovas-api"];
pub(super) const SCANNER_SERVICES: [&str; 2] = ["ospd-openvas", "notus-scanner"];

pub(super) struct ServiceRuntime<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
    environment: &'a BTreeMap<OsString, OsString>,
    image_ids: &'a BTreeMap<String, String>,
}

impl<'a> ServiceRuntime<'a> {
    pub(super) fn new(
        repo_root: &'a Path,
        runner: &'a dyn CommandRunner,
        environment: &'a BTreeMap<OsString, OsString>,
        image_ids: &'a BTreeMap<String, String>,
    ) -> Self {
        Self {
            repo_root,
            runner,
            environment,
            image_ids,
        }
    }

    pub(super) fn environment(&self) -> &BTreeMap<OsString, OsString> {
        self.environment
    }

    pub(super) fn running_services(&self, services: &[&str]) -> Result<Vec<String>, String> {
        services
            .iter()
            .filter_map(|service| match self.container_running(service) {
                Ok(true) => Some(Ok((*service).to_owned())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    pub(super) fn running_app_image_identity(&self) -> Result<StepOutcome, String> {
        let mut running = Vec::new();
        let mut mismatched = Vec::new();
        for service in APP_SERVICES {
            if !self.container_running(service)? {
                continue;
            }
            running.push(service);
            let observed = self.container_image_id(service)?;
            if observed.as_deref() != self.image_ids.get(service).map(String::as_str) {
                mismatched.push(service);
            }
        }
        let passed = mismatched.is_empty();
        Ok(outcome(
            if passed {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            "feed-generation.running-app-images",
            if passed {
                "Every running application service uses its prepared immutable image object."
            } else {
                "One or more running application services use an image object that differs from the prepared deployment."
            },
            json!({"running_services": running, "mismatched_services": mismatched}),
        ))
    }

    pub(super) fn stop_controls(&self) -> Result<(StepOutcome, Vec<String>), String> {
        let previously_running = self.running_services(&CONTROL_SERVICES)?;
        if previously_running.is_empty() {
            return Ok((
                outcome(
                    StepStatus::Pass,
                    "feed-generation.control-quiesce",
                    "No running scanner-control service needed to be stopped before the stable scan-state check.",
                    json!({"previously_running_services": []}),
                ),
                Vec::new(),
            ));
        }
        let mut arguments = vec!["--profile".to_owned(), "app".to_owned(), "stop".to_owned()];
        arguments.extend(previously_running.iter().cloned());
        let output = self.run_compose(&arguments, Duration::from_secs(300))?;
        let still_running = self.running_services(
            &previously_running
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )?;
        let passed = output.success && still_running.is_empty();
        Ok((
            outcome(
                if passed {
                    StepStatus::Pass
                } else {
                    StepStatus::Fail
                },
                "feed-generation.control-quiesce",
                &format!(
                    "Stop scanner-control services before stable scan-state verification exit code {}; {} remain running.",
                    output.exit_code.unwrap_or(1),
                    still_running.len()
                ),
                json!({
                    "exit_code": output.exit_code,
                    "previously_running_services": previously_running,
                    "still_running_services": still_running,
                }),
            ),
            previously_running,
        ))
    }

    pub(super) fn restore_controls(&self, services: &[String]) -> Result<StepOutcome, String> {
        let selected = services
            .iter()
            .filter(|service| CONTROL_SERVICES.contains(&service.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(outcome(
                StepStatus::Pass,
                "feed-generation.control-restore",
                "No scanner-control service needed restoration.",
                json!({"services": []}),
            ));
        }
        let mut arguments = vec!["--profile".to_owned(), "app".to_owned(), "start".to_owned()];
        arguments.extend(selected.iter().cloned());
        let output = self.run_compose(&arguments, Duration::from_secs(300))?;
        let missing = selected
            .iter()
            .filter_map(|service| match self.container_running(service) {
                Ok(true) => None,
                Ok(false) => Some(Ok(service.clone())),
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let passed = output.success && missing.is_empty();
        Ok(outcome(
            if passed {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            "feed-generation.control-restore",
            &format!(
                "Restore scanner-control services after aborted feed preflight exit code {}; {} failed to restart.",
                output.exit_code.unwrap_or(1),
                missing.len()
            ),
            json!({"exit_code": output.exit_code, "services": selected, "missing_services": missing}),
        ))
    }

    pub(super) fn remove_apps(&self, check: &str) -> Result<StepOutcome, String> {
        let mut arguments = vec![
            "--profile".to_owned(),
            "app".to_owned(),
            "rm".to_owned(),
            "-f".to_owned(),
            "-s".to_owned(),
        ];
        arguments.extend(APP_SERVICES.iter().map(|service| (*service).to_owned()));
        let output = self.run_compose(&arguments, Duration::from_secs(300))?;
        let mut remaining = Vec::new();
        for service in APP_SERVICES {
            if self.container_id(service)?.is_some() {
                remaining.push(service);
            }
        }
        let passed = output.success && remaining.is_empty();
        Ok(outcome(
            if passed {
                StepStatus::Pass
            } else {
                StepStatus::Fail
            },
            check,
            &format!(
                "Remove all app service containers for feed generation transition exit code {}; {} service container(s) remain.",
                output.exit_code.unwrap_or(1),
                remaining.len()
            ),
            json!({"exit_code": output.exit_code, "remaining_services": remaining}),
        ))
    }

    pub(super) fn start_pinned_services(
        &self,
        services: &[&str],
        check: &str,
        timeout: Duration,
    ) -> Result<StepOutcome, String> {
        self.start_pinned_services_with_delays(
            services,
            check,
            timeout,
            &[Duration::from_secs(8), Duration::from_secs(16)],
            std::thread::sleep,
        )
    }

    fn start_pinned_services_with_delays<F>(
        &self,
        services: &[&str],
        check: &str,
        timeout: Duration,
        retry_delays: &[Duration],
        mut wait: F,
    ) -> Result<StepOutcome, String>
    where
        F: FnMut(Duration),
    {
        if services
            .iter()
            .any(|service| !APP_SERVICES.contains(service))
        {
            return Err("invalid application service requested".into());
        }
        let mut arguments = vec![
            "--profile".to_owned(),
            "app".to_owned(),
            "up".to_owned(),
            "-d".to_owned(),
            "--no-deps".to_owned(),
            "--no-build".to_owned(),
            "--pull".to_owned(),
            "never".to_owned(),
            "--force-recreate".to_owned(),
        ];
        arguments.extend(services.iter().map(|service| (*service).to_owned()));
        let mut output = self.run_pinned_compose(&arguments, timeout)?;
        let transient_seen = !output.success && compose_up_transient_error(&output);
        let mut settled_after_failed_retry = false;
        if transient_seen {
            for delay in retry_delays.iter().take(2) {
                wait(*delay);
                output = self.run_pinned_compose(&arguments, Duration::from_secs(300))?;
                if output.success {
                    break;
                }
                if self.all_services_running(services)? {
                    settled_after_failed_retry = true;
                    break;
                }
                if !compose_up_transient_error(&output) {
                    break;
                }
            }
        }
        let mut missing = Vec::new();
        let mut mismatched = Vec::new();
        for service in services {
            if !self.container_running(service)? {
                missing.push(*service);
            }
            let observed = self.container_image_id(service)?;
            if observed.as_deref() != self.image_ids.get(*service).map(String::as_str) {
                mismatched.push(*service);
            }
        }
        let verified = missing.is_empty() && mismatched.is_empty();
        let status = if verified && (transient_seen || settled_after_failed_retry) {
            StepStatus::Warn
        } else if verified && output.success {
            StepStatus::Pass
        } else {
            StepStatus::Fail
        };
        Ok(outcome(
            status,
            check,
            &format!(
                "Start pinned application services exit code {}; {} are not running and {} use the wrong image{}.",
                output.exit_code.unwrap_or(1),
                missing.len(),
                mismatched.len(),
                if settled_after_failed_retry {
                    "; Docker reported a failed retry after all requested services settled"
                } else {
                    ""
                },
            ),
            json!({
                "exit_code": output.exit_code,
                "services": services,
                "missing_services": missing,
                "mismatched_image_services": mismatched,
                "transient_retry": transient_seen,
                "settled_after_failed_retry": settled_after_failed_retry,
            }),
        ))
    }

    fn all_services_running(&self, services: &[&str]) -> Result<bool, String> {
        services
            .iter()
            .map(|service| self.container_running(service))
            .collect::<Result<Vec<_>, _>>()
            .map(|states| states.into_iter().all(|running| running))
    }

    pub(super) fn run_pinned_compose(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, String> {
        let command = pinned_compose_command(self.repo_root, self.image_ids, arguments)?;
        self.run_docker(command, timeout)
    }

    pub(super) fn run_compose(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<ProcessOutput, String> {
        self.run_docker(compose_command(self.repo_root, arguments), timeout)
    }

    fn run_docker(&self, command: Vec<String>, timeout: Duration) -> Result<ProcessOutput, String> {
        let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
        self.runner
            .run_with(
                "docker",
                &arguments,
                Some(self.repo_root),
                Some(self.environment),
                Some(timeout),
            )
            .ok_or_else(|| "Docker command could not be started".to_owned())
    }

    fn container_id(&self, service: &str) -> Result<Option<String>, String> {
        if !APP_SERVICES.contains(&service) {
            return Err("invalid application service requested".into());
        }
        self.compose_container_id(service)
    }

    fn compose_container_id(&self, service: &str) -> Result<Option<String>, String> {
        let output = self.run_compose(
            &["ps".to_owned(), "-q".to_owned(), service.to_owned()],
            Duration::from_secs(120),
        )?;
        if !output.success {
            return Err("application container identity query failed".into());
        }
        let ids = output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        match ids.as_slice() {
            [] => Ok(None),
            [id] if id.bytes().all(|byte| byte.is_ascii_hexdigit()) => Ok(Some((*id).to_owned())),
            _ => Err("application container identity query was ambiguous".into()),
        }
    }

    fn container_running(&self, service: &str) -> Result<bool, String> {
        let Some(id) = self.container_id(service)? else {
            return Ok(false);
        };
        self.container_id_running(&id)
    }

    pub(super) fn scanner_redis_running(&self) -> Result<bool, String> {
        let Some(id) = self.compose_container_id("redis-openvas")? else {
            return Ok(false);
        };
        self.container_id_running(&id)
    }

    fn container_id_running(&self, id: &str) -> Result<bool, String> {
        let output = self
            .runner
            .run_with(
                "docker",
                &["inspect", "-f", "{{.State.Running}}", id],
                Some(self.repo_root),
                Some(self.environment),
                Some(Duration::from_secs(120)),
            )
            .ok_or_else(|| "application container state query could not be started".to_owned())?;
        if !output.success {
            return Err("application container state query failed".into());
        }
        Ok(output.stdout.trim() == "true")
    }

    fn container_image_id(&self, service: &str) -> Result<Option<String>, String> {
        let Some(id) = self.container_id(service)? else {
            return Ok(None);
        };
        let output = self
            .runner
            .run_with(
                "docker",
                &["inspect", "--format", "{{.Image}}", &id],
                Some(self.repo_root),
                Some(self.environment),
                Some(Duration::from_secs(120)),
            )
            .ok_or_else(|| "application container image query could not be started".to_owned())?;
        if !output.success {
            return Err("application container image query failed".into());
        }
        let value = output.stdout.trim();
        if value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Some(value.to_owned()))
        } else {
            Ok(None)
        }
    }
}

fn outcome(
    status: StepStatus,
    check: &str,
    message: &str,
    details: serde_json::Value,
) -> StepOutcome {
    StepOutcome::with_evidence(
        status,
        vec![Finding::new(status_name(status), check, message.to_owned()).with_details(details)],
        Vec::new(),
    )
}

fn status_name(status: StepStatus) -> &'static str {
    match status {
        StepStatus::Pass => "pass",
        StepStatus::Warn => "warn",
        StepStatus::Fail => "fail",
    }
}

fn compose_up_transient_error(output: &ProcessOutput) -> bool {
    let combined = format!("{}{}", output.stdout, output.stderr);
    [
        "No such container:",
        "removal of container",
        "is already in progress",
    ]
    .iter()
    .any(|fragment| combined.contains(fragment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Runner {
        outputs: Mutex<VecDeque<Option<ProcessOutput>>>,
        commands: Mutex<Vec<Vec<String>>>,
    }

    impl Runner {
        fn new(outputs: impl IntoIterator<Item = Option<ProcessOutput>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into_iter().collect()),
                commands: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            unreachable!("service runtime uses run_with")
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            _env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            let mut command = vec![program.to_owned()];
            command.extend(args.iter().map(|argument| (*argument).to_owned()));
            self.commands.lock().unwrap().push(command);
            self.outputs.lock().unwrap().pop_front().flatten()
        }
    }

    fn output(success: bool, stdout: impl Into<String>) -> Option<ProcessOutput> {
        output_with_stderr(success, stdout, "")
    }

    fn output_with_stderr(
        success: bool,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Option<ProcessOutput> {
        Some(ProcessOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: stderr.into(),
        })
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
        let base = std::env::current_dir().unwrap().join(format!(
            ".yafvsctl-service-runtime-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("TurboVAS");
        std::fs::create_dir_all(repo.join("compose")).unwrap();
        (base, repo)
    }

    #[test]
    fn remove_apps_requires_every_container_to_be_absent() {
        let runner = Runner::new(
            [output(true, "")]
                .into_iter()
                .chain(APP_SERVICES.map(|_| output(true, ""))),
        );
        let images = images();
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(Path::new("/repo"), &runner, &environment, &images);
        let result = runtime.remove_apps("feed-generation.stop-app").unwrap();
        assert_eq!(result.status, StepStatus::Pass);
        assert!(runner.commands.lock().unwrap()[0].contains(&"rm".to_owned()));
    }

    #[test]
    fn start_services_checks_running_state_and_pinned_images() {
        let (base, repo) = fixture_repo();
        let images = images();
        let mut outputs = vec![output(true, "")];
        for service in SCANNER_SERVICES {
            let id = format!("abc{}", service.len());
            outputs.push(output(true, format!("{id}\n")));
            outputs.push(output(true, "true\n"));
            outputs.push(output(true, format!("{id}\n")));
            outputs.push(output(true, format!("{}\n", images.get(service).unwrap())));
        }
        let runner = Runner::new(outputs);
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);
        let result = runtime
            .start_pinned_services(
                &SCANNER_SERVICES,
                "runtime.scanner-services-up",
                Duration::from_secs(900),
            )
            .unwrap();
        assert_eq!(result.status, StepStatus::Pass);
        assert!(runner.commands.lock().unwrap()[0].contains(&"--no-build".to_owned()));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn start_services_does_not_retry_non_transient_failure() {
        let (base, repo) = fixture_repo();
        let images = images();
        let runner = Runner::new([
            output_with_stderr(false, "", "daemon rejected request"),
            output(true, ""),
            output(true, ""),
        ]);
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);
        let mut waits = Vec::new();
        let result = runtime
            .start_pinned_services_with_delays(
                &["gvmd"],
                "runtime.app-up",
                Duration::from_secs(900),
                &[Duration::ZERO, Duration::ZERO],
                |delay| waits.push(delay),
            )
            .unwrap();
        assert_eq!(result.status, StepStatus::Fail);
        assert!(waits.is_empty());
        assert_eq!(
            runner
                .commands
                .lock()
                .unwrap()
                .iter()
                .filter(|command| command.contains(&"up".to_owned()))
                .count(),
            1
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn start_services_retries_transient_failure_successfully() {
        let (base, repo) = fixture_repo();
        let images = images();
        let id = "abc123";
        let runner = Runner::new([
            output_with_stderr(false, "", "No such container: stale"),
            output(true, ""),
            output(true, format!("{id}\n")),
            output(true, "true\n"),
            output(true, format!("{id}\n")),
            output(true, format!("{}\n", images["gvmd"])),
        ]);
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);
        let mut waits = Vec::new();
        let result = runtime
            .start_pinned_services_with_delays(
                &["gvmd"],
                "runtime.app-up",
                Duration::from_secs(900),
                &[Duration::from_secs(8), Duration::from_secs(16)],
                |delay| waits.push(delay),
            )
            .unwrap();
        assert_eq!(result.status, StepStatus::Warn);
        assert_eq!(waits, vec![Duration::from_secs(8)]);
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["transient_retry"],
            json!(true)
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn start_services_bounds_persistent_transient_retries() {
        let (base, repo) = fixture_repo();
        let images = images();
        let runner = Runner::new([
            output_with_stderr(false, "", "removal of container pending"),
            output_with_stderr(false, "", "is already in progress"),
            output(true, ""),
            output_with_stderr(false, "", "No such container: stale"),
            output(true, ""),
            output(true, ""),
            output(true, ""),
        ]);
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);
        let mut waits = Vec::new();
        let result = runtime
            .start_pinned_services_with_delays(
                &["gvmd"],
                "runtime.app-up",
                Duration::from_secs(900),
                &[Duration::from_secs(8), Duration::from_secs(16)],
                |delay| waits.push(delay),
            )
            .unwrap();
        assert_eq!(result.status, StepStatus::Fail);
        assert_eq!(waits, vec![Duration::from_secs(8), Duration::from_secs(16)]);
        assert_eq!(
            runner
                .commands
                .lock()
                .unwrap()
                .iter()
                .filter(|command| command.contains(&"up".to_owned()))
                .count(),
            3
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn start_services_warns_when_failed_retry_settles_all_services() {
        let (base, repo) = fixture_repo();
        let images = images();
        let id = "abc123";
        let runner = Runner::new([
            output_with_stderr(false, "", "No such container: stale"),
            output_with_stderr(false, "", "removal of container pending"),
            output(true, format!("{id}\n")),
            output(true, "true\n"),
            output(true, format!("{id}\n")),
            output(true, "true\n"),
            output(true, format!("{id}\n")),
            output(true, format!("{}\n", images["gvmd"])),
        ]);
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(&repo, &runner, &environment, &images);
        let result = runtime
            .start_pinned_services_with_delays(
                &["gvmd"],
                "runtime.app-up",
                Duration::from_secs(900),
                &[Duration::ZERO, Duration::ZERO],
                |_| {},
            )
            .unwrap();
        assert_eq!(result.status, StepStatus::Warn);
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["mismatched_image_services"],
            json!([])
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn running_image_identity_rejects_a_mismatched_container() {
        let images = images();
        let gvmd_id = "abc123";
        let wrong_image = format!("sha256:{}", "f".repeat(64));
        let runner = Runner::new(
            [
                output(true, format!("{gvmd_id}\n")),
                output(true, "true\n"),
                output(true, format!("{gvmd_id}\n")),
                output(true, format!("{wrong_image}\n")),
            ]
            .into_iter()
            .chain((1..APP_SERVICES.len()).map(|_| output(true, ""))),
        );
        let environment = BTreeMap::new();
        let runtime = ServiceRuntime::new(Path::new("/repo"), &runner, &environment, &images);
        let result = runtime.running_app_image_identity().unwrap();
        assert_eq!(result.status, StepStatus::Fail);
        assert_eq!(
            result.findings[0].details.as_ref().unwrap()["mismatched_services"],
            json!(["gvmd"])
        );
        assert!(
            runner
                .commands
                .lock()
                .unwrap()
                .iter()
                .all(|command| !command.contains(&"stop".to_owned())
                    && !command.contains(&"rm".to_owned()))
        );
    }
}
