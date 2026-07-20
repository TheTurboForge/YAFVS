// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guarded registration of the prepared OpenVAS scanner with the pinned gvmd.

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::runtime_app_environment;
use super::feed_generation::{require_current_app_deployment, run_pinned_gvmd};
use super::runtime_lock::{
    DEFAULT_RUNTIME_LOCK_TIMEOUT, FEED_ACTIVATION_LOCK, RuntimeLockError, RuntimeOperationLock,
    runtime_lock_dir,
};
use super::runtime_probe::{command_runtime_gmp_smoke_with, socket_readiness_finding};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "runtime-scanner-register";
const SCANNER_NAME: &str = "OpenVAS Default";
const SCANNER_SOCKET: &str = "/runtime/run/ospd/ospd-openvas.sock";

pub fn command_runtime_scanner_register(repo_root: &Path) -> ResultEnvelope {
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
    let _lock =
        match RuntimeOperationLock::acquire(repo_root, FEED_ACTIVATION_LOCK, COMMAND, timeout) {
            Ok(lock) => lock,
            Err(error) => return lock_failure(repo_root, runner, error),
        };
    let mut context = SystemContext { repo_root, runner };
    command_unlocked(repo_root, runner, &mut context)
}

trait RegisterContext {
    fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String>;
    fn deployment(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<BTreeMap<String, String>, String>;
    fn ospd_socket(&mut self) -> Finding;
    fn gmp_smoke(&mut self) -> ResultEnvelope;
    fn gvmd(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
        images: &BTreeMap<String, String>,
        command: &[String],
    ) -> Option<ProcessOutput>;
}

struct SystemContext<'a> {
    repo_root: &'a Path,
    runner: &'a dyn CommandRunner,
}

impl RegisterContext for SystemContext<'_> {
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
    fn ospd_socket(&mut self) -> Finding {
        socket_readiness_finding(
            "ospd.socket",
            "ospd-openvas",
            &runtime_dir(self.repo_root).join("run/ospd/ospd-openvas.sock"),
            "fail",
        )
    }
    fn gmp_smoke(&mut self) -> ResultEnvelope {
        command_runtime_gmp_smoke_with(self.repo_root, self.runner)
    }
    fn gvmd(
        &mut self,
        environment: &BTreeMap<OsString, OsString>,
        images: &BTreeMap<String, String>,
        command: &[String],
    ) -> Option<ProcessOutput> {
        let command = command.iter().map(String::as_str).collect::<Vec<_>>();
        run_pinned_gvmd(self.repo_root, self.runner, environment, images, &command).ok()
    }
}

fn command_unlocked(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    context: &mut dyn RegisterContext,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let environment = match context.app_environment() {
        Ok(value) => value,
        Err(error) => {
            return result(
                repo_root,
                runner,
                "Runtime scanner registration stopped at prerequisites.",
                vec![Finding::new("fail", "runtime.app-environment", error)],
            );
        }
    };
    let images = match context.deployment(&environment) {
        Ok(value) => {
            findings.push(Finding::new(
                "pass",
                "runtime.app-deployment-receipt",
                "Prepared application deployment receipt is valid for scanner registration.".into(),
            ));
            value
        }
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.app-deployment-receipt",
                error,
            ));
            return result(
                repo_root,
                runner,
                "Runtime scanner registration stopped at prerequisites.",
                findings,
            );
        }
    };
    let socket = context.ospd_socket();
    let ready = socket.status == "pass";
    findings.push(socket);
    if !ready {
        return result(
            repo_root,
            runner,
            "Runtime scanner registration stopped at prerequisites.",
            findings,
        );
    }
    let gmp = context.gmp_smoke();
    let gmp_ok = gmp.status == "pass";
    findings.push(
        Finding::new(
            if gmp_ok { "pass" } else { "fail" },
            "gvmd.gmp",
            gmp.summary,
        )
        .with_details(json!({"status": gmp.status})),
    );
    if !gmp_ok {
        return result(
            repo_root,
            runner,
            "Scanner registration stopped at prerequisites.",
            findings,
        );
    }

    let listed = match context.gvmd(&environment, &images, &["--get-scanners".into()]) {
        Some(output) => output,
        None => {
            findings.push(command_finding(
                false,
                "gvmd.get-scanners",
                "Pinned manager scanner listing could not be started.",
                None,
                None,
                &[],
            ));
            return result(
                repo_root,
                runner,
                "Scanner registration stopped while listing scanners.",
                findings,
            );
        }
    };
    if !listed.success {
        findings.push(command_finding(
            false,
            "gvmd.get-scanners",
            "Pinned manager scanner listing failed.",
            listed.exit_code,
            None,
            &output_tail(&listed.stdout, 80),
        ));
        return result(
            repo_root,
            runner,
            "Scanner registration stopped while listing scanners.",
            findings,
        );
    }
    let mut uuid = parse_openvas_default_uuid(&listed.stdout);
    findings.push(command_finding(
        true,
        "gvmd.get-scanners",
        "Pinned manager scanner listing completed.",
        listed.exit_code,
        uuid.as_deref(),
        &output_tail(&listed.stdout, 80),
    ));
    let mutation = scanner_contract(uuid.as_deref());
    let modifying = uuid.is_some();
    let mutation_output = context.gvmd(&environment, &images, &mutation);
    let mutation_ok = mutation_output
        .as_ref()
        .is_some_and(|output| output.success);
    if !modifying && let Some(output) = mutation_output.as_ref() {
        uuid = parse_created_scanner_uuid(&output.stdout);
    }
    findings.push(match mutation_output.as_ref() {
        Some(output) => command_finding(
            mutation_ok,
            if modifying {
                "gvmd.modify-scanner"
            } else {
                "gvmd.create-scanner"
            },
            "Pinned manager scanner mutation.",
            output.exit_code,
            uuid.as_deref(),
            &output_tail(&output.stdout, 80),
        ),
        None => command_finding(
            false,
            if modifying {
                "gvmd.modify-scanner"
            } else {
                "gvmd.create-scanner"
            },
            "Pinned manager scanner mutation could not be started.",
            None,
            uuid.as_deref(),
            &[],
        ),
    });
    let post_list = context.gvmd(&environment, &images, &["--get-scanners".into()]);
    if let Some(output) = post_list.as_ref().filter(|output| output.success) {
        uuid = parse_openvas_default_uuid(&output.stdout);
    }
    let (exit_code, tail) = post_list.as_ref().map_or((None, Vec::new()), |output| {
        (output.exit_code, output_tail(&output.stdout, 80))
    });
    findings.push(command_finding(
        uuid.is_some(),
        "gvmd.scanner.openvas-default",
        "OpenVAS Default scanner identity confirmation.",
        exit_code,
        uuid.as_deref(),
        &tail,
    ));
    if let Some(uuid) = uuid {
        let verified = context.gvmd(&environment, &images, &[format!("--verify-scanner={uuid}")]);
        let (success, exit_code, tail) = verified.map_or((false, None, Vec::new()), |output| {
            (
                output.success,
                output.exit_code,
                output_tail(&output.stdout, 100),
            )
        });
        findings.push(
            Finding::new(
                if success { "pass" } else { "warn" },
                "gvmd.verify-scanner",
                if success {
                    "Pinned manager scanner verification completed."
                } else {
                    "Pinned manager scanner verification did not complete."
                }
                .into(),
            )
            .with_details(json!({"exit_code": exit_code, "uuid": uuid, "output_tail": tail})),
        );
    }
    result(
        repo_root,
        runner,
        "Runtime scanner registration completed.",
        findings,
    )
}

fn scanner_contract(uuid: Option<&str>) -> Vec<String> {
    let mut command = match uuid {
        Some(uuid) => vec![
            format!("--modify-scanner={uuid}"),
            format!("--scanner-name={SCANNER_NAME}"),
        ],
        None => vec![format!("--create-scanner={SCANNER_NAME}")],
    };
    command.extend([
        "--scanner-type=OpenVAS".to_owned(),
        format!("--scanner-host={SCANNER_SOCKET}"),
        "--scanner-port=0".to_owned(),
        "--no-default-certs".to_owned(),
    ]);
    command
}

fn parse_openvas_default_uuid(output: &str) -> Option<String> {
    parse_uuid_on_named_line(output, &["OpenVAS", "Default"])
}

pub(crate) fn scanner_registration_finding(output: Option<&ProcessOutput>) -> Finding {
    let scanner_uuid = output
        .filter(|output| output.success)
        .and_then(|output| parse_openvas_default_uuid(&output.stdout));
    Finding::new(
        if scanner_uuid.is_some() {
            "pass"
        } else {
            "warn"
        },
        "gvmd.scanner.openvas-default",
        if scanner_uuid.is_some() {
            "OpenVAS Default scanner is registered."
        } else {
            "OpenVAS Default scanner is not registered."
        }
        .into(),
    )
    .with_details(json!({
        "scanner_uuid": scanner_uuid,
        "output_tail": output
            .map(|output| output_tail(&output.stdout, 80))
            .unwrap_or_default(),
    }))
}

fn parse_created_scanner_uuid(output: &str) -> Option<String> {
    parse_openvas_default_uuid(output).or_else(|| parse_uuid_on_named_line(output, &["Scanner"]))
}

fn parse_uuid_on_named_line(output: &str, name: &[&str]) -> Option<String> {
    output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields
            .windows(name.len())
            .any(|words| words == name)
            .then(|| fields.iter().find_map(|field| canonical_uuid(field)))
            .flatten()
    })
}

fn canonical_uuid(value: &str) -> Option<String> {
    (value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }))
    .then(|| value.to_ascii_lowercase())
}

fn command_finding(
    passed: bool,
    check: &str,
    message: &str,
    exit_code: Option<i32>,
    uuid: Option<&str>,
    tail: &[String],
) -> Finding {
    Finding::new(if passed { "pass" } else { "fail" }, check, message.into())
        .with_details(json!({"exit_code": exit_code, "uuid": uuid, "output_tail": tail}))
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
            format!("Timed out waiting for runtime lock {name:?}."),
            json!({"operation": operation, "holder": holder}),
        ),
        RuntimeLockError::Setup(message) => (
            format!("Runtime feed lifecycle lock failed closed: {message}."),
            json!({}),
        ),
    };
    result(
        repo_root,
        runner,
        "Runtime scanner registration stopped while waiting for the feed lifecycle lock.",
        vec![
            Finding::new("fail", "feed-generation.activation-lock", message)
                .with_path(&runtime_lock_dir(repo_root).display().to_string())
                .with_details(details),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Runner {
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.calls.lock().unwrap().push(
                std::iter::once(program.into())
                    .chain(args.iter().map(|arg| (*arg).into()))
                    .collect(),
            );
            Some(output(true, 0, ""))
        }
    }
    struct Context {
        outputs: VecDeque<Option<ProcessOutput>>,
        calls: Vec<Vec<String>>,
        ready: bool,
    }
    impl Context {
        fn ready(outputs: Vec<Option<ProcessOutput>>) -> Self {
            Self {
                outputs: outputs.into(),
                calls: Vec::new(),
                ready: true,
            }
        }
    }
    impl RegisterContext for Context {
        fn app_environment(&mut self) -> Result<BTreeMap<OsString, OsString>, String> {
            self.ready
                .then(BTreeMap::new)
                .ok_or_else(|| "environment unavailable".into())
        }
        fn deployment(
            &mut self,
            _: &BTreeMap<OsString, OsString>,
        ) -> Result<BTreeMap<String, String>, String> {
            self.ready
                .then(BTreeMap::new)
                .ok_or_else(|| "deployment unavailable".into())
        }
        fn ospd_socket(&mut self) -> Finding {
            Finding::new(
                if self.ready { "pass" } else { "fail" },
                "ospd.socket",
                "socket".into(),
            )
        }
        fn gmp_smoke(&mut self) -> ResultEnvelope {
            make_result(
                metadata(Path::new("/repo"), COMMAND, &Runner::default()),
                "gmp".into(),
                vec![Finding::new(
                    if self.ready { "pass" } else { "fail" },
                    "probe",
                    "probe".into(),
                )],
            )
        }
        fn gvmd(
            &mut self,
            _: &BTreeMap<OsString, OsString>,
            _: &BTreeMap<String, String>,
            command: &[String],
        ) -> Option<ProcessOutput> {
            self.calls.push(command.to_vec());
            self.outputs.pop_front().flatten()
        }
    }
    fn output(success: bool, code: i32, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success,
            exit_code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
    fn run(context: &mut Context) -> ResultEnvelope {
        command_unlocked(Path::new("/repo"), &Runner::default(), context)
    }
    const UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    fn existing() -> String {
        format!("{UUID} OpenVAS Default")
    }
    #[test]
    fn existing_scanner_modifies_with_exact_contract() {
        let mut c = Context::ready(vec![
            Some(output(true, 0, &existing())),
            Some(output(true, 0, "")),
            Some(output(true, 0, &existing())),
            Some(output(true, 0, "")),
        ]);
        assert_eq!(run(&mut c).status, "pass");
        assert_eq!(c.calls[1], scanner_contract(Some(UUID)));
    }
    #[test]
    fn absent_scanner_creates_and_parses_uuid() {
        let mut c = Context::ready(vec![
            Some(output(true, 0, "other")),
            Some(output(true, 0, &format!("Scanner {UUID}"))),
            Some(output(false, 1, "confirmation unavailable")),
            Some(output(true, 0, "")),
        ]);
        assert_eq!(run(&mut c).status, "pass");
        assert_eq!(c.calls[1], scanner_contract(None));
        assert_eq!(c.calls[3], vec![format!("--verify-scanner={UUID}")]);
    }
    #[test]
    fn parser_rejects_lookalikes_and_malformed_values() {
        assert_eq!(
            parse_openvas_default_uuid(&format!("x{UUID} OpenVAS Default")),
            None
        );
        assert_eq!(
            parse_openvas_default_uuid("123e4567-e89b-12d3-a456-42661417400z OpenVAS Default"),
            None
        );
        assert_eq!(
            parse_openvas_default_uuid(&format!("{UUID} OpenVAS Defaultish")),
            None
        );
    }
    #[test]
    fn initial_list_failure_stops() {
        let mut c = Context::ready(vec![Some(output(false, 1, "no"))]);
        assert_eq!(run(&mut c).status, "fail");
        assert_eq!(c.calls.len(), 1);
    }
    #[test]
    fn mutation_failure_remains_fail_after_confirmation() {
        let mut c = Context::ready(vec![
            Some(output(true, 0, &existing())),
            Some(output(false, 1, "no")),
            Some(output(true, 0, &existing())),
            Some(output(true, 0, "")),
        ]);
        assert_eq!(run(&mut c).status, "fail");
        assert_eq!(c.calls.len(), 4);
    }
    #[test]
    fn post_list_failure_preserves_candidate() {
        let mut c = Context::ready(vec![
            Some(output(true, 0, &existing())),
            Some(output(true, 0, "")),
            Some(output(false, 1, "bad")),
            Some(output(true, 0, "")),
        ]);
        assert_eq!(run(&mut c).status, "pass");
        assert_eq!(c.calls[3], vec![format!("--verify-scanner={UUID}")]);
    }
    #[test]
    fn verify_failure_is_warn() {
        let mut c = Context::ready(vec![
            Some(output(true, 0, &existing())),
            Some(output(true, 0, "")),
            Some(output(true, 0, &existing())),
            Some(output(false, 1, "bad")),
        ]);
        let result = run(&mut c);
        assert_eq!(result.status, "warn");
        assert_eq!(result.findings.last().unwrap().check, "gvmd.verify-scanner");
    }
    #[test]
    fn prerequisite_failure_runs_no_mutation() {
        let mut c = Context::ready(vec![]);
        c.ready = false;
        assert_eq!(run(&mut c).status, "fail");
        assert!(c.calls.is_empty());
    }
    #[test]
    fn lock_contention_fails_closed() {
        let root = std::env::temp_dir().join(format!("yafvs-register-lock-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let _holder =
            RuntimeOperationLock::acquire(&root, FEED_ACTIVATION_LOCK, "holder", Duration::ZERO)
                .unwrap();
        let runner = Runner::default();
        let result = command_with_runner_and_timeout(&root, &runner, Duration::ZERO);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "feed-generation.activation-lock");
        assert!(
            runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.first().is_none_or(|program| program != "docker"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pinned_gvmd_helper_uses_exact_images_with_pull_never_and_without_no_deps() {
        let parent =
            std::env::temp_dir().join(format!("yafvs-register-pinned-{}", std::process::id()));
        let repo = parent.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let image = format!("sha256:{}", "a".repeat(64));
        let images = ["gvmd", "ospd-openvas", "notus-scanner", "gsad", "yafvs-api"]
            .into_iter()
            .map(|service| (service.to_owned(), image.clone()))
            .collect();
        let runner = Runner::default();
        let environment = BTreeMap::from([
            (OsString::from("POSTGRES_DB"), OsString::from("yafvs")),
            (OsString::from("POSTGRES_USER"), OsString::from("yafvs")),
        ]);
        let output =
            run_pinned_gvmd(&repo, &runner, &environment, &images, &["--get-scanners"]).unwrap();
        assert!(output.success);
        let call = runner.calls.lock().unwrap().pop().unwrap();
        assert_eq!(call[0], "docker");
        assert!(call.windows(2).any(|pair| pair == ["--pull", "never"]));
        assert!(!call.iter().any(|argument| argument == "--no-deps"));
        assert!(call.iter().any(|argument| argument == "gvmd"));
        let override_path = parent.join("YAFVS-runtime/state/feed-generation/app-images.json");
        let override_json = std::fs::read_to_string(&override_path).unwrap();
        assert!(override_json.contains(&image));
        let _ = std::fs::remove_dir_all(&parent);
    }
}
