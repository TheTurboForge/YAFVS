// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{executable_path, metadata, output_tail, runtime_dir};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const UNITS: [&str; 2] = ["yafvs-quality-gate.service", "yafvs-quality-gate.timer"];
const TIMER: &str = "yafvs-quality-gate.timer";
const ENABLE_ENV: &str = "YAFVS_ENABLE_QUALITY_GATE_SCHEDULE";
const SHOW_PROPERTIES: &str = "--property=LoadState,UnitFileState,ActiveState,SubState,NextElapseUSecRealtime,LastTriggerUSecRealtime";

#[derive(Debug, Clone)]
struct QualityScheduleContext {
    enabled: bool,
    unit_dir: PathBuf,
    runtime_dir: PathBuf,
    log_dir: PathBuf,
    host: String,
    user: String,
}

pub fn command_quality_gate_schedule(repo_root: &Path, action: &str) -> ResultEnvelope {
    command_quality_gate_schedule_with_runner(
        repo_root,
        action,
        &SystemCommandRunner,
        &production_context(repo_root),
    )
}

fn command_quality_gate_schedule_with_runner(
    repo_root: &Path,
    action: &str,
    runner: &dyn CommandRunner,
    context: &QualityScheduleContext,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let mut details = json!({
        "action": action,
        "host": context.host,
        "user": context.user,
    });
    if action == "install" {
        if !context.enabled {
            return make_result(
                metadata(repo_root, "quality-gate-schedule", runner),
                "Quality gate schedule installation refused without explicit host opt-in."
                    .to_string(),
                vec![Finding::new(
                    "fail",
                    "quality-gate-schedule.opt-in",
                    format!("Quality gate timer installation requires {ENABLE_ENV}=1."),
                )],
            );
        }
        let systemd = systemctl_user(runner, repo_root, &["status"], 30);
        if exit_code(&systemd) != 0 {
            findings.push(process_step_finding(
                "fail",
                "quality-gate-schedule.systemd-user",
                "User-level systemd is unavailable; refusing to fall back to cron.".to_string(),
                &systemd,
                &["systemctl", "--user", "status"],
            ));
            return make_result(
                metadata(repo_root, "quality-gate-schedule", runner),
                "Quality gate schedule installation blocked because user-level systemd is unavailable."
                    .to_string(),
                findings,
            )
            .with_details(details);
        }
        fs::create_dir_all(&context.unit_dir)
            .expect("could not create systemd user unit directory");
        fs::create_dir_all(&context.log_dir).expect("could not create quality gate log directory");
        for unit in UNITS {
            let target = context.unit_dir.join(unit);
            fs::write(&target, render_unit(repo_root, unit, context))
                .expect("could not write quality gate systemd unit");
            findings.push(
                Finding::new(
                    "pass",
                    "quality-gate-schedule.unit-written",
                    format!("Wrote {unit} user unit."),
                )
                .with_path(&target.display().to_string()),
            );
        }
        let reload = systemctl_user(runner, repo_root, &["daemon-reload"], 60);
        findings.push(process_step_finding(
            if exit_code(&reload) == 0 {
                "pass"
            } else {
                "fail"
            },
            "quality-gate-schedule.daemon-reload",
            format!(
                "systemctl --user daemon-reload exit code {}.",
                exit_code(&reload)
            ),
            &reload,
            &["systemctl", "--user", "daemon-reload"],
        ));
        let enable = systemctl_user(runner, repo_root, &["enable", "--now", TIMER], 60);
        findings.push(process_step_finding(
            if exit_code(&enable) == 0 {
                "pass"
            } else {
                "fail"
            },
            "quality-gate-schedule.enable",
            format!("Enabled {TIMER} with exit code {}.", exit_code(&enable)),
            &enable,
            &["systemctl", "--user", "enable", "--now", TIMER],
        ));
    } else if action == "disable" {
        let disable = systemctl_user(runner, repo_root, &["disable", "--now", TIMER], 60);
        findings.push(process_step_finding(
            if exit_code(&disable) == 0 {
                "pass"
            } else {
                "warn"
            },
            "quality-gate-schedule.disable",
            format!("Disabled {TIMER} with exit code {}.", exit_code(&disable)),
            &disable,
            &["systemctl", "--user", "disable", "--now", TIMER],
        ));
    } else if action != "status" {
        return make_result(
            metadata(repo_root, "quality-gate-schedule", runner),
            "Unknown quality gate schedule action.".to_string(),
            vec![Finding::new(
                "fail",
                "quality-gate-schedule.action",
                format!("Unknown schedule action {action}."),
            )],
        );
    }

    let (status_findings, status_details) = schedule_status(runner, repo_root, context);
    findings.extend(status_findings);
    details
        .as_object_mut()
        .expect("schedule details must be an object")
        .insert("status".to_string(), status_details);
    make_result(
        metadata(repo_root, "quality-gate-schedule", runner),
        if action == "status" {
            "Quality gate schedule status collected.".to_string()
        } else {
            format!("Quality gate schedule {action} completed.")
        },
        findings,
    )
    .with_artifacts(
        UNITS
            .iter()
            .map(|unit| context.unit_dir.join(unit).display().to_string())
            .collect(),
    )
    .with_details(details)
}

fn schedule_status(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    context: &QualityScheduleContext,
) -> (Vec<Finding>, Value) {
    let mut findings = Vec::new();
    let mut units = Map::new();
    let systemd = systemctl_user(runner, repo_root, &["status"], 30);
    findings.push(process_step_finding(
        if exit_code(&systemd) == 0 {
            "pass"
        } else {
            "fail"
        },
        "quality-gate-schedule.systemd-user",
        format!("systemctl --user status exit code {}.", exit_code(&systemd)),
        &systemd,
        &["systemctl", "--user", "status"],
    ));
    for unit in UNITS {
        let path = context.unit_dir.join(unit);
        let exists = path.is_file();
        findings.push(
            Finding::new(
                if exists { "pass" } else { "warn" },
                "quality-gate-schedule.unit-file",
                if exists {
                    format!("{unit} is installed in the user unit directory.")
                } else {
                    format!("{unit} is not installed in the user unit directory.")
                },
            )
            .with_path(&path.display().to_string()),
        );
        let show = systemctl_user(runner, repo_root, &["show", unit, SHOW_PROPERTIES], 30);
        let properties = if exit_code(&show) == 0 {
            systemd_show_properties(&show.stdout)
        } else {
            BTreeMap::new()
        };
        if exit_code(&show) == 0 && properties.get("ActiveState").is_some_and(|v| v == "failed") {
            findings.push(
                Finding::new(
                    "fail",
                    "quality-gate-schedule.unit-state",
                    format!("{unit} is in failed state."),
                )
                .with_path(&path.display().to_string())
                .with_details(json!(properties)),
            );
        }
        units.insert(
            unit.to_string(),
            json!({
                "path": path.display().to_string(),
                "exists": exists,
                "systemctl_show_exit_code": exit_code(&show),
                "properties": properties,
            }),
        );
    }
    let enabled = systemctl_user(runner, repo_root, &["is-enabled", TIMER], 30);
    let active = systemctl_user(runner, repo_root, &["is-active", TIMER], 30);
    let enabled_text = enabled.stdout.trim();
    let active_text = active.stdout.trim();
    if context.unit_dir.join(TIMER).is_file() {
        findings.push(process_step_finding(
            if exit_code(&enabled) == 0 {
                "pass"
            } else {
                "warn"
            },
            "quality-gate-schedule.enabled",
            format!(
                "{TIMER} enablement is {}.",
                if enabled_text.is_empty() {
                    "unknown"
                } else {
                    enabled_text
                }
            ),
            &enabled,
            &["systemctl", "--user", "is-enabled", TIMER],
        ));
        findings.push(process_step_finding(
            if exit_code(&active) == 0 {
                "pass"
            } else {
                "warn"
            },
            "quality-gate-schedule.active",
            format!(
                "{TIMER} activity is {}.",
                if active_text.is_empty() {
                    "unknown"
                } else {
                    active_text
                }
            ),
            &active,
            &["systemctl", "--user", "is-active", TIMER],
        ));
    }
    (
        findings,
        json!({
            "host": context.host,
            "user": context.user,
            "unit_dir": context.unit_dir.display().to_string(),
            "units": units,
            "systemd_user_available": exit_code(&systemd) == 0,
            "timer_enabled": enabled_text,
            "timer_active": active_text,
        }),
    )
}

fn systemctl_user(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    arguments: &[&str],
    timeout_seconds: u64,
) -> ProcessOutput {
    let mut command = vec!["--user"];
    command.extend_from_slice(arguments);
    runner
        .run_with(
            "systemctl",
            &command,
            Some(repo_root),
            Some(&systemd_user_environment()),
            Some(Duration::from_secs(timeout_seconds)),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: String::new(),
        })
}

fn systemd_user_environment() -> BTreeMap<OsString, OsString> {
    let mut environment = env::vars_os().collect::<BTreeMap<_, _>>();
    // SAFETY: getuid has no preconditions and does not dereference memory.
    let uid = unsafe { libc::getuid() };
    environment
        .entry(OsString::from("XDG_RUNTIME_DIR"))
        .or_insert_with(|| OsString::from(format!("/run/user/{uid}")));
    environment
}

fn process_step_finding(
    status: &str,
    check: &str,
    message: String,
    output: &ProcessOutput,
    command: &[&str],
) -> Finding {
    Finding::new(status, check, message).with_details(json!({
        "exit_code": exit_code(output),
        "output_tail": output_tail(&output.stdout, 100),
        "command": command.join(" "),
    }))
}

fn exit_code(output: &ProcessOutput) -> i32 {
    output.exit_code.unwrap_or(1)
}

fn systemd_show_properties(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn render_unit(repo_root: &Path, unit: &str, context: &QualityScheduleContext) -> String {
    let template = fs::read_to_string(repo_root.join(format!("ops/systemd/{unit}.in")))
        .expect("could not read quality gate systemd template");
    let python = executable_path("python3")
        .unwrap_or_else(|| PathBuf::from("python3"))
        .display()
        .to_string();
    template
        .replace("@REPO_ROOT@", &repo_root.display().to_string())
        .replace("@PYTHON@", &python)
        .replace("@RUNTIME_DIR@", &context.runtime_dir.display().to_string())
        .replace(
            "@QUALITY_GATE_LOG_DIR@",
            &context.log_dir.display().to_string(),
        )
}

fn systemd_user_unit_dir() -> PathBuf {
    home_dir().join(".config/systemd/user")
}

fn quality_gate_log_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("logs/quality-gate")
}

fn production_context(repo_root: &Path) -> QualityScheduleContext {
    QualityScheduleContext {
        enabled: env::var(ENABLE_ENV).ok().as_deref() == Some("1"),
        unit_dir: systemd_user_unit_dir(),
        runtime_dir: runtime_dir(repo_root),
        log_dir: quality_gate_log_dir(repo_root),
        host: hostname(),
        user: env::var("USER")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(home_name),
    }
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn home_name() -> String {
    home_dir()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string()
}

fn hostname() -> String {
    let mut buffer = [0_u8; 256];
    // SAFETY: buffer is valid for its full length and gethostname writes at
    // most that many bytes. We search for the first NUL before decoding.
    let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if status != 0 {
        return String::new();
    }
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..length]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedCommand {
        program: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        has_xdg_runtime_dir: bool,
        timeout: Option<Duration>,
    }

    struct FakeCommandRunner {
        outputs: BTreeMap<String, ProcessOutput>,
        records: Mutex<Vec<RecordedCommand>>,
    }

    impl FakeCommandRunner {
        fn new(outputs: BTreeMap<String, ProcessOutput>) -> Self {
            Self {
                outputs,
                records: Mutex::new(Vec::new()),
            }
        }

        fn records(&self) -> Vec<RecordedCommand> {
            self.records.lock().unwrap().clone()
        }

        fn output(&self, args: &[&str]) -> ProcessOutput {
            self.outputs
                .get(&args.join(" "))
                .cloned()
                .unwrap_or_else(|| process_output(0, ""))
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.records.lock().unwrap().push(RecordedCommand {
                program: program.to_string(),
                args: args.iter().map(|arg| (*arg).to_string()).collect(),
                cwd: None,
                has_xdg_runtime_dir: false,
                timeout: None,
            });
            Some(self.output(args))
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            cwd: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.records.lock().unwrap().push(RecordedCommand {
                program: program.to_string(),
                args: args.iter().map(|arg| (*arg).to_string()).collect(),
                cwd: cwd.map(Path::to_path_buf),
                has_xdg_runtime_dir: environment
                    .is_some_and(|values| values.contains_key(&OsString::from("XDG_RUNTIME_DIR"))),
                timeout,
            });
            Some(self.output(args))
        }
    }

    struct Fixture {
        root: PathBuf,
        context: QualityScheduleContext,
    }

    impl Fixture {
        fn new(enabled: bool) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = env::temp_dir().join(format!(
                "yafvs-quality-schedule-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("ops/systemd")).unwrap();
            fs::write(
                root.join("ops/systemd/yafvs-quality-gate.service.in"),
                "repo=@REPO_ROOT@ runtime=@RUNTIME_DIR@ log=@QUALITY_GATE_LOG_DIR@ python=@PYTHON@",
            )
            .unwrap();
            fs::write(
                root.join("ops/systemd/yafvs-quality-gate.timer.in"),
                "repo=@REPO_ROOT@ runtime=@RUNTIME_DIR@ log=@QUALITY_GATE_LOG_DIR@ python=@PYTHON@",
            )
            .unwrap();
            Self {
                context: QualityScheduleContext {
                    enabled,
                    unit_dir: root.join("units"),
                    runtime_dir: root.join("runtime"),
                    log_dir: root.join("logs/quality-gate"),
                    host: "test-host".to_string(),
                    user: "test-user".to_string(),
                },
                root,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn process_output(exit_code: i32, stdout: &str) -> ProcessOutput {
        ProcessOutput {
            success: exit_code == 0,
            exit_code: Some(exit_code),
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn systemctl_records(runner: &FakeCommandRunner) -> Vec<RecordedCommand> {
        runner
            .records()
            .into_iter()
            .filter(|record| record.program == "systemctl")
            .collect()
    }

    #[test]
    fn parses_systemd_show_properties() {
        assert_eq!(
            systemd_show_properties("LoadState=loaded\nActiveState=active\n"),
            BTreeMap::from([
                ("ActiveState".to_string(), "active".to_string()),
                ("LoadState".to_string(), "loaded".to_string()),
            ])
        );
    }

    #[test]
    fn install_refuses_absent_opt_in_without_commands_or_unit_writes() {
        let fixture = Fixture::new(false);
        let runner = FakeCommandRunner::new(BTreeMap::new());
        let result = command_quality_gate_schedule_with_runner(
            &fixture.root,
            "install",
            &runner,
            &fixture.context,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "quality-gate-schedule.opt-in");
        assert!(systemctl_records(&runner).is_empty());
        assert!(!fixture.context.unit_dir.exists());
    }

    #[test]
    fn install_refuses_when_user_systemd_is_unavailable() {
        let fixture = Fixture::new(true);
        let runner = FakeCommandRunner::new(BTreeMap::from([(
            "--user status".to_string(),
            process_output(1, "offline"),
        )]));
        let result = command_quality_gate_schedule_with_runner(
            &fixture.root,
            "install",
            &runner,
            &fixture.context,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Quality gate schedule installation blocked because user-level systemd is unavailable."
        );
        assert_eq!(systemctl_records(&runner).len(), 1);
        assert!(!fixture.context.unit_dir.exists());
        assert!(!fixture.context.log_dir.exists());
    }

    #[test]
    fn install_writes_units_and_collects_expected_status() {
        let fixture = Fixture::new(true);
        let runner = FakeCommandRunner::new(BTreeMap::from([
            (
                "--user is-enabled yafvs-quality-gate.timer".to_string(),
                process_output(0, "enabled\n"),
            ),
            (
                "--user is-active yafvs-quality-gate.timer".to_string(),
                process_output(0, "active\n"),
            ),
        ]));
        let result = command_quality_gate_schedule_with_runner(
            &fixture.root,
            "install",
            &runner,
            &fixture.context,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.summary, "Quality gate schedule install completed.");
        assert!(fixture.context.log_dir.is_dir());
        for unit in UNITS {
            let rendered = fs::read_to_string(fixture.context.unit_dir.join(unit)).unwrap();
            assert!(rendered.contains(&fixture.root.display().to_string()));
            assert!(rendered.contains(&fixture.context.runtime_dir.display().to_string()));
            assert!(rendered.contains(&fixture.context.log_dir.display().to_string()));
        }
        assert_eq!(
            systemctl_records(&runner)
                .iter()
                .map(|record| (record.args.join(" "), record.timeout))
                .collect::<Vec<_>>(),
            vec![
                ("--user status".to_string(), Some(Duration::from_secs(30))),
                (
                    "--user daemon-reload".to_string(),
                    Some(Duration::from_secs(60))
                ),
                (
                    "--user enable --now yafvs-quality-gate.timer".to_string(),
                    Some(Duration::from_secs(60))
                ),
                ("--user status".to_string(), Some(Duration::from_secs(30))),
                (
                    format!("--user show yafvs-quality-gate.service {SHOW_PROPERTIES}"),
                    Some(Duration::from_secs(30))
                ),
                (
                    format!("--user show yafvs-quality-gate.timer {SHOW_PROPERTIES}"),
                    Some(Duration::from_secs(30))
                ),
                (
                    "--user is-enabled yafvs-quality-gate.timer".to_string(),
                    Some(Duration::from_secs(30))
                ),
                (
                    "--user is-active yafvs-quality-gate.timer".to_string(),
                    Some(Duration::from_secs(30))
                ),
            ]
        );
        assert!(systemctl_records(&runner).iter().all(|record| {
            record.cwd == Some(fixture.root.clone()) && record.has_xdg_runtime_dir
        }));
        assert_eq!(result.artifacts.len(), 2);
        assert_eq!(result.details.as_ref().unwrap()["host"], "test-host");
        assert_eq!(
            result.details.as_ref().unwrap()["status"]["timer_enabled"],
            "enabled"
        );
    }

    #[test]
    fn disable_reports_pass_or_warn_and_still_collects_status() {
        for (exit_code, status) in [(0, "pass"), (1, "warn")] {
            let fixture = Fixture::new(false);
            fs::create_dir_all(&fixture.context.unit_dir).unwrap();
            for unit in UNITS {
                fs::write(fixture.context.unit_dir.join(unit), "unit").unwrap();
            }
            let runner = FakeCommandRunner::new(BTreeMap::from([(
                "--user disable --now yafvs-quality-gate.timer".to_string(),
                process_output(exit_code, "disabled\n"),
            )]));
            let result = command_quality_gate_schedule_with_runner(
                &fixture.root,
                "disable",
                &runner,
                &fixture.context,
            );
            assert_eq!(result.status, status);
            assert!(
                result
                    .findings
                    .iter()
                    .any(|finding| finding.check == "quality-gate-schedule.systemd-user")
            );
            assert!(
                systemctl_records(&runner)
                    .iter()
                    .any(|record| record.args.join(" ") == "--user status")
            );
        }
    }

    #[test]
    fn status_reports_unit_files_states_and_timer_shape() {
        let fixture = Fixture::new(false);
        fs::create_dir_all(&fixture.context.unit_dir).unwrap();
        fs::write(fixture.context.unit_dir.join(UNITS[1]), "unit").unwrap();
        let runner = FakeCommandRunner::new(BTreeMap::from([
            (
                format!("--user show {} {SHOW_PROPERTIES}", UNITS[0]),
                process_output(1, "not found"),
            ),
            (
                format!("--user show {} {SHOW_PROPERTIES}", UNITS[1]),
                process_output(0, "ActiveState=failed\nLoadState=loaded\n"),
            ),
            (
                "--user is-enabled yafvs-quality-gate.timer".to_string(),
                process_output(1, "disabled\n"),
            ),
            (
                "--user is-active yafvs-quality-gate.timer".to_string(),
                process_output(0, "active\n"),
            ),
        ]));
        let result = command_quality_gate_schedule_with_runner(
            &fixture.root,
            "status",
            &runner,
            &fixture.context,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.summary, "Quality gate schedule status collected.");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "quality-gate-schedule.unit-state")
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "quality-gate-schedule.unit-file"
                    && finding.status == "warn")
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "quality-gate-schedule.enabled" && finding.status == "warn"
        }));
        assert!(result.findings.iter().any(|finding| {
            finding.check == "quality-gate-schedule.active" && finding.status == "pass"
        }));
        assert_eq!(result.artifacts.len(), 2);
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["status"]["units"][UNITS[0]]["exists"], false);
        assert_eq!(details["status"]["units"][UNITS[1]]["exists"], true);
        assert_eq!(details["status"]["timer_enabled"], "disabled");
        assert_eq!(details["status"]["timer_active"], "active");
    }

    #[test]
    fn unknown_action_fails_closed() {
        let fixture = Fixture::new(true);
        let runner = FakeCommandRunner::new(BTreeMap::new());
        let result = command_quality_gate_schedule_with_runner(
            &fixture.root,
            "unexpected",
            &runner,
            &fixture.context,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "quality-gate-schedule.action");
        assert!(systemctl_records(&runner).is_empty());
    }
}
