// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
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

const UNITS: [&str; 2] = [
    "turbovas-quality-gate.service",
    "turbovas-quality-gate.timer",
];
const TIMER: &str = "turbovas-quality-gate.timer";
const ENABLE_ENV: &str = "TURBOVAS_ENABLE_QUALITY_GATE_SCHEDULE";
const SHOW_PROPERTIES: &str = "--property=LoadState,UnitFileState,ActiveState,SubState,NextElapseUSecRealtime,LastTriggerUSecRealtime";

pub fn command_quality_gate_schedule(repo_root: &Path, action: &str) -> ResultEnvelope {
    command_quality_gate_schedule_with_runner(repo_root, action, &SystemCommandRunner)
}

fn command_quality_gate_schedule_with_runner(
    repo_root: &Path,
    action: &str,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let unit_dir = systemd_user_unit_dir();
    let mut findings = Vec::new();
    let mut details = json!({
        "action": action,
        "host": hostname(),
        "user": env::var("USER").ok().filter(|value| !value.is_empty()).unwrap_or_else(home_name),
    });
    if action == "install" {
        if env::var(ENABLE_ENV).ok().as_deref() != Some("1") {
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
        fs::create_dir_all(&unit_dir).expect("could not create systemd user unit directory");
        fs::create_dir_all(quality_gate_log_dir(repo_root))
            .expect("could not create quality gate log directory");
        for unit in UNITS {
            let target = unit_dir.join(unit);
            fs::write(&target, render_unit(repo_root, unit))
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

    let (status_findings, status_details) = schedule_status(runner, repo_root, &unit_dir);
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
            .map(|unit| unit_dir.join(unit).display().to_string())
            .collect(),
    )
    .with_details(details)
}

fn schedule_status(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    unit_dir: &Path,
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
        let path = unit_dir.join(unit);
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
    if unit_dir.join(TIMER).is_file() {
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
            "host": hostname(),
            "user": env::var("USER").ok().filter(|value| !value.is_empty()).unwrap_or_else(home_name),
            "unit_dir": unit_dir.display().to_string(),
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

fn render_unit(repo_root: &Path, unit: &str) -> String {
    let template = fs::read_to_string(repo_root.join(format!("ops/systemd/{unit}.in")))
        .expect("could not read quality gate systemd template");
    let python = executable_path("python3")
        .unwrap_or_else(|| PathBuf::from("python3"))
        .display()
        .to_string();
    template
        .replace("@REPO_ROOT@", &repo_root.display().to_string())
        .replace("@PYTHON@", &python)
        .replace(
            "@RUNTIME_DIR@",
            &runtime_dir(repo_root).display().to_string(),
        )
        .replace(
            "@QUALITY_GATE_LOG_DIR@",
            &quality_gate_log_dir(repo_root).display().to_string(),
        )
}

fn systemd_user_unit_dir() -> PathBuf {
    home_dir().join(".config/systemd/user")
}

fn quality_gate_log_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("logs/quality-gate")
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
    fn install_requires_explicit_opt_in() {
        if env::var(ENABLE_ENV).ok().as_deref() == Some("1") {
            return;
        }
        let result = command_quality_gate_schedule(Path::new("/srv/TurboVAS"), "install");
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings[0].check, "quality-gate-schedule.opt-in");
    }
}
