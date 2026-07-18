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
