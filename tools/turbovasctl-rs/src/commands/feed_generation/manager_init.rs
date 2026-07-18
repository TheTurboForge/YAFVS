// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pinned, output-redacted manager initialization for guarded feed activation.

use super::database::DatabaseAttestationAdapter;
use super::service_runtime::ServiceRuntime;
use super::transition::{StepOutcome, StepStatus};
use crate::commands::secret::{
    read_or_create_runtime_secret, runtime_secret_path, write_private_text,
};
use crate::process::{CommandRunner, ProcessOutput};
use crate::result::Finding;
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::Duration;

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "admin";
const ADMIN_SECRET: &str = "gvmd-admin-password";
const FEED_IMPORT_OWNER_SETTING: &str = "78eceaec-3385-11ea-b237-28d24461215b";
const SOURCE_DATABASE_VERSION: u64 = 287;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const DATABASE_VERSION_SQL: &str =
    "SELECT COALESCE((SELECT value FROM meta WHERE name = 'database_version'), 'missing');";

pub(super) fn initialize_manager(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    runtime: &ServiceRuntime<'_>,
) -> StepOutcome {
    let mut findings = Vec::new();
    let secret_path = runtime_secret_path(repo_root, ADMIN_SECRET);
    if required_identifier(runtime.environment(), "POSTGRES_DB").is_err()
        || required_identifier(runtime.environment(), "POSTGRES_USER").is_err()
    {
        return failed(
            findings,
            "runtime.manager-environment",
            "Manager initialization environment is invalid.",
            &secret_path,
        );
    }
    let (observed_password, created) = match read_or_create_runtime_secret(repo_root, ADMIN_SECRET)
    {
        Ok(value) => value,
        Err(_) => {
            return failed(
                findings,
                "runtime.admin-secret",
                "Development manager secret could not be read safely.",
                &secret_path,
            );
        }
    };
    if observed_password != ADMIN_PASSWORD
        && write_private_text(&secret_path, &format!("{ADMIN_PASSWORD}\n")).is_err()
    {
        return failed(
            findings,
            "runtime.admin-secret",
            "Development manager secret could not be aligned to the local development default.",
            &secret_path,
        );
    }
    findings.push(
        Finding::new(
            "pass",
            "runtime.admin-secret",
            if observed_password == ADMIN_PASSWORD {
                if created {
                    "Development manager secret was created for the local runtime."
                } else {
                    "Development manager secret was reused from the local runtime."
                }
            } else {
                "Development manager secret was aligned to the local development default."
            }
            .to_owned(),
        )
        .with_path(&secret_path.display().to_string()),
    );

    let migrate = match run_gvmd(runtime, &["--migrate"], COMMAND_TIMEOUT) {
        Ok(output) => output,
        Err(()) => {
            return failed(
                findings,
                "gvmd.migrate",
                "Pinned manager database migration could not be started.",
                &secret_path,
            );
        }
    };
    findings.push(command_finding(
        migrate.success,
        "gvmd.migrate",
        "Pinned manager database migration",
        migrate.exit_code,
    ));
    if !migrate.success {
        return finish(StepStatus::Fail, findings, &secret_path);
    }

    let expected_version = SOURCE_DATABASE_VERSION;
    let observed_version = match DatabaseAttestationAdapter::new(repo_root, runner)
        .query_single_value(DATABASE_VERSION_SQL)
    {
        Ok(Some(version)) => version,
        _ => {
            return failed(
                findings,
                "gvmd.migrate-version",
                "Manager migration did not yield one database schema version.",
                &secret_path,
            );
        }
    };
    let version_matches = observed_version == expected_version.to_string();
    findings.push(
        Finding::new(
            if version_matches { "pass" } else { "fail" },
            "gvmd.migrate-version",
            if version_matches {
                "Manager database version matches the embedded source schema."
            } else {
                "Manager database version does not match the embedded source schema."
            }
            .to_owned(),
        )
        .with_details(json!({
            "expected": expected_version,
            "observed": observed_version,
        })),
    );
    if !version_matches {
        return finish(StepStatus::Fail, findings, &secret_path);
    }

    let users = match run_gvmd(runtime, &["--get-users", "--verbose"], COMMAND_TIMEOUT) {
        Ok(output) if output.success => output,
        Ok(output) => {
            findings.push(command_finding(
                false,
                "gvmd.get-users",
                "Development manager user lookup",
                output.exit_code,
            ));
            return finish(StepStatus::Fail, findings, &secret_path);
        }
        Err(()) => {
            return failed(
                findings,
                "gvmd.get-users",
                "Development manager user lookup could not be started.",
                &secret_path,
            );
        }
    };
    let mut admin_uuid = parse_user_uuid(&users.stdout, ADMIN_USER);
    findings.push(
        command_finding(
            true,
            "gvmd.get-users",
            "Development manager user lookup",
            users.exit_code,
        )
        .with_details(json!({"admin_uuid_found": admin_uuid.is_some()})),
    );

    if admin_uuid.is_none() {
        let create_user = match run_gvmd(
            runtime,
            &[
                &format!("--create-user={ADMIN_USER}"),
                &format!("--password={ADMIN_PASSWORD}"),
                "--disable-password-policy",
            ],
            COMMAND_TIMEOUT,
        ) {
            Ok(output) => output,
            Err(()) => {
                return failed(
                    findings,
                    "gvmd.create-admin",
                    "Development manager user creation could not be started.",
                    &secret_path,
                );
            }
        };
        findings.push(command_finding(
            create_user.success,
            "gvmd.create-admin",
            "Development manager user creation",
            create_user.exit_code,
        ));
        if !create_user.success {
            return finish(StepStatus::Fail, findings, &secret_path);
        }
        let users = match run_gvmd(runtime, &["--get-users", "--verbose"], COMMAND_TIMEOUT) {
            Ok(output) if output.success => output,
            _ => {
                return failed(
                    findings,
                    "gvmd.admin-uuid",
                    "Development manager UUID lookup failed after user creation.",
                    &secret_path,
                );
            }
        };
        admin_uuid = parse_user_uuid(&users.stdout, ADMIN_USER);
        if admin_uuid.is_none() {
            return failed(
                findings,
                "gvmd.admin-uuid",
                "Development manager UUID was absent after successful user creation.",
                &secret_path,
            );
        }
        findings.push(Finding::new(
            "pass",
            "gvmd.admin-uuid",
            "Development manager UUID was verified after user creation.".to_owned(),
        ));
    }

    let update_password = match run_gvmd(
        runtime,
        &[
            &format!("--user={ADMIN_USER}"),
            &format!("--new-password={ADMIN_PASSWORD}"),
            "--disable-password-policy",
        ],
        COMMAND_TIMEOUT,
    ) {
        Ok(output) => output,
        Err(()) => {
            return failed(
                findings,
                "gvmd.admin-password",
                "Development manager password update could not be started.",
                &secret_path,
            );
        }
    };
    findings.push(command_finding(
        update_password.success,
        "gvmd.admin-password",
        "Development manager password update",
        update_password.exit_code,
    ));
    if !update_password.success {
        return finish(StepStatus::Fail, findings, &secret_path);
    }

    let admin_uuid = admin_uuid.expect("verified above");
    let owner = match run_gvmd(
        runtime,
        &[
            &format!("--modify-setting={FEED_IMPORT_OWNER_SETTING}"),
            &format!("--value={admin_uuid}"),
        ],
        COMMAND_TIMEOUT,
    ) {
        Ok(output) => output,
        Err(()) => {
            return failed(
                findings,
                "gvmd.feed-owner",
                "Feed import owner update could not be started.",
                &secret_path,
            );
        }
    };
    findings.push(command_finding(
        owner.success,
        "gvmd.feed-owner",
        "Feed import owner update",
        owner.exit_code,
    ));
    finish(
        if owner.success {
            StepStatus::Pass
        } else {
            StepStatus::Fail
        },
        findings,
        &secret_path,
    )
}

fn run_gvmd(
    runtime: &ServiceRuntime<'_>,
    command: &[&str],
    timeout: Duration,
) -> Result<ProcessOutput, ()> {
    let environment = runtime.environment();
    let database = required_identifier(environment, "POSTGRES_DB")?;
    let user = required_identifier(environment, "POSTGRES_USER")?;
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
    ];
    arguments.extend(command.iter().map(|argument| (*argument).to_owned()));
    runtime
        .run_pinned_compose(&arguments, timeout)
        .map_err(|_| ())
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

fn parse_user_uuid(output: &str, username: &str) -> Option<String> {
    output
        .lines()
        .filter(|line| line.split_whitespace().any(|token| token == username))
        .find_map(uuid_in)
}

fn uuid_in(value: &str) -> Option<String> {
    value
        .split(|character: char| !(character.is_ascii_hexdigit() || character == '-'))
        .find(|candidate| {
            candidate.len() == 36
                && candidate
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| match index {
                        8 | 13 | 18 | 23 => byte == b'-',
                        _ => byte.is_ascii_hexdigit(),
                    })
        })
        .map(str::to_ascii_lowercase)
}

fn command_finding(passed: bool, check: &str, operation: &str, exit_code: Option<i32>) -> Finding {
    Finding::new(
        if passed { "pass" } else { "fail" },
        check,
        format!(
            "{operation} {}.",
            if passed { "completed" } else { "failed" }
        ),
    )
    .with_details(json!({"exit_code": exit_code}))
}

fn failed(
    mut findings: Vec<Finding>,
    check: &str,
    message: &str,
    secret_path: &Path,
) -> StepOutcome {
    findings.push(Finding::new("fail", check, message.to_owned()));
    finish(StepStatus::Fail, findings, secret_path)
}

fn finish(status: StepStatus, findings: Vec<Finding>, secret_path: &Path) -> StepOutcome {
    StepOutcome::with_evidence(status, findings, vec![secret_path.display().to_string()])
}
