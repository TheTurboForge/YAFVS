// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guarded PostgreSQL and pg-gvm initialization for the development runtime.

use super::common::{metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_lifecycle_environment};
use super::config_schedule_schema::{
    CONFIG_SCHEDULE_SCHEMA_FINGERPRINT, CONFIG_SCHEDULE_SCHEMA_SQL,
    config_schedule_schema_fingerprint_sql,
};
use super::foundational_schema::{
    FOUNDATIONAL_SCHEMA_FINGERPRINT, FOUNDATIONAL_SCHEMA_SQL, foundational_schema_fingerprint_sql,
};
use super::runtime_setup::ensure_runtime_setup;
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const POSTGRES_COLLATION_BASE_DATABASES: [&str; 2] = ["postgres", "template1"];
const POSTGRES_SERVICE: &str = "postgres";
const PG_GVM_CONTROL: &str = "pg-gvm.control";
const PG_GVM_LIBRARY: &str = "libpg-gvm.so";
const COMPOSE_STATE_OUTPUT_MAX_BYTES: usize = 256;
#[derive(Clone, Copy)]
pub(crate) struct PostgresExtension {
    pub(crate) name: &'static str,
    pub(crate) check: &'static str,
    pub(crate) create_sql: &'static str,
    pub(crate) status_sql: &'static str,
}

pub(crate) const POSTGRES_EXTENSIONS: [PostgresExtension; 3] = [
    PostgresExtension {
        name: "uuid-ossp",
        check: "postgres.uuid-ossp",
        create_sql: "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";",
        status_sql: "SELECT COALESCE((SELECT extversion FROM pg_extension WHERE extname = 'uuid-ossp'), 'missing');",
    },
    PostgresExtension {
        name: "pgcrypto",
        check: "postgres.pgcrypto",
        create_sql: "CREATE EXTENSION IF NOT EXISTS pgcrypto;",
        status_sql: "SELECT COALESCE((SELECT extversion FROM pg_extension WHERE extname = 'pgcrypto'), 'missing');",
    },
    PostgresExtension {
        name: "pg-gvm",
        check: "postgres.pg-gvm",
        create_sql: "CREATE EXTENSION IF NOT EXISTS \"pg-gvm\";",
        status_sql: "SELECT COALESCE((SELECT extversion FROM pg_extension WHERE extname = 'pg-gvm'), 'missing');",
    },
];
const READY_ATTEMPTS: usize = 30;
const READY_INTERVAL: Duration = Duration::from_secs(2);

struct OpenArtifact {
    file: File,
    name: String,
    source_path: PathBuf,
    destination: String,
}

struct PgGvmArtifacts {
    extension_files: Vec<OpenArtifact>,
    library: OpenArtifact,
}

pub fn command_runtime_init(repo_root: &Path) -> ResultEnvelope {
    let mut sleep = std::thread::sleep;
    command_runtime_init_with(repo_root, &SystemCommandRunner, &mut sleep)
}

pub(crate) fn command_runtime_init_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    sleep: &mut dyn FnMut(Duration),
) -> ResultEnvelope {
    let mut findings = ensure_runtime_setup(repo_root, runner);
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped before Postgres changes.",
            findings,
        );
    }
    let environment = match runtime_lifecycle_environment(repo_root) {
        Ok(environment) => environment,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "runtime.mqtt-secrets",
                format!("Runtime MQTT secrets could not be prepared: {error}"),
            ));
            return result(
                repo_root,
                runner,
                "Runtime initialization stopped before Postgres changes.",
                findings,
            );
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

    let (artifact_findings, artifacts) = inspect_pg_gvm_artifacts(repo_root);
    findings.extend(artifact_findings);
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped before Postgres changes.",
            findings,
        );
    }
    let artifacts = artifacts.expect("passing pg-gvm findings have open artifacts");

    match postgres_is_running(repo_root, runner, &environment) {
        Ok(true) => findings.push(Finding::new(
            "pass",
            "postgres.running-state",
            "Existing PostgreSQL service is running and was preserved without Compose lifecycle changes."
                .to_string(),
        )),
        Ok(false) => {
            let postgres_up = run_compose(
                repo_root,
                runner,
                &environment,
                &[
                    "up".into(),
                    "-d".into(),
                    "--build".into(),
                    POSTGRES_SERVICE.into(),
                ],
            );
            findings.push(process_finding(
                &postgres_up,
                "postgres.up",
                "docker compose up postgres",
                80,
                None,
            ));
            if !process_succeeded(&postgres_up) {
                return result(
                    repo_root,
                    runner,
                    "Runtime initialization stopped at Postgres startup.",
                    findings,
                );
            }
        }
        Err(finding) => {
            findings.push(finding);
            return result(
                repo_root,
                runner,
                "Runtime initialization stopped before Postgres lifecycle changes.",
                findings,
            );
        }
    }

    let mut ready = None;
    for attempt in 0..READY_ATTEMPTS {
        let probe = postgres_ready(repo_root, runner, &environment);
        let succeeded = probe.as_ref().is_some_and(|output| output.success);
        ready = probe;
        if succeeded {
            break;
        }
        if attempt + 1 < READY_ATTEMPTS {
            sleep(READY_INTERVAL);
        }
    }
    findings.push(process_finding(
        &ready,
        "postgres.ready",
        "pg_isready",
        20,
        None,
    ));
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped before database setup.",
            findings,
        );
    }

    findings.extend(ensure_postgres_collation(repo_root, runner, &environment));
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped at Postgres collation check.",
            findings,
        );
    }

    findings.extend(copy_pg_gvm_extension(
        repo_root,
        runner,
        &environment,
        artifacts,
    ));
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while installing pg-gvm files.",
            findings,
        );
    }

    let database = environment_value(&environment, "POSTGRES_DB", "yafvs");
    let user = environment_value(&environment, "POSTGRES_USER", "yafvs");
    let create_dba = psql(
        repo_root,
        runner,
        &environment,
        &database,
        "DO $$ BEGIN CREATE ROLE dba WITH SUPERUSER NOINHERIT; EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
    );
    findings.push(process_finding(
        &create_dba,
        "postgres.role.dba",
        "Create/verify dba role",
        40,
        None,
    ));
    let grant_dba = psql(
        repo_root,
        runner,
        &environment,
        &database,
        &format!("GRANT dba TO {};", sql_identifier(&user)),
    );
    findings.push(process_finding(
        &grant_dba,
        "postgres.role.grant",
        &format!("Grant dba to {user}"),
        40,
        None,
    ));
    for extension in POSTGRES_EXTENSIONS {
        let create_extension = psql(
            repo_root,
            runner,
            &environment,
            &database,
            extension.create_sql,
        );
        findings.push(process_finding(
            &create_extension,
            &format!("postgres.extension.{}", extension.name),
            &format!("Create/verify {} extension", extension.name),
            80,
            None,
        ));
        if !process_succeeded(&create_extension) {
            return result(
                repo_root,
                runner,
                "Runtime initialization stopped while creating PostgreSQL extensions.",
                findings,
            );
        }
    }
    for extension in POSTGRES_EXTENSIONS {
        let status =
            postgres_extension_status(repo_root, runner, &environment, &database, extension);
        let verification_failed = status.status == "fail";
        findings.push(status);
        if verification_failed {
            return result(
                repo_root,
                runner,
                "Runtime initialization stopped while verifying PostgreSQL extensions.",
                findings,
            );
        }
    }
    let create_foundational_schema = psql(
        repo_root,
        runner,
        &environment,
        &database,
        FOUNDATIONAL_SCHEMA_SQL,
    );
    findings.push(process_finding(
        &create_foundational_schema,
        "postgres.foundational-schema.create",
        "Create/verify foundational schema",
        80,
        None,
    ));
    if !process_succeeded(&create_foundational_schema) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while creating foundational schema.",
            findings,
        );
    }
    let foundational_fingerprint = psql(
        repo_root,
        runner,
        &environment,
        &database,
        &foundational_schema_fingerprint_sql(),
    );
    if !process_succeeded(&foundational_fingerprint) {
        findings.push(process_finding(
            &foundational_fingerprint,
            "postgres.foundational-schema",
            "Foundational schema fingerprint query",
            40,
            None,
        ));
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while verifying foundational schema.",
            findings,
        );
    }
    let observed_fingerprint = psql_value(
        foundational_fingerprint
            .as_ref()
            .map_or("", |output| &output.stdout),
    );
    findings.push(
        Finding::new(
            if observed_fingerprint == FOUNDATIONAL_SCHEMA_FINGERPRINT {
                "pass"
            } else {
                "fail"
            },
            "postgres.foundational-schema",
            if observed_fingerprint == FOUNDATIONAL_SCHEMA_FINGERPRINT {
                "Foundational schema matches the fixed catalog contract.".to_string()
            } else {
                "Foundational schema does not match the fixed catalog contract.".to_string()
            },
        )
        .with_details(json!({
            "expected": FOUNDATIONAL_SCHEMA_FINGERPRINT,
            "observed": observed_fingerprint,
        })),
    );
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while verifying foundational schema.",
            findings,
        );
    }
    let create_config_schedule_schema = psql(
        repo_root,
        runner,
        &environment,
        &database,
        CONFIG_SCHEDULE_SCHEMA_SQL,
    );
    findings.push(process_finding(
        &create_config_schedule_schema,
        "postgres.config-schedule-schema.create",
        "Create/verify configuration and schedule schema",
        80,
        None,
    ));
    if !process_succeeded(&create_config_schedule_schema) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while creating configuration and schedule schema.",
            findings,
        );
    }
    let config_schedule_fingerprint = psql(
        repo_root,
        runner,
        &environment,
        &database,
        &config_schedule_schema_fingerprint_sql(),
    );
    if !process_succeeded(&config_schedule_fingerprint) {
        findings.push(process_finding(
            &config_schedule_fingerprint,
            "postgres.config-schedule-schema",
            "Configuration and schedule schema fingerprint query",
            40,
            None,
        ));
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while verifying configuration and schedule schema.",
            findings,
        );
    }
    let observed_fingerprint = psql_value(
        config_schedule_fingerprint
            .as_ref()
            .map_or("", |output| &output.stdout),
    );
    let schema_matches = observed_fingerprint == CONFIG_SCHEDULE_SCHEMA_FINGERPRINT;
    findings.push(
        Finding::new(
            if schema_matches { "pass" } else { "fail" },
            "postgres.config-schedule-schema",
            if schema_matches {
                "Configuration and schedule schema matches the fixed catalog contract.".to_string()
            } else {
                "Configuration and schedule schema does not match the fixed catalog contract."
                    .to_string()
            },
        )
        .with_details(json!({
            "expected": CONFIG_SCHEDULE_SCHEMA_FINGERPRINT,
            "observed": observed_fingerprint,
        })),
    );
    if has_failure(&findings) {
        return result(
            repo_root,
            runner,
            "Runtime initialization stopped while verifying configuration and schedule schema.",
            findings,
        );
    }
    result(
        repo_root,
        runner,
        "Runtime database initialization completed.",
        findings,
    )
    .with_artifacts(vec![
        runtime_dir(repo_root).display().to_string(),
        "build/prefix".to_string(),
    ])
}

fn postgres_is_running(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<bool, Finding> {
    let output = run_compose(
        repo_root,
        runner,
        environment,
        &[
            "ps".into(),
            "--status".into(),
            "running".into(),
            "--services".into(),
            POSTGRES_SERVICE.into(),
        ],
    );
    if !process_succeeded(&output) {
        return Err(process_finding(
            &output,
            "postgres.running-state",
            "PostgreSQL running-state inspection",
            20,
            None,
        ));
    }
    let stdout = output.as_ref().map_or("", |output| output.stdout.as_str());
    let state = match stdout {
        "" => Ok(false),
        "postgres\n" => Ok(true),
        _ if stdout.len() > COMPOSE_STATE_OUTPUT_MAX_BYTES => {
            Err("output exceeded the bounded size")
        }
        _ => Err("output was not the exact expected service name"),
    };
    state.map_err(|reason| {
        Finding::new(
            "fail",
            "postgres.running-state",
            format!("PostgreSQL running-state inspection was unsafe: {reason}."),
        )
        .with_details(json!({ "output_tail": process_tail(&output, 20) }))
    })
}

fn result(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, "runtime-init", runner),
        summary.to_string(),
        findings,
    )
}

fn has_failure(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.status == "fail")
}

fn process_succeeded(output: &Option<ProcessOutput>) -> bool {
    output.as_ref().is_some_and(|output| output.success)
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
    .with_details(json!({
        "output_tail": output
            .as_ref()
            .map(|output| output_tail(&output.stdout, tail_lines))
            .unwrap_or_default(),
    }));
    if let Some(path) = path {
        finding = finding.with_path(path);
    }
    finding
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

fn postgres_ready(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> Option<ProcessOutput> {
    let user = environment_value(environment, "POSTGRES_USER", "yafvs");
    let database = environment_value(environment, "POSTGRES_DB", "yafvs");
    exec_in_postgres(
        repo_root,
        runner,
        environment,
        &[
            "pg_isready".into(),
            "-U".into(),
            user,
            "-d".into(),
            database,
        ],
    )
}

fn psql(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    database: &str,
    sql: &str,
) -> Option<ProcessOutput> {
    let user = environment_value(environment, "POSTGRES_USER", "yafvs");
    let password = environment_value(environment, "POSTGRES_PASSWORD", "yafvs-dev");
    let mut process_environment = environment.clone();
    process_environment.insert(OsString::from("PGPASSWORD"), OsString::from(password));
    exec_in_postgres(
        repo_root,
        runner,
        &process_environment,
        &[
            "-e".into(),
            "PGPASSWORD".into(),
            "psql".into(),
            "-v".into(),
            "ON_ERROR_STOP=1".into(),
            "-U".into(),
            user,
            "-d".into(),
            database.into(),
            "-At".into(),
            "-c".into(),
            sql.into(),
        ],
    )
}

fn exec_in_postgres(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    operation: &[String],
) -> Option<ProcessOutput> {
    let mut arguments = vec!["exec".into(), "-T".into()];
    arguments.extend_from_slice(operation);
    let service_position = if arguments.get(2).is_some_and(|part| part == "-e") {
        4
    } else {
        2
    };
    arguments.insert(service_position, "postgres".into());
    run_compose(repo_root, runner, environment, &arguments)
}

fn ensure_postgres_collation(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
) -> Vec<Finding> {
    let configured = environment_value(environment, "POSTGRES_DB", "yafvs");
    let mut seen = BTreeSet::new();
    std::iter::once(configured.as_str())
        .chain(POSTGRES_COLLATION_BASE_DATABASES)
        .filter(|database| seen.insert((*database).to_string()))
        .map(|database| ensure_database_collation(repo_root, runner, environment, database))
        .collect()
}

fn ensure_database_collation(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    database: &str,
) -> Finding {
    const VERSION_SQL: &str = "SELECT datcollversion || '|' || pg_database_collation_actual_version(oid) FROM pg_database WHERE datname = current_database();";
    const RELATION_SQL: &str = "SELECT count(*) FROM pg_class WHERE relkind IN ('r','i','S','v','m') AND relnamespace NOT IN (SELECT oid FROM pg_namespace WHERE nspname LIKE 'pg_%' OR nspname = 'information_schema');";
    let version = psql(repo_root, runner, environment, database, VERSION_SQL);
    if !process_succeeded(&version) {
        return process_finding(
            &version,
            "postgres.collation",
            &format!("{database}: collation version check"),
            40,
            None,
        )
        .with_details(json!({
            "database": database,
            "output_tail": process_tail(&version, 40),
        }));
    }
    let value = psql_value(version.as_ref().map_or("", |output| &output.stdout));
    let Some((recorded, actual)) = value.split_once('|') else {
        return Finding::new(
            "warn",
            "postgres.collation",
            format!("{database}: could not parse database collation version check."),
        )
        .with_details(json!({
            "database": database,
            "output_tail": process_tail(&version, 40),
        }));
    };
    if recorded == actual {
        return Finding::new(
            "pass",
            "postgres.collation",
            format!("{database}: database collation version is current: {actual}."),
        )
        .with_details(json!({
            "database": database,
            "recorded": recorded,
            "actual": actual,
        }));
    }

    let relation_count = psql(repo_root, runner, environment, database, RELATION_SQL);
    if !process_succeeded(&relation_count) {
        return Finding::new(
            "fail",
            "postgres.collation",
            format!(
                "{database}: collation mismatch {recorded} != {actual}; relation-count check failed."
            ),
        )
        .with_details(json!({
            "database": database,
            "recorded": recorded,
            "actual": actual,
            "output_tail": process_tail(&relation_count, 40),
        }));
    }
    let count = psql_value(relation_count.as_ref().map_or("", |output| &output.stdout));
    if count != "0" {
        return Finding::new(
            "warn",
            "postgres.collation",
            format!(
                "{database}: database collation version mismatch {recorded} != {actual}; manual review required before refreshing a database with objects."
            ),
        )
        .with_details(json!({
            "database": database,
            "recorded": recorded,
            "actual": actual,
            "relation_count": count,
        }));
    }

    let connection_database = collation_connection_database(environment, database);
    let refresh = psql(
        repo_root,
        runner,
        environment,
        &connection_database,
        &format!(
            "ALTER DATABASE {} REFRESH COLLATION VERSION;",
            sql_identifier(database)
        ),
    );
    Finding::new(
        if process_succeeded(&refresh) {
            "pass"
        } else {
            "fail"
        },
        "postgres.collation",
        format!(
            "{database}: refreshed empty development database collation version from {recorded} to {actual}."
        ),
    )
    .with_details(json!({
        "database": database,
        "recorded": recorded,
        "actual": actual,
        "relation_count": count,
        "output_tail": process_tail(&refresh, 40),
    }))
}

fn collation_connection_database(
    environment: &BTreeMap<OsString, OsString>,
    target: &str,
) -> String {
    let configured = environment_value(environment, "POSTGRES_DB", "yafvs");
    std::iter::once(configured.as_str())
        .chain(POSTGRES_COLLATION_BASE_DATABASES)
        .find(|candidate| *candidate != target)
        .unwrap_or(target)
        .to_string()
}

fn inspect_pg_gvm_artifacts(repo_root: &Path) -> (Vec<Finding>, Option<PgGvmArtifacts>) {
    match open_pg_gvm_artifacts(repo_root) {
        Ok(artifacts) => {
            let sql_paths = artifacts
                .extension_files
                .iter()
                .filter(|artifact| artifact.name != PG_GVM_CONTROL)
                .map(|artifact| relative_display(repo_root, &artifact.source_path))
                .collect::<Vec<_>>();
            let control = artifacts
                .extension_files
                .iter()
                .find(|artifact| artifact.name == PG_GVM_CONTROL)
                .expect("open artifacts include control file");
            let findings = vec![
                Finding::new(
                    "pass",
                    "pg-gvm.control",
                    format!("{PG_GVM_CONTROL} is available in build/prefix."),
                )
                .with_path(&relative_display(repo_root, &control.source_path)),
                Finding::new(
                    "pass",
                    "pg-gvm.library",
                    format!("{PG_GVM_LIBRARY} is available in build/prefix."),
                )
                .with_path(&relative_display(repo_root, &artifacts.library.source_path)),
                Finding::new(
                    "pass",
                    "pg-gvm.sql",
                    "pg-gvm extension SQL files are available in build/prefix.".into(),
                )
                .with_details(json!({ "files": sql_paths })),
            ];
            (findings, Some(artifacts))
        }
        Err(error) => (
            vec![
                Finding::new(
                    "fail",
                    "pg-gvm.artifacts",
                    format!("pg-gvm build artifacts are unavailable or unsafe: {error}"),
                )
                .with_path("build/prefix"),
            ],
            None,
        ),
    }
}

fn open_pg_gvm_artifacts(repo_root: &Path) -> io::Result<PgGvmArtifacts> {
    let repo = open_directory(repo_root)?;
    let extension_dir = open_directory_chain(
        repo.as_raw_fd(),
        &["build", "prefix", "share", "postgresql", "extension"],
    )?;
    let library_dir =
        open_directory_chain(repo.as_raw_fd(), &["build", "prefix", "lib", "postgresql"])?;

    let mut sql_names = Vec::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", extension_dir.as_raw_fd()))? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("pg-gvm--") && name.ends_with(".sql") {
            sql_names.push(name.to_string());
        }
    }
    sql_names.sort();
    if sql_names.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no pg-gvm extension SQL files were found",
        ));
    }

    let mut extension_files = Vec::with_capacity(sql_names.len() + 1);
    extension_files.push(open_artifact_at(
        extension_dir.as_raw_fd(),
        PG_GVM_CONTROL,
        repo_root.join("build/prefix/share/postgresql/extension/pg-gvm.control"),
        "/usr/share/postgresql/16/extension/pg-gvm.control".into(),
    )?);
    for name in sql_names {
        extension_files.push(open_artifact_at(
            extension_dir.as_raw_fd(),
            &name,
            repo_root
                .join("build/prefix/share/postgresql/extension")
                .join(&name),
            format!("/usr/share/postgresql/16/extension/{name}"),
        )?);
    }
    let library = open_artifact_at(
        library_dir.as_raw_fd(),
        PG_GVM_LIBRARY,
        repo_root.join("build/prefix/lib/postgresql/libpg-gvm.so"),
        "/usr/lib/postgresql/16/lib/libpg-gvm.so".into(),
    )?;
    Ok(PgGvmArtifacts {
        extension_files,
        library,
    })
}

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    Ok(file.into())
}

fn open_directory_chain(parent: RawFd, components: &[&str]) -> io::Result<OwnedFd> {
    let mut current: Option<OwnedFd> = None;
    let mut parent_fd = parent;
    for component in components {
        let name = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "directory name contains NUL")
        })?;
        // SAFETY: name is a valid NUL-terminated string and parent_fd remains open.
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        let opened = unsafe { OwnedFd::from_raw_fd(fd) };
        parent_fd = opened.as_raw_fd();
        current = Some(opened);
    }
    current.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty directory chain"))
}

fn open_artifact_at(
    directory: RawFd,
    name: &str,
    source_path: PathBuf,
    destination: String,
) -> io::Result<OpenArtifact> {
    let name_c = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file name contains NUL"))?;
    // SAFETY: name_c is valid and directory remains open for this call.
    let fd = unsafe {
        libc::openat(
            directory,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    // SAFETY: getuid has no preconditions and does not dereference memory.
    let uid = unsafe { libc::getuid() };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", source_path.display()),
        ));
    }
    if metadata.uid() != uid || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be current-user-owned, single-linked, and not group/world writable",
                source_path.display()
            ),
        ));
    }
    Ok(OpenArtifact {
        file,
        name: name.to_string(),
        source_path,
        destination,
    })
}

fn copy_pg_gvm_extension(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    artifacts: PgGvmArtifacts,
) -> Vec<Finding> {
    let mut extension_outputs = Vec::new();
    for artifact in &artifacts.extension_files {
        extension_outputs.push(copy_artifact(repo_root, runner, environment, artifact));
    }
    let library_output = copy_artifact(repo_root, runner, environment, &artifacts.library);
    let extension_ok = extension_outputs.iter().all(process_succeeded);
    let library_ok = process_succeeded(&library_output);
    vec![
        Finding::new(
            if extension_ok { "pass" } else { "fail" },
            "pg-gvm.copy.sql",
            format!(
                "Copy pg-gvm SQL/control files exit code {}.",
                if extension_ok { 0 } else { 1 }
            ),
        )
        .with_details(json!({
            "files": artifacts.extension_files.iter().map(|artifact| artifact.name.as_str()).collect::<Vec<_>>(),
            "output_tail": extension_outputs.iter().flat_map(|output| process_tail(output, 40)).collect::<Vec<_>>(),
        })),
        Finding::new(
            if library_ok { "pass" } else { "fail" },
            "pg-gvm.copy.library",
            format!(
                "Copy pg-gvm shared library exit code {}.",
                if library_ok { 0 } else { 1 }
            ),
        )
        .with_details(json!({ "output_tail": process_tail(&library_output, 40) })),
    ]
}

fn copy_artifact(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    artifact: &OpenArtifact,
) -> Option<ProcessOutput> {
    let mut contents = Vec::new();
    let mut source = &artifact.file;
    source.read_to_end(&mut contents).ok()?;
    let expected_sha256 = format!("{:x}", Sha256::digest(&contents));
    let command = compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "--user".into(),
            "0".into(),
            "postgres".into(),
            "sh".into(),
            "-ceu".into(),
            concat!(
                "destination=$1; expected_sha256=$2; ",
                "temporary=\"${destination}.yafvsctl.$$\"; ",
                "trap 'rm -f -- \"$temporary\"' EXIT HUP INT TERM; ",
                "umask 022; cat > \"$temporary\"; ",
                "actual_sha256=$(sha256sum \"$temporary\"); ",
                "actual_sha256=${actual_sha256%% *}; ",
                "test \"$actual_sha256\" = \"$expected_sha256\"; ",
                "chmod 0644 \"$temporary\"; ",
                "mv -fT -- \"$temporary\" \"$destination\"; ",
                "trap - EXIT HUP INT TERM"
            )
            .into(),
            "sh".into(),
            artifact.destination.clone(),
            expected_sha256,
        ],
    );
    let arguments = command.iter().map(String::as_str).collect::<Vec<_>>();
    runner.run_with_input(
        "docker",
        &arguments,
        Some(repo_root),
        Some(environment),
        None,
        Some(&contents),
    )
}

fn postgres_extension_status(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    environment: &BTreeMap<OsString, OsString>,
    database: &str,
    extension: PostgresExtension,
) -> Finding {
    let output = psql(
        repo_root,
        runner,
        environment,
        database,
        extension.status_sql,
    );
    if !process_succeeded(&output) {
        return process_finding(
            &output,
            extension.check,
            &format!("{} extension status query", extension.name),
            40,
            None,
        );
    }
    let version = psql_value(output.as_ref().map_or("", |output| &output.stdout));
    Finding::new(
        if version.is_empty() || version == "missing" {
            "fail"
        } else {
            "pass"
        },
        extension.check,
        if version.is_empty() || version == "missing" {
            format!(
                "{} extension is missing; run yafvsctl runtime-init.",
                extension.name
            )
        } else {
            format!("{} extension is {version}.", extension.name)
        },
    )
    .with_details(json!({ "version": version }))
}

fn environment_value(
    environment: &BTreeMap<OsString, OsString>,
    name: &str,
    default: &str,
) -> String {
    environment
        .get(&OsString::from(name))
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn psql_value(output: &str) -> String {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !["WARNING:", "DETAIL:", "HINT:", "NOTICE:"]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
        })
        .unwrap_or_default()
        .to_string()
}

fn process_tail(output: &Option<ProcessOutput>, lines: usize) -> Vec<String> {
    output
        .as_ref()
        .map(|output| output_tail(&output.stdout, lines))
        .unwrap_or_default()
}

fn sql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn relative_display(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Mutex;

    struct Fixture {
        root: PathBuf,
        repo: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "yafvsctl-runtime-init-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            let repo = root.join("YAFVS");
            fs::create_dir_all(repo.join("compose")).unwrap();
            fs::write(repo.join("compose/dev.yaml"), "services: {}\n").unwrap();
            let extension = repo.join("build/prefix/share/postgresql/extension");
            let library = repo.join("build/prefix/lib/postgresql");
            fs::create_dir_all(&extension).unwrap();
            fs::create_dir_all(&library).unwrap();
            fs::write(extension.join(PG_GVM_CONTROL), "default_version = '22.6'\n").unwrap();
            fs::write(extension.join("pg-gvm--22.6.sql"), "SELECT 1;\n").unwrap();
            fs::write(library.join(PG_GVM_LIBRARY), "library\n").unwrap();
            for path in [
                extension.join(PG_GVM_CONTROL),
                extension.join("pg-gvm--22.6.sql"),
                library.join(PG_GVM_LIBRARY),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            Self { root, repo }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug, Clone)]
    struct Call {
        args: Vec<String>,
        environment: BTreeMap<OsString, OsString>,
        inherited_fd: bool,
        input_bytes: usize,
    }

    struct Runner {
        calls: Mutex<Vec<Call>>,
        ready: bool,
        postgres_state_success: bool,
        postgres_state_output: &'static str,
        collation: &'static str,
        relations: &'static str,
        extension_create_success: bool,
        extension_status_success: bool,
        extension_version: &'static str,
        foundational_create_success: bool,
        foundational_fingerprint_success: bool,
        foundational_fingerprint: String,
        config_schedule_create_success: bool,
        config_schedule_fingerprint_success: bool,
        config_schedule_fingerprint: String,
    }

    impl Runner {
        fn passing() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                ready: true,
                postgres_state_success: true,
                postgres_state_output: "",
                collation: "1|1\n",
                relations: "0\n",
                extension_create_success: true,
                extension_status_success: true,
                extension_version: "22.6\n",
                foundational_create_success: true,
                foundational_fingerprint_success: true,
                foundational_fingerprint: format!("{FOUNDATIONAL_SCHEMA_FINGERPRINT}\n"),
                config_schedule_create_success: true,
                config_schedule_fingerprint_success: true,
                config_schedule_fingerprint: format!("{CONFIG_SCHEDULE_SCHEMA_FINGERPRINT}\n"),
            }
        }

        fn docker_output(&self, args: &[&str]) -> ProcessOutput {
            let joined = args.join(" ");
            if joined.ends_with("ps --status running --services postgres") {
                return output(
                    if self.postgres_state_success { 0 } else { 1 },
                    self.postgres_state_output,
                );
            }
            if joined.contains("pg_isready") {
                return output(if self.ready { 0 } else { 1 }, "");
            }
            if joined.contains("datcollversion") {
                return output(0, self.collation);
            }
            if joined.contains("SELECT count(*) FROM pg_class") {
                return output(0, self.relations);
            }
            if joined.contains("CREATE EXTENSION IF NOT EXISTS") {
                return output(if self.extension_create_success { 0 } else { 1 }, "");
            }
            if joined.contains("extversion FROM pg_extension") {
                return output(
                    if self.extension_status_success { 0 } else { 1 },
                    self.extension_version,
                );
            }
            if joined.contains("CREATE TABLE IF NOT EXISTS meta") {
                return output(
                    if self.foundational_create_success {
                        0
                    } else {
                        1
                    },
                    "",
                );
            }
            if joined.contains("foundational_schema_items") {
                return output(
                    if self.foundational_fingerprint_success {
                        0
                    } else {
                        1
                    },
                    &self.foundational_fingerprint,
                );
            }
            if joined.contains("CREATE TABLE IF NOT EXISTS nvt_selectors") {
                return output(
                    if self.config_schedule_create_success {
                        0
                    } else {
                        1
                    },
                    "",
                );
            }
            if joined.contains("config_schedule_schema_items") {
                return output(
                    if self.config_schedule_fingerprint_success {
                        0
                    } else {
                        1
                    },
                    &self.config_schedule_fingerprint,
                );
            }
            output(0, "")
        }

        fn record(
            &self,
            args: &[&str],
            environment: Option<&BTreeMap<OsString, OsString>>,
            inherited_fd: bool,
            input_bytes: usize,
        ) -> ProcessOutput {
            self.calls.lock().unwrap().push(Call {
                args: args
                    .iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
                environment: environment.cloned().unwrap_or_default(),
                inherited_fd,
                input_bytes,
            });
            self.docker_output(args)
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
            _: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
        ) -> Option<ProcessOutput> {
            (program == "docker").then(|| self.record(args, environment, false, 0))
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            _: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            _: Option<Duration>,
            input: Option<&[u8]>,
        ) -> Option<ProcessOutput> {
            (program == "docker")
                .then(|| self.record(args, environment, false, input.map_or(0, <[u8]>::len)))
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
    fn initialization_preserves_order_and_keeps_password_out_of_arguments() {
        let fixture = Fixture::new("success");
        let runner = Runner::passing();
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "pass", "{:?}", result.findings);
        assert_eq!(result.summary, "Runtime database initialization completed.");
        assert_eq!(
            result.artifacts,
            vec![
                fixture.root.join("YAFVS-runtime").display().to_string(),
                "build/prefix".to_string(),
            ]
        );
        let calls = runner.calls.lock().unwrap();
        let joined = calls
            .iter()
            .map(|call| call.args.join(" "))
            .collect::<Vec<_>>();
        let config = joined
            .iter()
            .position(|call| call.ends_with("config --quiet"))
            .unwrap();
        let running_state = joined
            .iter()
            .position(|call| call.ends_with("ps --status running --services postgres"))
            .unwrap();
        let foundational_create = joined
            .iter()
            .position(|call| call.contains("CREATE TABLE IF NOT EXISTS meta"))
            .unwrap();
        let foundational_fingerprint = joined
            .iter()
            .position(|call| call.contains("foundational_schema_items"))
            .unwrap();
        let config_schedule_create = joined
            .iter()
            .position(|call| call.contains("CREATE TABLE IF NOT EXISTS nvt_selectors"))
            .unwrap();
        let config_schedule_fingerprint = joined
            .iter()
            .position(|call| call.contains("config_schedule_schema_items"))
            .unwrap();
        let up = joined
            .iter()
            .position(|call| call.ends_with("up -d --build postgres"))
            .unwrap();
        let ready = joined
            .iter()
            .position(|call| call.contains("pg_isready"))
            .unwrap();
        let copy = joined
            .iter()
            .position(|call| call.contains(" exec -T --user 0 postgres sh -ceu "))
            .unwrap();
        let role = joined
            .iter()
            .position(|call| call.contains("CREATE ROLE dba"))
            .unwrap();
        let uuid_create = joined
            .iter()
            .position(|call| call.contains("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"))
            .unwrap();
        let pgcrypto_create = joined
            .iter()
            .position(|call| call.contains("CREATE EXTENSION IF NOT EXISTS pgcrypto;"))
            .unwrap();
        let pg_gvm_create = joined
            .iter()
            .position(|call| call.contains("CREATE EXTENSION IF NOT EXISTS \"pg-gvm\";"))
            .unwrap();
        assert!(
            config < running_state
                && running_state < up
                && up < ready
                && ready < copy
                && copy < role
        );
        assert!(
            role < uuid_create && uuid_create < pgcrypto_create && pgcrypto_create < pg_gvm_create
        );
        assert!(
            pg_gvm_create < foundational_create && foundational_create < foundational_fingerprint
        );
        assert!(
            foundational_fingerprint < config_schedule_create
                && config_schedule_create < config_schedule_fingerprint
        );
        let foundational_sql = calls[foundational_create]
            .args
            .iter()
            .find(|argument| argument.contains("CREATE TABLE IF NOT EXISTS meta"))
            .unwrap();
        assert!(foundational_sql.trim_start().starts_with("BEGIN;"));
        assert!(foundational_sql.trim_end().ends_with("COMMIT;"));
        assert!(!foundational_sql.contains("database_version"));
        let config_schedule_sql = calls[config_schedule_create]
            .args
            .iter()
            .find(|argument| argument.contains("CREATE TABLE IF NOT EXISTS nvt_selectors"))
            .unwrap();
        assert!(config_schedule_sql.trim_start().starts_with("BEGIN;"));
        assert!(config_schedule_sql.trim_end().ends_with("COMMIT;"));
        assert!(!config_schedule_sql.contains("database_version"));
        for extension in POSTGRES_EXTENSIONS {
            assert!(
                joined
                    .iter()
                    .any(|call| call.contains(extension.create_sql))
            );
            assert!(
                joined
                    .iter()
                    .any(|call| call.contains(extension.status_sql))
            );
            assert!(
                result.findings.iter().any(|finding| {
                    finding.check == extension.check && finding.status == "pass"
                })
            );
        }
        let streamed_copies = calls
            .iter()
            .filter(|call| {
                call.args
                    .iter()
                    .any(|arg| arg.contains("cat > \"$temporary\""))
            })
            .collect::<Vec<_>>();
        assert_eq!(streamed_copies.len(), 3);
        assert!(
            streamed_copies
                .iter()
                .all(|call| !call.inherited_fd && call.input_bytes > 0)
        );
        assert!(streamed_copies.iter().all(|call| {
            call.args.last().is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        }));
        assert!(
            calls
                .iter()
                .all(|call| call.args.iter().all(|arg| !arg.contains("/proc/self/fd/")))
        );
        for call in calls
            .iter()
            .filter(|call| call.args.iter().any(|arg| arg == "psql"))
        {
            assert!(!call.args.iter().any(|arg| arg.contains("yafvs-dev")));
            assert_eq!(
                call.environment.get(&OsString::from("PGPASSWORD")),
                Some(&OsString::from("yafvs-dev"))
            );
        }
    }

    #[test]
    fn running_postgres_skips_compose_up_and_preserves_service() {
        let fixture = Fixture::new("postgres-running");
        let runner = Runner {
            postgres_state_output: "postgres\n",
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "pass", "{:?}", result.findings);
        assert!(result.findings.iter().any(|finding| {
            finding.check == "postgres.running-state"
                && finding.status == "pass"
                && finding.message.contains("preserved")
        }));
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.args.ends_with(&[
                "ps".into(),
                "--status".into(),
                "running".into(),
                "--services".into(),
                "postgres".into(),
            ])
        }));
        assert!(!calls.iter().any(|call| {
            call.args.ends_with(&[
                "up".into(),
                "-d".into(),
                "--build".into(),
                "postgres".into(),
            ])
        }));
    }

    #[test]
    fn absent_postgres_performs_compose_up_build() {
        let fixture = Fixture::new("postgres-absent");
        let runner = Runner::passing();
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "pass", "{:?}", result.findings);
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.args.ends_with(&[
                "up".into(),
                "-d".into(),
                "--build".into(),
                "postgres".into(),
            ])
        }));
    }

    #[test]
    fn failed_or_malformed_postgres_state_inspection_stops_before_mutation() {
        for (name, state_success, state_output) in [
            ("state-command-failure", false, ""),
            ("state-malformed-output", true, "postgres\nunexpected\n"),
        ] {
            let fixture = Fixture::new(name);
            let runner = Runner {
                postgres_state_success: state_success,
                postgres_state_output: state_output,
                ..Runner::passing()
            };
            let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
            assert_eq!(result.status, "fail", "{:?}", result.findings);
            assert_eq!(
                result.summary,
                "Runtime initialization stopped before Postgres lifecycle changes."
            );
            assert!(result.findings.iter().any(|finding| {
                finding.check == "postgres.running-state" && finding.status == "fail"
            }));
            let calls = runner.calls.lock().unwrap();
            assert!(!calls.iter().any(|call| {
                call.args
                    .iter()
                    .any(|argument| matches!(argument.as_str(), "up" | "exec" | "restart" | "stop"))
            }));
        }
    }

    #[test]
    fn foundational_schema_creation_failure_stops_before_attestation() {
        let fixture = Fixture::new("foundational-create-failure");
        let runner = Runner {
            foundational_create_success: false,
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while creating foundational schema."
        );
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.args
                .join(" ")
                .contains("CREATE TABLE IF NOT EXISTS meta")
        }));
        assert!(
            !calls
                .iter()
                .any(|call| call.args.join(" ").contains("foundational_schema_items"))
        );
    }

    #[test]
    fn foundational_schema_mismatch_fails_closed() {
        let fixture = Fixture::new("foundational-mismatch");
        let runner = Runner {
            foundational_fingerprint: "not-the-contract\n".into(),
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while verifying foundational schema."
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "postgres.foundational-schema"
                && finding.status == "fail"
                && finding.message.contains("does not match")
        }));
    }

    #[test]
    fn foundational_schema_attestation_query_failure_fails_closed() {
        let fixture = Fixture::new("foundational-query-failure");
        let runner = Runner {
            foundational_fingerprint_success: false,
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while verifying foundational schema."
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "postgres.foundational-schema" && finding.status == "fail"
        }));
    }

    #[test]
    fn config_schedule_schema_creation_failure_stops_before_attestation() {
        let fixture = Fixture::new("config-schedule-create-failure");
        let runner = Runner {
            config_schedule_create_success: false,
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while creating configuration and schedule schema."
        );
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call.args
                .join(" ")
                .contains("CREATE TABLE IF NOT EXISTS nvt_selectors")
        }));
        assert!(
            !calls
                .iter()
                .any(|call| { call.args.join(" ").contains("config_schedule_schema_items") })
        );
    }

    #[test]
    fn config_schedule_schema_mismatch_fails_closed() {
        let fixture = Fixture::new("config-schedule-mismatch");
        let runner = Runner {
            config_schedule_fingerprint: "not-the-contract\n".into(),
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while verifying configuration and schedule schema."
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "postgres.config-schedule-schema"
                && finding.status == "fail"
                && finding.message.contains("does not match")
        }));
    }

    #[test]
    fn config_schedule_schema_attestation_query_failure_fails_closed() {
        let fixture = Fixture::new("config-schedule-query-failure");
        let runner = Runner {
            config_schedule_fingerprint_success: false,
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while verifying configuration and schedule schema."
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "postgres.config-schedule-schema" && finding.status == "fail"
        }));
    }

    #[test]
    fn missing_extension_verification_fails_closed() {
        let fixture = Fixture::new("missing-extension");
        let runner = Runner {
            extension_version: "missing\n",
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while verifying PostgreSQL extensions."
        );
        assert!(result.findings.iter().any(|finding| {
            finding.check == "postgres.uuid-ossp"
                && finding.status == "fail"
                && finding.message.contains("run yafvsctl runtime-init")
        }));
    }

    #[test]
    fn extension_verification_query_failure_fails_closed() {
        let fixture = Fixture::new("extension-status-failure");
        let runner = Runner {
            extension_status_success: false,
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while verifying PostgreSQL extensions."
        );
        assert!(
            result.findings.iter().any(|finding| {
                finding.check == "postgres.uuid-ossp" && finding.status == "fail"
            })
        );
    }

    #[test]
    fn extension_creation_failure_stops_before_verification() {
        let fixture = Fixture::new("extension-create-failure");
        let runner = Runner {
            extension_create_success: false,
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped while creating PostgreSQL extensions."
        );
        let calls = runner.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call
                    .args
                    .join(" ")
                    .contains("CREATE EXTENSION IF NOT EXISTS"))
                .count(),
            1
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.args.join(" ").contains("extversion FROM pg_extension"))
        );
    }

    #[test]
    fn unsafe_runtime_setup_stops_before_docker_or_secrets() {
        let fixture = Fixture::new("setup-failure");
        fs::write(fixture.root.join("YAFVS-runtime"), "not a directory").unwrap();
        let runner = Runner::passing();
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime initialization stopped before Postgres changes."
        );
        assert!(result.artifacts.is_empty());
        assert!(runner.calls.lock().unwrap().is_empty());
        assert!(!fixture.root.join("YAFVS-runtime/secrets").exists());
    }

    #[test]
    fn missing_or_linked_artifacts_stop_before_postgres_start() {
        let fixture = Fixture::new("linked-artifact");
        let control = fixture
            .repo
            .join("build/prefix/share/postgresql/extension/pg-gvm.control");
        fs::remove_file(&control).unwrap();
        symlink("pg-gvm--22.6.sql", &control).unwrap();
        let runner = Runner::passing();
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.summary,
            "Runtime initialization stopped before Postgres changes."
        );
        let calls = runner.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|call| call.args.ends_with(&["config".into(), "--quiet".into()]))
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.args.iter().any(|arg| arg == "up"))
        );
    }

    #[test]
    fn nonempty_collation_mismatch_warns_without_refreshing() {
        let fixture = Fixture::new("collation-nonempty");
        let runner = Runner {
            collation: "1|2\n",
            relations: "4\n",
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "warn", "{:?}", result.findings);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "postgres.collation"
                    && finding.status == "warn"
                    && finding.message.contains("manual review"))
        );
        assert!(
            !runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.args.iter().any(|arg| arg.contains("ALTER DATABASE")))
        );
    }

    #[test]
    fn empty_collation_mismatch_refreshes_through_another_database() {
        let fixture = Fixture::new("collation-empty");
        let runner = Runner {
            collation: "1|2\n",
            relations: "0\n",
            ..Runner::passing()
        };
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| {});
        assert_eq!(result.status, "pass", "{:?}", result.findings);
        let calls = runner.calls.lock().unwrap();
        let refreshes = calls
            .iter()
            .filter(|call| call.args.iter().any(|arg| arg.contains("ALTER DATABASE")))
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 3);
        assert!(refreshes.iter().all(|call| {
            call.args
                .windows(2)
                .any(|parts| parts[0] == "-d" && !parts[1].is_empty())
        }));
    }

    #[test]
    fn readiness_exhaustion_stops_before_database_mutation() {
        let fixture = Fixture::new("not-ready");
        let runner = Runner {
            ready: false,
            ..Runner::passing()
        };
        let mut sleeps = 0;
        let result = command_runtime_init_with(&fixture.repo, &runner, &mut |_| sleeps += 1);
        assert_eq!(result.status, "fail", "{:?}", result.findings);
        assert_eq!(
            result.summary,
            "Runtime initialization stopped before database setup."
        );
        let calls = runner.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.args.iter().any(|arg| arg == "pg_isready"))
                .count(),
            READY_ATTEMPTS
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.args.iter().any(|arg| arg == "psql"))
        );
        assert_eq!(sleeps, READY_ATTEMPTS - 1);
    }

    #[test]
    fn artifact_permissions_are_not_broadened_by_inspection() {
        let fixture = Fixture::new("artifact-mode");
        let control = fixture
            .repo
            .join("build/prefix/share/postgresql/extension/pg-gvm.control");
        fs::set_permissions(&control, fs::Permissions::from_mode(0o664)).unwrap();
        let (findings, artifacts) = inspect_pg_gvm_artifacts(&fixture.repo);
        assert!(artifacts.is_none());
        assert!(findings.iter().any(|finding| finding.status == "fail"));
        assert_eq!(
            fs::metadata(control).unwrap().permissions().mode() & 0o777,
            0o664
        );
    }
}
