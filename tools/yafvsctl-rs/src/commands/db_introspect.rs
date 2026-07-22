// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata, output_tail};
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const PSQL_SCRIPT: &str = r#"export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"; exec psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-yafvs}" -d "${POSTGRES_DB:-yafvs}" -At -c "$1""#;

const TABLES: [(&str, &str); 31] = [
    ("public", "meta"),
    ("public", "users"),
    ("public", "tasks"),
    ("public", "targets"),
    ("public", "reports"),
    ("public", "results"),
    ("public", "report_hosts"),
    ("public", "hosts"),
    ("public", "credentials"),
    ("public", "port_lists"),
    ("public", "configs"),
    ("public", "scanners"),
    ("public", "schedules"),
    ("public", "filters"),
    ("public", "tags"),
    ("public", "overrides"),
    ("public", "alerts"),
    ("public", "scopes"),
    ("public", "scope_targets"),
    ("public", "scope_hosts"),
    ("public", "scope_reports"),
    ("public", "scope_report_sources"),
    ("public", "scope_report_system_metrics"),
    ("public", "scope_report_vulnerability_metrics"),
    ("public", "nvts"),
    ("public", "cves"),
    ("public", "cpes"),
    ("cert", "cert_bund_advs"),
    ("cert", "cert_bund_cves"),
    ("cert", "dfn_cert_advs"),
    ("cert", "dfn_cert_cves"),
];

const COLUMNS: [(&str, &str, &str); 12] = [
    ("public", "meta", "name"),
    ("public", "meta", "value"),
    ("public", "reports", "id"),
    ("public", "reports", "task"),
    ("public", "results", "id"),
    ("public", "results", "report"),
    ("public", "tasks", "id"),
    ("public", "targets", "id"),
    ("public", "scopes", "id"),
    ("public", "scope_reports", "id"),
    ("cert", "cert_bund_advs", "uuid"),
    ("cert", "dfn_cert_advs", "uuid"),
];

static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());

#[derive(Clone, Debug, Default, Serialize)]
struct Details {
    database: BTreeMap<String, Value>,
    schemas: BTreeMap<String, Presence>,
    tables: BTreeMap<String, TableState>,
    columns: BTreeMap<String, Presence>,
    requested_columns: Vec<RequestedColumns>,
}

#[derive(Clone, Debug, Serialize)]
struct Presence {
    exists: bool,
}

#[derive(Clone, Debug, Serialize)]
struct TableState {
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    row_count: Option<Option<i64>>,
}

#[derive(Clone, Debug, Serialize)]
struct RequestedColumns {
    table: String,
    exists: bool,
    columns: Vec<ColumnDescription>,
}

#[derive(Clone, Debug, Serialize)]
struct ColumnDescription {
    name: String,
    data_type: String,
    is_nullable: String,
}

pub fn command_runtime_db_introspect(
    repo_root: &Path,
    status_only: bool,
    columns_for: &[String],
) -> ResultEnvelope {
    command_with(repo_root, status_only, columns_for, &SystemCommandRunner)
}

fn command_with(
    repo_root: &Path,
    status_only: bool,
    columns_for: &[String],
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mut findings = Vec::new();
    let mut details = Details::default();
    let mut requested = Vec::new();
    let mut seen = BTreeSet::new();

    for request in columns_for {
        match parse_schema_table(request) {
            Ok(value) if seen.insert(value.clone()) => requested.push(value),
            Ok(_) => {}
            Err(message) => findings.push(
                Finding::new("fail", "db-introspect.columns-for-shape", message)
                    .with_details(json!({"input": request})),
            ),
        }
    }

    if !service_running(repo_root, "postgres", runner) {
        findings.push(Finding::new(
            "warn",
            "db-introspect.postgres",
            "Postgres is not running; database introspection is unavailable.".into(),
        ));
        let mut result = make_result(
            metadata(repo_root, "runtime-db-introspect", runner),
            "Runtime database introspection could not inspect Postgres.".into(),
            findings,
        )
        .with_details(json!(details));
        if status_only {
            result = status_only_result(result, &details);
        }
        return result;
    }

    let identity = psql(
        repo_root,
        "SELECT current_database() || '|' || current_user || '|' || session_user;",
        runner,
    );
    let identity_value = psql_value(&identity.stdout);
    let identity_parts = identity_value.splitn(3, '|').collect::<Vec<_>>();
    if identity.success && identity_parts.len() == 3 {
        details
            .database
            .insert("name".into(), json!(identity_parts[0]));
        details
            .database
            .insert("current_user".into(), json!(identity_parts[1]));
        details
            .database
            .insert("session_user".into(), json!(identity_parts[2]));
        findings.push(
            Finding::new(
                "pass",
                "db-introspect.identity",
                "Database identity captured.".into(),
            )
            .with_details(json!({"database": details.database})),
        );
    } else {
        findings.push(
            Finding::new(
                "fail",
                "db-introspect.identity",
                "Database identity query failed.".into(),
            )
            .with_details(json!({"output_tail": failure_tail(repo_root, &identity.stdout, 80)})),
        );
    }

    let version = psql(
        repo_root,
        "SELECT COALESCE((SELECT value FROM meta WHERE name = 'database_version'), 'missing');",
        runner,
    );
    let database_version = if version.success {
        psql_value(&version.stdout)
    } else {
        String::new()
    };
    details
        .database
        .insert("manager_database_version".into(), json!(database_version));
    if let Some(identity_finding) = findings
        .iter_mut()
        .find(|finding| finding.check == "db-introspect.identity" && finding.status == "pass")
    {
        identity_finding.details = Some(json!({"database": details.database}));
    }
    findings.push(
        Finding::new(
            if version.success && !database_version.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "db-introspect.database-version",
            format!(
                "Manager database version is {}.",
                if database_version.is_empty() {
                    "unknown"
                } else {
                    &database_version
                }
            ),
        )
        .with_details(json!({"output_tail": if version.success { output_tail(&version.stdout, 40) } else { failure_tail(repo_root, &version.stdout, 40) }})),
    );

    let schemas = psql(
        repo_root,
        "SELECT schema_name FROM information_schema.schemata WHERE schema_name IN ('public', 'cert') ORDER BY schema_name;",
        runner,
    );
    let schema_names = if schemas.success {
        schemas
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    for schema in ["public", "cert"] {
        details.schemas.insert(
            schema.into(),
            Presence {
                exists: schema_names.contains(schema),
            },
        );
    }
    let missing_schemas = details
        .schemas
        .iter()
        .filter(|(_, value)| !value.exists)
        .map(|(schema, _)| schema.clone())
        .collect::<Vec<_>>();
    findings.push(
        Finding::new(
            if schemas.success && missing_schemas.is_empty() {
                "pass"
            } else {
                "warn"
            },
            "db-introspect.schemas",
            if missing_schemas.is_empty() {
                "Expected database schemas are present.".into()
            } else {
                format!("Missing expected schemas: {}.", missing_schemas.join(", "))
            },
        )
        .with_details(json!({
            "schemas": details.schemas,
            "output_tail": if schemas.success { output_tail(&schemas.stdout, 40) } else { failure_tail(repo_root, &schemas.stdout, 40) },
        })),
    );

    let table_query = psql(repo_root, &table_presence_query(), runner);
    if table_query.success {
        let presence = parse_presence(&table_query.stdout);
        for (schema, table) in TABLES {
            let key = format!("{schema}.{table}");
            let exists = presence.get(&key).copied().unwrap_or(false);
            let row_count = exists.then(|| table_row_count(repo_root, schema, table, runner));
            details.tables.insert(key, TableState { exists, row_count });
        }
        findings.push(
            Finding::new(
                "pass",
                "db-introspect.tables",
                "Fixed database table catalog captured.".into(),
            )
            .with_details(json!({"table_count": details.tables.len()})),
        );
    } else {
        findings.push(
            Finding::new(
                "fail",
                "db-introspect.tables",
                "Fixed database table catalog query failed.".into(),
            )
            .with_details(json!({"output_tail": failure_tail(repo_root, &table_query.stdout, 80)})),
        );
    }

    let column_query = psql(repo_root, &column_presence_query(), runner);
    if column_query.success {
        details.columns = parse_presence(&column_query.stdout)
            .into_iter()
            .map(|(key, exists)| (key, Presence { exists }))
            .collect();
        findings.push(
            Finding::new(
                "pass",
                "db-introspect.columns",
                "Fixed database column catalog captured.".into(),
            )
            .with_details(json!({"column_count": details.columns.len()})),
        );
    } else {
        findings.push(
            Finding::new(
                "fail",
                "db-introspect.columns",
                "Fixed database column catalog query failed.".into(),
            )
            .with_details(
                json!({"output_tail": failure_tail(repo_root, &column_query.stdout, 80)}),
            ),
        );
    }

    for (schema, table) in requested {
        let key = format!("{schema}.{table}");
        let query = requested_columns_query(&schema, &table);
        let output = psql(repo_root, &query, runner);
        if output.success {
            let columns = parse_column_descriptions(&output.stdout);
            let count = columns.len();
            details.requested_columns.push(RequestedColumns {
                table: key.clone(),
                exists: !columns.is_empty(),
                columns,
            });
            findings.push(
                Finding::new(
                    if count == 0 { "warn" } else { "pass" },
                    "db-introspect.requested-columns",
                    if count == 0 {
                        format!("No columns found for {key}.")
                    } else {
                        format!("Column catalog captured for {key}.")
                    },
                )
                .with_details(json!({"table": key, "column_count": count})),
            );
        } else {
            details.requested_columns.push(RequestedColumns {
                table: key.clone(),
                exists: false,
                columns: Vec::new(),
            });
            findings.push(
                Finding::new(
                    "fail",
                    "db-introspect.requested-columns",
                    format!("Column catalog query failed for {key}."),
                )
                .with_details(json!({
                    "table": key,
                    "output_tail": failure_tail(repo_root, &output.stdout, 80),
                })),
            );
        }
    }

    let mut result = make_result(
        metadata(repo_root, "runtime-db-introspect", runner),
        "Runtime database introspection completed.".into(),
        findings,
    )
    .with_details(json!(details));
    if status_only {
        result = status_only_result(result, &details);
    }
    result
}

fn status_only_result(mut result: ResultEnvelope, details: &Details) -> ResultEnvelope {
    let finding_count = result.findings.len();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let non_pass_count = non_pass.len();
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "runtime-db-introspect.status-only",
            "Runtime database introspection passed; no non-pass findings.".into(),
        ));
    }
    result.findings = non_pass;
    result.details = Some(json!({
        "database_name": details.database.get("name").cloned().unwrap_or(Value::Null),
        "manager_database_version": details.database.get("manager_database_version").cloned().unwrap_or(Value::Null),
        "schema_count": details.schemas.len(),
        "missing_schema_count": details.schemas.values().filter(|item| !item.exists).count(),
        "table_count": details.tables.len(),
        "existing_table_count": details.tables.values().filter(|item| item.exists).count(),
        "column_count": details.columns.len(),
        "existing_column_count": details.columns.values().filter(|item| item.exists).count(),
        "requested_column_table_count": details.requested_columns.len(),
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
    }));
    result
}

fn parse_schema_table(value: &str) -> Result<(String, String), String> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err("expected schema.table".into());
    }
    let schema = parts[0].trim();
    let table = parts[1].trim();
    if !matches!(schema, "public" | "cert" | "scap") {
        return Err(format!("schema {schema:?} is not allowed"));
    }
    if !IDENTIFIER.is_match(table) {
        return Err("table must be a simple SQL identifier".into());
    }
    Ok((schema.into(), table.into()))
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn table_presence_query() -> String {
    let values = TABLES
        .iter()
        .map(|(schema, table)| format!("({}, {})", sql_literal(schema), sql_literal(table)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "WITH wanted(schema_name, table_name) AS (VALUES {values}) SELECT wanted.schema_name || '.' || wanted.table_name || '|' || (tables.table_name IS NOT NULL) FROM wanted LEFT JOIN information_schema.tables tables ON tables.table_schema = wanted.schema_name AND tables.table_name = wanted.table_name ORDER BY wanted.schema_name, wanted.table_name;"
    )
}

fn column_presence_query() -> String {
    let values = COLUMNS
        .iter()
        .map(|(schema, table, column)| {
            format!(
                "({}, {}, {})",
                sql_literal(schema),
                sql_literal(table),
                sql_literal(column)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "WITH wanted(schema_name, table_name, column_name) AS (VALUES {values}) SELECT wanted.schema_name || '.' || wanted.table_name || '.' || wanted.column_name || '|' || (columns.column_name IS NOT NULL) FROM wanted LEFT JOIN information_schema.columns columns ON columns.table_schema = wanted.schema_name AND columns.table_name = wanted.table_name AND columns.column_name = wanted.column_name ORDER BY wanted.schema_name, wanted.table_name, wanted.column_name;"
    )
}

fn requested_columns_query(schema: &str, table: &str) -> String {
    format!(
        "SELECT column_name || '|' || data_type || '|' || is_nullable FROM information_schema.columns WHERE table_schema = {} AND table_name = {} ORDER BY ordinal_position;",
        sql_literal(schema),
        sql_literal(table)
    )
}

fn table_row_count(
    repo_root: &Path,
    schema: &str,
    table: &str,
    runner: &dyn CommandRunner,
) -> Option<i64> {
    let query = format!(
        "SELECT count(*) FROM {}.{};",
        sql_identifier(schema),
        sql_identifier(table)
    );
    let output = psql(repo_root, &query, runner);
    output
        .success
        .then(|| psql_value(&output.stdout).parse().ok())
        .flatten()
}

fn parse_presence(stdout: &str) -> BTreeMap<String, bool> {
    stdout
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().split_once('|')?;
            Some((
                name.to_string(),
                matches!(value.trim().to_lowercase().as_str(), "t" | "true" | "1"),
            ))
        })
        .collect()
}

fn parse_column_descriptions(stdout: &str) -> Vec<ColumnDescription> {
    stdout
        .lines()
        .filter_map(|line| {
            let parts = line.splitn(3, '|').collect::<Vec<_>>();
            (parts.len() == 3).then(|| ColumnDescription {
                name: parts[0].into(),
                data_type: parts[1].into(),
                is_nullable: parts[2].into(),
            })
        })
        .collect()
}

fn psql_value(stdout: &str) -> String {
    const IGNORED: [&str; 4] = ["WARNING:", "DETAIL:", "HINT:", "NOTICE:"];
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty() && !IGNORED.iter().any(|prefix| line.starts_with(prefix)))
        .unwrap_or_default()
        .to_string()
}

fn diagnostic_environment(repo_root: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = runtime_environment(repo_root);
    environment.remove(&OsString::from("POSTGRES_PASSWORD"));
    environment
}

fn service_running(repo_root: &Path, service: &str, runner: &dyn CommandRunner) -> bool {
    let arguments = compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]);
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(container_id) = runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(&diagnostic_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
    else {
        return false;
    };
    runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &container_id],
            Some(repo_root),
            Some(&diagnostic_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .is_some_and(|output| output.success && output.stdout.trim() == "true")
}

fn psql(repo_root: &Path, sql: &str, runner: &dyn CommandRunner) -> ProcessOutput {
    let arguments = compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "postgres".into(),
            "sh".into(),
            "-ceu".into(),
            PSQL_SCRIPT.into(),
            "yafvsctl-psql".into(),
            sql.into(),
        ],
    );
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    runner
        .run_with(
            "docker",
            &arguments,
            Some(repo_root),
            Some(&diagnostic_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: "Postgres query process could not be started.".into(),
            stderr: String::new(),
        })
}

fn failure_tail(repo_root: &Path, stdout: &str, lines: usize) -> Vec<String> {
    let environment = runtime_environment(repo_root);
    let password = environment
        .get(&OsString::from("POSTGRES_PASSWORD"))
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty());
    output_tail(stdout, lines)
        .into_iter()
        .map(|line| {
            password
                .map(|password| line.replace(password, "[redacted]"))
                .unwrap_or(line)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Runner {
        calls: RefCell<Vec<Vec<String>>>,
        environments_contain_password: RefCell<Vec<bool>>,
        postgres_running: bool,
        fail_queries: bool,
        invalid_row_count: bool,
    }

    impl Runner {
        fn successful() -> Self {
            Self {
                postgres_running: true,
                ..Self::default()
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            self.run_with(program, args, None, None, None)
        }

        fn run_with(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            environment: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
        ) -> Option<ProcessOutput> {
            self.environments_contain_password.borrow_mut().push(
                environment.is_some_and(|values| {
                    values.contains_key(&OsString::from("POSTGRES_PASSWORD"))
                }),
            );
            let mut call = vec![program.to_string()];
            call.extend(args.iter().map(|argument| (*argument).to_string()));
            self.calls.borrow_mut().push(call);
            let stdout = if program == "git" {
                "abc1234\n".into()
            } else if args.ends_with(&["ps", "-q", "postgres"]) {
                if self.postgres_running {
                    "postgres-container\n".into()
                } else {
                    String::new()
                }
            } else if args == ["inspect", "-f", "{{.State.Running}}", "postgres-container"] {
                "true\n".into()
            } else {
                let sql = *args.last()?;
                if self.fail_queries {
                    return Some(ProcessOutput {
                        success: false,
                        exit_code: Some(1),
                        stdout: (0..100)
                            .map(|index| format!("failure-{index}"))
                            .chain(std::iter::once("yafvs-dev".into()))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        stderr: String::new(),
                    });
                }
                if sql.contains("current_database()") {
                    "yafvs|yafvs|yafvs\n".into()
                } else if sql.contains("database_version") {
                    "283\n".into()
                } else if sql.contains("information_schema.schemata") {
                    "cert\npublic\n".into()
                } else if sql.contains("WITH wanted(schema_name, table_name, column_name)") {
                    COLUMNS
                        .iter()
                        .map(|(schema, table, column)| format!("{schema}.{table}.{column}|t"))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else if sql.contains("WITH wanted(schema_name, table_name)") {
                    TABLES
                        .iter()
                        .map(|(schema, table)| format!("{schema}.{table}|t"))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else if sql.contains("column_name || '|' || data_type") {
                    "id|integer|NO\nowner|integer|YES\n".into()
                } else if sql.starts_with("SELECT count(*)") {
                    if self.invalid_row_count {
                        "not-an-integer\n".into()
                    } else {
                        "7\n".into()
                    }
                } else {
                    return None;
                }
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn safe_schema_table_parser_rejects_injection_shapes() {
        assert_eq!(
            parse_schema_table(" public.targets ").unwrap(),
            ("public".into(), "targets".into())
        );
        for value in [
            "targets",
            "public.targets.extra",
            "private.targets",
            "public.targets;DROP",
            "public.1targets",
        ] {
            assert!(parse_schema_table(value).is_err(), "{value}");
        }
    }

    #[test]
    fn query_builders_are_fixed_select_only_statements() {
        let queries = [
            table_presence_query(),
            column_presence_query(),
            requested_columns_query("public", "targets"),
        ];
        for query in queries {
            let uppercase = query.to_uppercase();
            assert!(uppercase.starts_with("SELECT") || uppercase.starts_with("WITH"));
            for forbidden in [
                " INSERT ", " UPDATE ", " DELETE ", " DROP ", " ALTER ", " CREATE ",
            ] {
                assert!(!uppercase.contains(forbidden), "{query}");
            }
        }
    }

    #[test]
    fn successful_command_preserves_full_and_status_only_contracts() {
        let runner = Runner::successful();
        let requests = vec!["public.targets".into(), "public.targets".into()];
        let full = command_with(Path::new("/srv/YAFVS"), false, &requests, &runner);
        assert_eq!(full.status, "pass");
        let value = serde_json::to_value(&full).unwrap();
        assert_eq!(
            value["details"]["database"]["manager_database_version"],
            "283"
        );
        assert_eq!(
            value["findings"][0]["details"]["database"]["manager_database_version"],
            "283"
        );
        assert_eq!(value["details"]["tables"]["public.meta"]["row_count"], 7);
        assert_eq!(
            value["details"]["requested_columns"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            value["details"]["requested_columns"][0]["columns"][0]["name"],
            "id"
        );

        let compact = command_with(Path::new("/srv/YAFVS"), true, &requests, &runner);
        let compact = serde_json::to_value(&compact).unwrap();
        assert_eq!(compact["details"]["table_count"], TABLES.len());
        assert_eq!(compact["details"]["column_count"], COLUMNS.len());
        assert_eq!(compact["details"]["requested_column_table_count"], 1);
        assert_eq!(compact["details"]["non_pass_count"], 0);
        assert_eq!(
            compact["findings"][0]["check"],
            "runtime-db-introspect.status-only"
        );
        assert!(
            runner
                .environments_contain_password
                .borrow()
                .iter()
                .all(|present| !present)
        );
        assert!(!serde_json::to_string(&full).unwrap().contains("yafvs-dev"));
    }

    #[test]
    fn absent_postgres_and_invalid_requests_preserve_status_semantics() {
        let runner = Runner::default();
        let warning = command_with(Path::new("/srv/YAFVS"), true, &[], &runner);
        assert_eq!(warning.status, "warn");
        assert_eq!(warning.findings[0].check, "db-introspect.postgres");

        let failed = command_with(
            Path::new("/srv/YAFVS"),
            false,
            &["public.targets;DROP".into(), "private.targets".into()],
            &runner,
        );
        assert_eq!(failed.status, "fail");
        assert_eq!(
            failed
                .findings
                .iter()
                .filter(|finding| finding.check == "db-introspect.columns-for-shape")
                .count(),
            2
        );
        assert!(
            !runner
                .calls
                .borrow()
                .iter()
                .flatten()
                .any(|argument| argument.contains("DROP"))
        );
    }

    #[test]
    fn failures_are_bounded_redacted_and_invalid_counts_are_null() {
        let failed_runner = Runner {
            postgres_running: true,
            fail_queries: true,
            ..Runner::default()
        };
        let failed = command_with(Path::new("/srv/YAFVS"), false, &[], &failed_runner);
        let serialized = serde_json::to_string(&failed).unwrap();
        assert!(!serialized.contains("yafvs-dev"));
        assert!(serialized.contains("[redacted]"));
        assert!(failed.findings.iter().all(|finding| {
            finding
                .details
                .as_ref()
                .and_then(|details| details.get("output_tail"))
                .and_then(Value::as_array)
                .is_none_or(|tail| tail.len() <= 80)
        }));

        let invalid_count_runner = Runner {
            postgres_running: true,
            invalid_row_count: true,
            ..Runner::default()
        };
        let result = command_with(Path::new("/srv/YAFVS"), false, &[], &invalid_count_runner);
        let value = serde_json::to_value(result).unwrap();
        assert!(value["details"]["tables"]["public.meta"]["row_count"].is_null());
    }
}
