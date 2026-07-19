// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{iso_system_time, metadata, output_tail, runtime_dir};
use super::compose::{compose_command, runtime_environment};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const RETAINED_PERFORMANCE_ARTIFACTS: usize = 30;
const PERFORMANCE_ARTIFACT: &str = "performance-snapshot.json";
const PERFORMANCE_STEM: &str = "performance-snapshot";
const REDIS_CONTAINER_SOCKET: &str = "/run/redis-openvas/redis.sock";

const DATABASE_CORE_TABLES: [&str; 17] = [
    "meta",
    "users",
    "tasks",
    "targets",
    "reports",
    "results",
    "report_hosts",
    "hosts",
    "credentials",
    "port_lists",
    "configs",
    "scanners",
    "schedules",
    "filters",
    "tags",
    "overrides",
    "alerts",
];
const DATABASE_SCOPE_TABLES: [&str; 7] = [
    "scopes",
    "scope_targets",
    "scope_hosts",
    "scope_reports",
    "scope_report_sources",
    "scope_report_system_metrics",
    "scope_report_vulnerability_metrics",
];

const PSQL_SCRIPT: &str = r#"export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"; exec psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-yafvs}" -d "${POSTGRES_DB:-yafvs}" -At -c "$1""#;

const DECIMAL_BYTE_UNITS: [(&str, i64); 6] = [
    ("B", 1),
    ("KB", 1000),
    ("kB", 1000),
    ("MB", 1000_i64.pow(2)),
    ("GB", 1000_i64.pow(3)),
    ("TB", 1000_i64.pow(4)),
];
const BINARY_BYTE_UNITS: [(&str, i64); 4] = [
    ("KiB", 1024),
    ("MiB", 1024_i64.pow(2)),
    ("GiB", 1024_i64.pow(3)),
    ("TiB", 1024_i64.pow(4)),
];

#[derive(Clone, Debug, Default)]
struct RuntimeDetails {
    docker_stats: Vec<Map<String, Value>>,
    docker_stats_numeric: Vec<Map<String, Value>>,
    docker_top: Map<String, Value>,
    database: Map<String, Value>,
    report_workflow: Option<Value>,
    scanner_redis: Option<Value>,
    paths: Map<String, Value>,
}

pub fn command_runtime_performance_snapshot(repo_root: &Path) -> ResultEnvelope {
    command_runtime_performance_snapshot_with(repo_root, &SystemCommandRunner)
}

fn command_runtime_performance_snapshot_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_dir = performance_artifact_dir(repo_root);
    let (latest_path, timestamped_path) =
        retained_json_artifact_paths(&artifact_dir, PERFORMANCE_STEM, PERFORMANCE_ARTIFACT);

    let mut findings = Vec::new();
    let mut details = RuntimeDetails::default();

    let stats_output = run_docker_command(
        repo_root,
        &[
            "stats".to_string(),
            "--no-stream".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
        runner,
    );

    if stats_output.success {
        details.docker_stats = parse_docker_stats_lines(&stats_output.stdout);
    }
    details.docker_stats_numeric = details
        .docker_stats
        .iter()
        .map(normalize_docker_stat)
        .collect::<Vec<_>>();
    details.docker_top = top_map(
        &details.docker_stats_numeric,
        &[
            "cpu_percent",
            "memory_usage_bytes",
            "network_rx_bytes",
            "network_tx_bytes",
            "block_read_bytes",
            "block_write_bytes",
            "pids",
        ],
    );

    findings.push(process_step_finding(
        if stats_output.success { "pass" } else { "warn" },
        "performance.docker-stats",
        format!(
            "docker stats snapshot exit code {}.",
            stats_exit_code(&stats_output)
        ),
        &stats_output,
        &docker_arguments(&["stats", "--no-stream", "--format", "json"]),
    ));

    if stats_output.success {
        findings.push(
            Finding::new(
                "pass",
                "performance.docker-stats-numeric",
                "Docker stats numeric summary captured.".into(),
            )
            .with_details(json!({
                "container_count": details.docker_stats_numeric.len(),
                "top": details.docker_top,
            })),
        );
    }

    if service_running(repo_root, "postgres", runner) {
        let db_size_output = psql(
            repo_root,
            "SELECT pg_database_size(current_database());",
            runner,
        );
        let byte_count = if db_size_output.success {
            psql_value(&db_size_output.stdout)
                .parse::<i64>()
                .ok()
                .and_then(|value| if value >= 0 { Some(value) } else { None })
        } else {
            None
        };
        details.database.insert(
            "byte_count".into(),
            byte_count.map(Value::from).unwrap_or(Value::Null),
        );
        findings.push(
            Finding::new(
                if db_size_output.success {
                    "pass"
                } else {
                    "warn"
                },
                "performance.database-size",
                if db_size_output.success {
                    "Database size captured.".into()
                } else {
                    "Database size query failed.".into()
                },
            )
            .with_details(json!({
                "output_tail": output_tail(&db_size_output.stdout, 40),
                "byte_count": details
                    .database
                    .get("byte_count")
                    .cloned()
                    .unwrap_or(Value::Null),
            })),
        );

        let tables = combine_tables();
        let (table_query, presence) = table_presence_rows(repo_root, runner, &tables);
        if table_query.success {
            let mut row_counts = BTreeMap::new();
            for (table, present) in presence {
                if present {
                    row_counts.insert(
                        table.clone(),
                        table_row_count(repo_root, &table, runner)
                            .map(Value::from)
                            .unwrap_or(Value::Null),
                    );
                }
            }
            details.database.insert(
                "row_counts".into(),
                Value::Object(row_counts.into_iter().collect()),
            );
            findings.push(
                Finding::new(
                    "pass",
                    "performance.table-row-counts",
                    "Database row-count estimates captured for known tables.".into(),
                )
                .with_details(json!({
                    "table_count": details
                        .database
                        .get("row_counts")
                        .and_then(Value::as_object)
                        .map(|object| object.len())
                        .unwrap_or(0),
                })),
            );
        } else {
            findings.push(
                Finding::new(
                    "warn",
                    "performance.table-row-counts",
                    "Could not inspect database row counts.".into(),
                )
                .with_details(json!({ "output_tail": output_tail(&table_query.stdout, 80) })),
            );
        }

        let largest_relations_output = psql(
            repo_root,
            "SELECT relname || '|' || pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','m','i','t') ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 10;",
            runner,
        );
        let largest_relations = if largest_relations_output.success {
            parse_relation_size_rows(&largest_relations_output.stdout)
        } else {
            Vec::new()
        };
        details.database.insert(
            "largest_relations".into(),
            Value::Array(
                largest_relations
                    .into_iter()
                    .map(|row| Value::Object(row.into_iter().collect()))
                    .collect(),
            ),
        );
        findings.push(
            Finding::new(
                if largest_relations_output.success {
                    "pass"
                } else {
                    "warn"
                },
                "performance.database-largest-relations",
                if largest_relations_output.success {
                    "Largest database relations captured.".into()
                } else {
                    "Largest database relation query failed.".into()
                },
            )
            .with_details(json!({
                "relations": details
                    .database
                    .get("largest_relations")
                    .cloned()
                    .unwrap_or(Value::Array(Vec::new())),
                "output_tail": output_tail(&largest_relations_output.stdout, 80),
            })),
        );

        let report_workflow_output = psql(
            repo_root,
            "SELECT 'reports|' || count (*) FROM reports UNION ALL SELECT 'scope_reports|' || count (*) FROM scope_reports UNION ALL SELECT 'scope_report_sources|' || count (*) FROM scope_report_sources UNION ALL SELECT 'max_sources_per_scope_report|' || coalesce ((SELECT max (source_count) FROM (SELECT count (*) AS source_count FROM scope_report_sources GROUP BY scope_report) x), 0) UNION ALL SELECT 'max_results_per_report|' || coalesce ((SELECT max (result_count) FROM (SELECT count (*) AS result_count FROM results GROUP BY report) x), 0) UNION ALL SELECT 'max_scope_report_result_count|' || coalesce ((SELECT max (result_count) FROM scope_reports), 0) UNION ALL SELECT 'max_scope_report_source_host_count|' || coalesce ((SELECT max (evidence_host_count) FROM scope_reports), 0);",
            runner,
        );
        let report_workflow = if report_workflow_output.success {
            parse_pipe_int_rows(&report_workflow_output.stdout)
        } else {
            BTreeMap::new()
        };
        let report_workflow_detail = Value::Object(
            report_workflow
                .iter()
                .map(|(name, value)| (name.clone(), Value::from(*value)))
                .collect(),
        );
        details.report_workflow = Some(report_workflow_detail.clone());
        findings.push(
            Finding::new(
                if report_workflow_output.success {
                    "pass"
                } else {
                    "warn"
                },
                "performance.report-workflow",
                if report_workflow_output.success {
                    "Report workflow baseline captured.".into()
                } else {
                    "Report workflow baseline query failed.".into()
                },
            )
            .with_details(json!({
                "report_workflow": report_workflow_detail,
                "output_tail": output_tail(&report_workflow_output.stdout, 80),
            })),
        );
    } else {
        findings.push(Finding::new(
            "warn",
            "performance.database",
            "Postgres is not running; database size and row counts are unavailable.".into(),
        ));
    }

    if service_running(repo_root, "redis-openvas", runner) {
        let metrics = scanner_redis_metrics(repo_root, runner);
        let metrics_ready = metrics.get("dbsize_status").and_then(Value::as_str) == Some("pass")
            && metrics.get("info_status").and_then(Value::as_str) == Some("pass");
        findings.push(
            Finding::new(
                if metrics_ready { "pass" } else { "warn" },
                "performance.scanner-redis",
                if metrics_ready {
                    "Scanner Redis performance counters captured without key names or values."
                        .into()
                } else {
                    "Scanner Redis performance counters could not be fully captured.".into()
                },
            )
            .with_path(&scanner_redis_socket_path(repo_root).display().to_string())
            .with_details(json!({ "scanner_redis": metrics.clone() })),
        );
        details.scanner_redis = Some(Value::Object(metrics));
    } else {
        findings.push(
            Finding::new(
                "warn",
                "performance.scanner-redis",
                "Scanner Redis is not running; performance counters are unavailable.".into(),
            )
            .with_path(&scanner_redis_socket_path(repo_root).display().to_string()),
        );
    }

    let paths = [
        (
            "runtime-artifacts",
            runtime_dir(repo_root).join("artifacts"),
            true,
            false,
        ),
        (
            "runtime-logs",
            runtime_dir(repo_root).join("logs"),
            true,
            false,
        ),
        ("gsa-static", gsad_static_dir(repo_root), true, true),
        ("build-prefix", repo_root.join("build/prefix"), false, false),
    ];

    for (name, path, recursive, with_largest) in paths {
        let mut summary = path_tree_summary(&path, recursive);
        if with_largest {
            summary.insert(
                "largest_files".into(),
                Value::Array(
                    largest_files(&path, 10)
                        .into_iter()
                        .map(|row| Value::Object(row.into_iter().collect()))
                        .collect(),
                ),
            );
        }
        details
            .paths
            .insert(name.to_string(), Value::Object(summary.clone()));
        findings.push(
            Finding::new(
                if path.exists() { "pass" } else { "warn" },
                "performance.path",
                if path.exists() {
                    format!("{name} size snapshot captured.")
                } else {
                    format!("{name} path is missing.")
                },
            )
            .with_path(&path.display().to_string())
            .with_details(json!({ "summary": summary.clone() })),
        );
    }

    let mut output_details = Map::new();
    output_details.insert(
        "docker_stats".into(),
        Value::Array(
            details
                .docker_stats
                .into_iter()
                .map(Value::Object)
                .collect(),
        ),
    );
    output_details.insert(
        "docker_stats_numeric".into(),
        Value::Array(
            details
                .docker_stats_numeric
                .into_iter()
                .map(Value::Object)
                .collect(),
        ),
    );
    output_details.insert("docker_top".into(), Value::Object(details.docker_top));
    output_details.insert("database".into(), Value::Object(details.database));
    output_details.insert("paths".into(), Value::Object(details.paths));
    if let Some(report_workflow) = details.report_workflow {
        output_details.insert("report_workflow".into(), report_workflow);
    }
    if let Some(scanner_redis) = details.scanner_redis {
        output_details.insert("scanner_redis".into(), scanner_redis);
    }

    let mut result = make_result(
        metadata(repo_root, "runtime-performance-snapshot", runner),
        "Runtime performance snapshot completed.".into(),
        findings,
    )
    .with_artifacts(vec![
        latest_path.display().to_string(),
        timestamped_path.display().to_string(),
    ])
    .with_details(Value::Object(output_details));

    if let Err(error) = write_retained_json_artifact(
        &latest_path,
        &timestamped_path,
        &result,
        PERFORMANCE_STEM,
        RETAINED_PERFORMANCE_ARTIFACTS,
    ) {
        result.findings.push(
            Finding::new(
                "fail",
                "performance.artifact",
                format!("Runtime performance snapshot artifact write failed: {error}."),
            )
            .with_path(&artifact_dir.display().to_string()),
        );
        result.status = "fail".into();
    }

    result
}

fn docker_arguments(arguments: &[&str]) -> Vec<String> {
    std::iter::once("docker".to_string())
        .chain(arguments.iter().map(|argument| (*argument).to_string()))
        .collect()
}

fn run_docker_command(
    repo_root: &Path,
    arguments: &[String],
    runner: &dyn CommandRunner,
) -> ProcessOutput {
    runner
        .run_with(
            "docker",
            &arguments.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        })
}

fn parse_docker_stats_lines(output: &str) -> Vec<Map<String, Value>> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Map<String, Value>>(line).ok())
        .collect()
}

fn parse_percent(value: &str) -> Value {
    let cleaned = value.trim();
    if !cleaned.ends_with('%') {
        return Value::Null;
    }
    cleaned[..cleaned.len() - 1]
        .parse::<f64>()
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn parse_byte_quantity(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    let mut split = 0;
    for (offset, ch) in trimmed.char_indices() {
        if ch.is_ascii_alphabetic() {
            split = offset;
            break;
        }
    }
    if split == 0 {
        return None;
    }
    let (number, unit) = trimmed.split_at(split);
    let number: f64 = number.trim().parse().ok()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    let multiplier = DECIMAL_BYTE_UNITS
        .iter()
        .chain(BINARY_BYTE_UNITS.iter())
        .find(|(suffix, _)| *suffix == unit.trim())
        .map(|(_, multiplier)| *multiplier)?;
    Some((number * multiplier as f64) as i64)
}

fn parse_byte_pair(value: &str, left: &str, right: &str) -> Map<String, Value> {
    let mut output = Map::new();
    let (left_raw, right_raw) = value.split_once('/').unwrap_or(("", ""));
    output.insert(
        left.into(),
        parse_byte_quantity(left_raw)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    output.insert(
        right.into(),
        parse_byte_quantity(right_raw)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    output
}

fn normalize_docker_stat(row: &Map<String, Value>) -> Map<String, Value> {
    let mut normalized = Map::new();
    normalized.insert(
        "name".into(),
        row.get("Name").cloned().unwrap_or(Value::Null),
    );
    normalized.insert("id".into(), row.get("ID").cloned().unwrap_or(Value::Null));
    normalized.insert(
        "cpu_percent".into(),
        row.get("CPUPerc")
            .and_then(Value::as_str)
            .map_or(Value::Null, parse_percent),
    );
    normalized.insert(
        "memory_percent".into(),
        row.get("MemPerc")
            .and_then(Value::as_str)
            .map_or(Value::Null, parse_percent),
    );
    normalized.insert(
        "pids".into(),
        row.get("PIDs")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<i64>().ok())
            .map(Value::from)
            .unwrap_or(Value::Null),
    );

    if let Some(memory) = row.get("MemUsage").and_then(Value::as_str) {
        normalized.extend(parse_byte_pair(
            memory,
            "memory_usage_bytes",
            "memory_limit_bytes",
        ));
    } else {
        normalized.insert("memory_usage_bytes".into(), Value::Null);
        normalized.insert("memory_limit_bytes".into(), Value::Null);
    }
    if let Some(netio) = row.get("NetIO").and_then(Value::as_str) {
        normalized.extend(parse_byte_pair(
            netio,
            "network_rx_bytes",
            "network_tx_bytes",
        ));
    } else {
        normalized.insert("network_rx_bytes".into(), Value::Null);
        normalized.insert("network_tx_bytes".into(), Value::Null);
    }
    if let Some(block) = row.get("BlockIO").and_then(Value::as_str) {
        normalized.extend(parse_byte_pair(
            block,
            "block_read_bytes",
            "block_write_bytes",
        ));
    } else {
        normalized.insert("block_read_bytes".into(), Value::Null);
        normalized.insert("block_write_bytes".into(), Value::Null);
    }
    normalized
}

fn top_numeric_rows(
    rows: &[Map<String, Value>],
    key: &str,
    limit: usize,
) -> Vec<Map<String, Value>> {
    let mut ranked = rows.to_vec();
    ranked.sort_by(|left, right| {
        let left_value = numeric_value_for_ordering(left.get(key));
        let right_value = numeric_value_for_ordering(right.get(key));
        right_value
            .partial_cmp(&left_value)
            .unwrap_or(Ordering::Equal)
    });
    ranked.truncate(limit);
    ranked
}

fn numeric_value_for_ordering(value: Option<&Value>) -> f64 {
    match value {
        Some(value) => value
            .as_f64()
            .or_else(|| value.as_i64().map(|value| value as f64))
            .unwrap_or(-1.0),
        None => -1.0,
    }
}

fn top_map(rows: &[Map<String, Value>], keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .map(|key| {
            let rows = top_numeric_rows(rows, key, 5)
                .into_iter()
                .map(Value::Object)
                .collect();
            ((*key).to_string(), Value::Array(rows))
        })
        .collect()
}

fn parse_redis_info(stdout: &str) -> BTreeMap<String, i64> {
    let allow = BTreeSet::from([
        "used_memory",
        "used_memory_peak",
        "connected_clients",
        "blocked_clients",
        "total_commands_processed",
        "instantaneous_ops_per_sec",
        "keyspace_hits",
        "keyspace_misses",
    ]);
    let mut metrics = BTreeMap::new();
    let mut keyspace_keys = 0;

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if allow.contains(key) {
            if let Ok(value) = value.parse::<i64>() {
                metrics.insert(key.to_string(), value);
            }
        } else if key.starts_with("db") {
            for part in value.split(',') {
                if let Some(raw) = part.strip_prefix("keys=")
                    && let Ok(value) = raw.parse::<i64>()
                {
                    keyspace_keys += value;
                }
            }
        }
    }
    if keyspace_keys != 0 {
        metrics.insert("keyspace_keys".into(), keyspace_keys);
    }
    metrics
}

fn parse_redis_dbsize(stdout: &str) -> Option<i64> {
    stdout.lines().find_map(|line| line.trim().parse().ok())
}

fn scanner_redis_cli(repo_root: &Path, args: &[&str], runner: &dyn CommandRunner) -> ProcessOutput {
    let mut args = args.iter().map(|item| item.to_string()).collect::<Vec<_>>();
    let mut command = vec![
        "exec".to_string(),
        "-T".to_string(),
        "redis-openvas".to_string(),
        "redis-cli".to_string(),
        "-s".to_string(),
        REDIS_CONTAINER_SOCKET.to_string(),
    ];
    command.append(&mut args);
    let command = compose_command(repo_root, &command);
    runner
        .run_with(
            "docker",
            &command.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        })
}

fn scanner_redis_metrics(repo_root: &Path, runner: &dyn CommandRunner) -> Map<String, Value> {
    let mut metrics = Map::new();

    let dbsize = scanner_redis_cli(repo_root, &["DBSIZE"], runner);
    metrics.insert(
        "dbsize_status".into(),
        Value::from(if dbsize.success { "pass" } else { "fail" }),
    );
    metrics.insert(
        "dbsize".into(),
        if dbsize.success {
            parse_redis_dbsize(&dbsize.stdout)
                .map(Value::from)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    if !dbsize.success {
        metrics.insert(
            "dbsize_output_tail".into(),
            Value::Array(
                output_tail(&dbsize.stdout, 20)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    let info = scanner_redis_cli(repo_root, &["INFO"], runner);
    metrics.insert(
        "info_status".into(),
        Value::from(if info.success { "pass" } else { "fail" }),
    );
    if info.success {
        for (key, value) in parse_redis_info(&info.stdout) {
            metrics.insert(key, Value::from(value));
        }
    } else {
        metrics.insert(
            "info_output_tail".into(),
            Value::Array(
                output_tail(&info.stdout, 20)
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    metrics
}

fn parse_relation_size_rows(output: &str) -> Vec<Map<String, Value>> {
    output
        .lines()
        .filter_map(|line| {
            let (name, size) = line.trim().split_once('|')?;
            Some({
                let mut row = Map::new();
                row.insert("name".into(), Value::from(name.to_string()));
                row.insert(
                    "byte_count".into(),
                    size.trim()
                        .parse::<i64>()
                        .map(Value::from)
                        .unwrap_or(Value::Null),
                );
                row
            })
        })
        .collect()
}

fn parse_pipe_int_rows(output: &str) -> BTreeMap<String, i64> {
    output
        .lines()
        .filter_map(|line| {
            let (name, value) = line.trim().split_once('|')?;
            value
                .parse::<i64>()
                .ok()
                .map(|value| (name.to_string(), value))
        })
        .collect()
}

pub(crate) fn table_presence_rows(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    tables: &[&str],
) -> (ProcessOutput, BTreeMap<String, bool>) {
    let values = tables
        .iter()
        .map(|name| format!("({})", sql_literal(name)))
        .collect::<Vec<_>>()
        .join(",");
    let query = format!(
        "WITH wanted(name) AS (VALUES {values}) SELECT name || '|' || (to_regclass('public.' || quote_ident(name)) IS NOT NULL) FROM wanted ORDER BY name;"
    );
    let output = psql(repo_root, &query, runner);
    let presence = if output.success {
        output
            .stdout
            .lines()
            .filter_map(|line| {
                let (name, raw) = line.trim().split_once('|')?;
                Some((
                    name.to_string(),
                    matches!(raw.trim().to_lowercase().as_str(), "t" | "true" | "1"),
                ))
            })
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    (output, presence)
}

pub(crate) fn table_row_count_output(
    repo_root: &Path,
    table: &str,
    runner: &dyn CommandRunner,
) -> (ProcessOutput, Option<i64>) {
    let output = psql(
        repo_root,
        &format!("SELECT count(*) FROM {};", sql_identifier(table)),
        runner,
    );
    let count = output
        .success
        .then(|| psql_value(&output.stdout).parse::<i64>().ok())
        .flatten();
    (output, count)
}

fn table_row_count(repo_root: &Path, table: &str, runner: &dyn CommandRunner) -> Option<i64> {
    table_row_count_output(repo_root, table, runner).1
}

fn empty_path_tree_summary(path: &Path) -> Map<String, Value> {
    let mut summary = Map::new();
    summary.insert(
        "path".into(),
        Value::from(path.to_string_lossy().to_string()),
    );
    summary.insert("exists".into(), Value::from(path.exists()));
    summary.insert("kind".into(), Value::from("missing"));
    summary.insert("file_count".into(), Value::from(0_u64));
    summary.insert("directory_count".into(), Value::from(0_u64));
    summary.insert("byte_count".into(), Value::from(0_u64));
    summary.insert("latest_mtime".into(), Value::Null);
    summary
}

pub(crate) fn path_tree_summary_checked(
    path: &Path,
    recursive: bool,
) -> Result<Map<String, Value>, String> {
    let mut summary = empty_path_tree_summary(path);

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(summary),
        Err(error) => return Err(format!("could not inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!("{} is a symbolic link", path.display()));
    }

    if metadata.is_file() {
        summary.insert("kind".into(), Value::from("file"));
        summary.insert("file_count".into(), Value::from(1_u64));
        summary.insert("byte_count".into(), Value::from(metadata.len()));
        summary.insert(
            "latest_mtime".into(),
            metadata
                .modified()
                .ok()
                .and_then(iso_system_time)
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        return Ok(summary);
    }

    if !metadata.is_dir() {
        return Ok(summary);
    }

    summary.insert("kind".into(), Value::from("directory"));
    let mut latest = if recursive {
        None
    } else {
        metadata.modified().ok()
    };

    let mut directories = vec![path.to_path_buf()];
    while let Some(current) = directories.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|error| format!("could not read {}: {error}", current.display()))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("could not read directory entry: {error}"))?;
            let child = entry.path();
            let child_meta = fs::symlink_metadata(&child)
                .map_err(|error| format!("could not inspect {}: {error}", child.display()))?;
            if child_meta.file_type().is_symlink() {
                continue;
            }
            if child_meta.is_dir() {
                summary.insert(
                    "directory_count".into(),
                    Value::from(
                        summary
                            .get("directory_count")
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                            + 1,
                    ),
                );
                if recursive && child.starts_with(path) {
                    directories.push(child);
                }
                if !recursive && let Ok(child_mtime) = child_meta.modified() {
                    latest = latest.max(Some(child_mtime));
                }
                continue;
            }
            if child_meta.is_file() {
                summary.insert(
                    "file_count".into(),
                    Value::from(
                        summary
                            .get("file_count")
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                            + 1,
                    ),
                );
                summary.insert(
                    "byte_count".into(),
                    Value::from(
                        summary
                            .get("byte_count")
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                            + child_meta.len(),
                    ),
                );
                if let Ok(child_mtime) = child_meta.modified() {
                    latest = latest.max(Some(child_mtime));
                }
            }
        }
        if !recursive {
            break;
        }
    }
    if let Some(value) = latest.and_then(iso_system_time) {
        summary.insert("latest_mtime".into(), Value::String(value));
    }
    Ok(summary)
}

fn path_tree_summary(path: &Path, recursive: bool) -> Map<String, Value> {
    path_tree_summary_checked(path, recursive).unwrap_or_else(|_| empty_path_tree_summary(path))
}

fn largest_files(path: &Path, limit: usize) -> Vec<Map<String, Value>> {
    if !path.exists() || is_symlink(path) {
        return Vec::new();
    }
    if path.is_file() {
        let mut rows = Vec::new();
        if let Ok(meta) = fs::metadata(path) {
            rows.push(file_row(path.to_string_lossy().as_ref(), meta.len()));
        }
        return rows;
    }

    let mut rows = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(root) = stack.pop() {
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            if is_symlink(&candidate) {
                continue;
            }
            if candidate.is_dir() {
                stack.push(candidate);
                continue;
            }
            if candidate.is_file()
                && let Ok(meta) = fs::metadata(&candidate)
            {
                let display = candidate
                    .strip_prefix(path)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                rows.push(file_row(&display, meta.len()));
            }
        }
    }

    rows.sort_by(|left, right| {
        right
            .get("byte_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(&left.get("byte_count").and_then(Value::as_u64).unwrap_or(0))
            .then_with(|| {
                left.get("path")
                    .and_then(Value::as_str)
                    .cmp(&right.get("path").and_then(Value::as_str))
            })
    });
    rows.truncate(limit);
    rows
}

fn file_row(path: &str, size: u64) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert("path".into(), Value::from(path.to_string()));
    row.insert("byte_count".into(), Value::from(size));
    row
}

fn process_step_finding(
    status: &str,
    check: &str,
    message: String,
    output: &ProcessOutput,
    command: &[String],
) -> Finding {
    Finding::new(status, check, message).with_details(json!({
        "exit_code": output.exit_code.unwrap_or(1),
        "output_tail": output_tail(&output.stdout, 100),
        "command": command.join(" "),
    }))
}

fn stats_exit_code(output: &ProcessOutput) -> i32 {
    output.exit_code.unwrap_or(1)
}

fn retained_json_artifact_paths(
    artifact_dir: &Path,
    stem: &str,
    latest_name: &str,
) -> (PathBuf, PathBuf) {
    let _ = fs::create_dir_all(artifact_dir);
    let timestamp = artifact_timestamp();
    let mut timestamped = artifact_dir.join(format!("{stem}-{timestamp}.json"));
    let mut counter = 1;
    while timestamped.exists() {
        timestamped = artifact_dir.join(format!("{stem}-{timestamp}-{counter}.json"));
        counter += 1;
    }
    (artifact_dir.join(latest_name), timestamped)
}

fn artifact_timestamp() -> String {
    use time::OffsetDateTime;
    let format = time::format_description::parse_borrowed::<2>(
        "[year][month][day]T[hour][minute][second][subsecond digits:6]Z",
    )
    .expect("artifact timestamp format");
    OffsetDateTime::now_utc()
        .format(&format)
        .unwrap_or_else(|_| String::from("19700101T000000000000Z"))
}

fn write_retained_json_artifact(
    latest_path: &Path,
    timestamped_path: &Path,
    payload: &ResultEnvelope,
    stem: &str,
    keep: usize,
) -> Result<(), String> {
    let parent = latest_path
        .parent()
        .ok_or_else(|| "artifact path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    if is_symlink(parent) {
        return Err("artifact directory is a symlink".into());
    }
    let text = serde_json::to_string_pretty(payload)
        .map(|text| format!("{text}\n"))
        .map_err(|error| error.to_string())?;
    write_new_file(timestamped_path, text.as_bytes())?;
    write_atomic_latest(latest_path, text.as_bytes())?;

    let mut candidates = fs::read_dir(parent)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(&format!("{stem}-")) && name.ends_with(".json")
                })
        })
        .collect::<Vec<_>>();
    candidates.sort();
    let keep = keep.max(1);
    let remove = candidates.len().saturating_sub(keep);
    for path in candidates.into_iter().take(remove) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(contents)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

pub(crate) fn write_secure_json_artifact(
    path: &Path,
    payload: &ResultEnvelope,
) -> Result<(), String> {
    let text = serde_json::to_string_pretty(payload)
        .map(|text| format!("{text}\n"))
        .map_err(|error| error.to_string())?;
    write_secure_atomic_latest(path, text.as_bytes())
}

fn validate_secure_artifact_target(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "latest artifact has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.uid() != unsafe { libc::getuid() } {
        return Err("artifact directory is not a real, current-user-owned directory".into());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::getuid() }
                && metadata.nlink() == 1 => {}
        Ok(_) => return Err("artifact target is not a private regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(())
}

fn write_secure_atomic_latest(path: &Path, contents: &[u8]) -> Result<(), String> {
    validate_secure_artifact_target(path)?;
    write_atomic_latest(path, contents)
}

fn write_atomic_latest(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "latest artifact has no parent".to_string())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "latest artifact name is invalid".to_string())?;
    for counter in 0..100_u32 {
        let temporary = parent.join(format!(".{name}.tmp-{}-{counter}", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        };
        if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.to_string());
        }
        return Ok(());
    }
    Err("could not allocate a private temporary artifact".into())
}

pub(crate) fn service_running(repo_root: &Path, service: &str, runner: &dyn CommandRunner) -> bool {
    let ps = compose_command(repo_root, &["ps".into(), "-q".into(), service.into()]);
    let ps_output = runner
        .run_with(
            "docker",
            &ps.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .filter(|output| output.success)
        .and_then(|output| {
            output
                .stdout
                .lines()
                .next()
                .map(str::trim)
                .map(str::to_string)
        });
    let Some(container_id) = ps_output else {
        return false;
    };
    if container_id.is_empty() {
        return false;
    }

    runner
        .run_with(
            "docker",
            &["inspect", "-f", "{{.State.Running}}", &container_id],
            Some(repo_root),
            Some(&runtime_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .is_some_and(|output| output.success && output.stdout.trim() == "true")
}

pub(crate) fn psql(repo_root: &Path, query: &str, runner: &dyn CommandRunner) -> ProcessOutput {
    let compose = compose_command(
        repo_root,
        &[
            "exec".into(),
            "-T".into(),
            "postgres".into(),
            "sh".into(),
            "-ceu".into(),
            PSQL_SCRIPT.into(),
            "yafvsctl-psql".into(),
            query.into(),
        ],
    );
    runner
        .run_with(
            "docker",
            &compose.iter().map(String::as_str).collect::<Vec<_>>(),
            Some(repo_root),
            Some(&diagnostic_environment(repo_root)),
            Some(PROCESS_TIMEOUT),
        )
        .unwrap_or(ProcessOutput {
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        })
}

pub(crate) fn psql_value(stdout: &str) -> &str {
    const IGNORED: [&str; 4] = ["WARNING:", "DETAIL:", "HINT:", "NOTICE:"];
    stdout
        .lines()
        .rev()
        .find(|line| {
            let line = line.trim();
            !line.is_empty() && !IGNORED.iter().any(|prefix| line.starts_with(prefix))
        })
        .unwrap_or_default()
        .trim()
}

fn diagnostic_environment(repo_root: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = runtime_environment(repo_root);
    environment.remove(&OsString::from("POSTGRES_PASSWORD"));
    environment
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn sql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn combine_tables() -> Vec<&'static str> {
    let mut tables = Vec::with_capacity(24);
    tables.extend_from_slice(&DATABASE_CORE_TABLES);
    tables.extend_from_slice(&DATABASE_SCOPE_TABLES);
    tables
}

fn performance_artifact_dir(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("artifacts/performance")
}

fn scanner_redis_socket_path(repo_root: &Path) -> PathBuf {
    runtime_dir(repo_root).join("run/redis-openvas/redis.sock")
}

fn gsad_static_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("build/prefix/share/gvm/gsad/web")
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_percent_and_quantities() {
        assert_eq!(parse_byte_quantity("12.5MB"), Some(12_500_000));
        assert_eq!(parse_byte_quantity("9KiB"), Some(9216));
        assert_eq!(parse_byte_quantity("bad"), None);
        assert_eq!(parse_percent("12.5%"), Value::from(12.5));
        assert_eq!(parse_percent("12"), Value::Null);
        let pair = parse_byte_pair("1.5GB/3.25KiB", "left", "right");
        assert_eq!(pair.get("left"), Some(&Value::from(1_500_000_000_i64)));
        assert_eq!(pair.get("right"), Some(&Value::from(3_328_i64)));
    }

    #[test]
    fn malformed_docker_rows_are_ignored_and_normalized() {
        let rows = parse_docker_stats_lines("bad-json\n{\"Name\":\"svc\",\"CPUPerc\":\"10%\"}\n");
        assert_eq!(rows.len(), 1);
        let normalized = normalize_docker_stat(&rows[0]);
        assert_eq!(normalized.get("name"), Some(&Value::from("svc")));
        assert_eq!(normalized.get("pids"), Some(&Value::Null));
    }

    #[test]
    fn top_numeric_rows_are_deterministic_for_ties() {
        let rows = vec![
            vec![
                ("name", Value::from("a")),
                ("cpu_percent", Value::from(1.0)),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            vec![
                ("name", Value::from("b")),
                ("cpu_percent", Value::from(1.0)),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            vec![
                ("name", Value::from("c")),
                ("cpu_percent", Value::from(2.0)),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        ];
        let top = top_numeric_rows(&rows, "cpu_percent", 2);
        assert_eq!(top[0].get("name"), Some(&Value::from("c")));
    }

    #[test]
    fn redis_and_sql_row_parsers() {
        let info = parse_redis_info(
            "used_memory:1024\nconnected_clients:2\nblocked_clients:0\ndb0:keys=7,expires=2\ndb2:keys=not-a-number\n",
        );
        assert_eq!(info.get("used_memory"), Some(&1024));
        assert_eq!(info.get("keyspace_keys"), Some(&7));
        assert_eq!(parse_redis_dbsize("bad\n12\n"), Some(12));

        let rel = parse_relation_size_rows("reports|12\nbad\nscope|notint\n");
        assert_eq!(rel.len(), 2);
        assert_eq!(rel[1].get("byte_count"), Some(&Value::Null));

        let piped = parse_pipe_int_rows("reports|3\nscope|x\n");
        assert_eq!(piped.get("reports"), Some(&3));
        assert!(!piped.contains_key("scope"));
    }

    #[test]
    fn path_summary_does_not_follow_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-snapshot-path-{}-{}",
            std::process::id(),
            0
        ));
        let outside = root.join("outside");
        let victim = root.join("victim");
        let target = outside.join("payload.txt");
        let link = victim.join("link");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(target, &link).unwrap();
        fs::write(victim.join("keep.txt"), b"data").unwrap();

        let summary = path_tree_summary(&victim, true);
        assert_eq!(summary.get("file_count").and_then(Value::as_u64), Some(1));
        assert_eq!(
            summary.get("directory_count").and_then(Value::as_u64),
            Some(0)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_artifacts_keep_only_recent_entries() {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-snapshot-retain-{}-{}",
            std::process::id(),
            0
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("performance-snapshot-20260101T000000000000Z.json"),
            "{}\n",
        )
        .unwrap();
        fs::write(
            root.join("performance-snapshot-20260101T000000000001Z.json"),
            "{}\n",
        )
        .unwrap();
        fs::write(
            root.join("performance-snapshot-20260101T000000000002Z.json"),
            "{}\n",
        )
        .unwrap();

        let (latest, timed) =
            retained_json_artifact_paths(&root, PERFORMANCE_STEM, PERFORMANCE_ARTIFACT);
        assert_eq!(latest, root.join(PERFORMANCE_ARTIFACT));
        let envelope = ResultEnvelope {
            status: "pass".into(),
            summary: "x".into(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            metadata: super::metadata(&root, "runtime-performance-snapshot", &SystemCommandRunner),
            details: None,
        };
        write_retained_json_artifact(&latest, &timed, &envelope, PERFORMANCE_STEM, 2).unwrap();
        let names = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with("performance-snapshot") && name.ends_with(".json"))
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 3);
        assert!(names.iter().any(|name| name == PERFORMANCE_ARTIFACT));
        assert_eq!(
            names
                .iter()
                .filter(|name| name.starts_with("performance-snapshot-"))
                .count(),
            2
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn latest_artifact_replaces_symlink_without_touching_target() {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-snapshot-symlink-{}-{}",
            std::process::id(),
            0
        ));
        fs::create_dir_all(&root).unwrap();
        let victim = root.join("victim.json");
        let latest = root.join(PERFORMANCE_ARTIFACT);
        let timestamped = root.join("performance-snapshot-20260101T000000000000Z.json");
        fs::write(&victim, "victim\n").unwrap();
        std::os::unix::fs::symlink(&victim, &latest).unwrap();
        let envelope = ResultEnvelope {
            status: "pass".into(),
            summary: "x".into(),
            findings: Vec::new(),
            artifacts: Vec::new(),
            metadata: super::metadata(&root, "runtime-performance-snapshot", &SystemCommandRunner),
            details: None,
        };

        write_retained_json_artifact(&latest, &timestamped, &envelope, PERFORMANCE_STEM, 30)
            .unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim\n");
        assert!(
            !fs::symlink_metadata(&latest)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn docker_stats_and_inspect_use_direct_docker_arguments() {
        use std::cell::RefCell;

        struct Runner {
            calls: RefCell<Vec<Vec<String>>>,
        }
        impl CommandRunner for Runner {
            fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
                None
            }

            fn run_with(
                &self,
                program: &str,
                args: &[&str],
                _cwd: Option<&Path>,
                _env: Option<&std::collections::BTreeMap<OsString, OsString>>,
                _timeout: Option<std::time::Duration>,
            ) -> Option<ProcessOutput> {
                assert_eq!(program, "docker");
                self.calls
                    .borrow_mut()
                    .push(args.iter().map(|value| (*value).to_string()).collect());
                let stdout = if args.contains(&"-q") {
                    "container-id\n"
                } else if args.first() == Some(&"inspect") {
                    "true\n"
                } else {
                    ""
                };
                Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: stdout.into(),
                    stderr: String::new(),
                })
            }
        }

        let runner = Runner {
            calls: RefCell::new(Vec::new()),
        };
        let repo = Path::new("/tmp/repo");
        let stats = run_docker_command(repo, &["stats".into(), "--no-stream".into()], &runner);
        assert!(stats.success);
        assert!(service_running(repo, "postgres", &runner));
        let calls = runner.calls.borrow();
        assert_eq!(calls[0], ["stats", "--no-stream"]);
        assert_eq!(
            calls[2],
            ["inspect", "-f", "{{.State.Running}}", "container-id"]
        );
    }

    #[test]
    fn absent_services_generates_warning_findings() {
        struct Runner;
        impl CommandRunner for Runner {
            fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
                if program == "git" {
                    None
                } else {
                    Some(ProcessOutput {
                        success: true,
                        exit_code: Some(0),
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }

            fn run_with(
                &self,
                program: &str,
                _args: &[&str],
                _cwd: Option<&Path>,
                _env: Option<&std::collections::BTreeMap<OsString, OsString>>,
                _timeout: Option<std::time::Duration>,
            ) -> Option<ProcessOutput> {
                if program != "docker" {
                    return None;
                }
                Some(ProcessOutput {
                    success: true,
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }

        let root = std::env::temp_dir().join(format!(
            "yafvsctl-snapshot-absent-root-{}-{}",
            std::process::id(),
            0
        ));
        let repo = root.join("repo");
        fs::create_dir_all(&repo).unwrap();
        let result = super::command_runtime_performance_snapshot_with(&repo, &Runner);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "performance.database" && finding.status == "warn")
        );
        assert!(result.findings.iter().any(
            |finding| finding.check == "performance.scanner-redis" && finding.status == "warn"
        ));
        let details = result.details.as_ref().and_then(Value::as_object).unwrap();
        assert!(!details.contains_key("scanner_redis"));
        assert!(!details.contains_key("report_workflow"));
        assert_eq!(
            result
                .findings
                .iter()
                .find(|finding| finding.check == "performance.scanner-redis")
                .and_then(|finding| finding.path.as_deref()),
            Some(
                root.join("YAFVS-runtime/run/redis-openvas/redis.sock")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        fs::remove_dir_all(root).unwrap();
    }
}
