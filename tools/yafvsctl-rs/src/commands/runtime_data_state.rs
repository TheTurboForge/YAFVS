// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only runtime data-state diagnostic with private local evidence output.

use super::artifact::write_secure_json_artifact;
use super::common::{metadata, output_tail, runtime_dir};
use super::runtime_lock::{inspect_runtime_lock, runtime_lock_paths};
use super::runtime_performance_snapshot::{
    path_tree_summary_checked, psql, psql_value, service_running, table_presence_rows,
    table_row_count_output,
};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::Path;

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
const DATABASE_REMOVED_TABLES: [&str; 12] = [
    "roles",
    "groups",
    "permissions",
    "oci_image_targets",
    "oci_image_targets_trash",
    "notes",
    "tickets",
    "agents",
    "agent_groups",
    "agent_installers",
    "audits",
    "audit_reports",
];

const DATA_STATE_ARTIFACT_PATHS: [(&str, &str, &str, bool); 15] = [
    ("reports", "db_owned_export", "artifacts/reports", true),
    (
        "scope-reports",
        "db_owned_export",
        "artifacts/scope-reports",
        true,
    ),
    ("metrics", "db_owned_export", "artifacts/metrics", true),
    (
        "browser-smoke",
        "diagnostic_artifact",
        "artifacts/browser-smoke",
        true,
    ),
    (
        "browser-regression",
        "diagnostic_artifact",
        "artifacts/browser-regression",
        true,
    ),
    (
        "credential-smoke",
        "diagnostic_artifact",
        "artifacts/credential-smoke",
        true,
    ),
    (
        "full-test-scan",
        "diagnostic_artifact",
        "artifacts/full-test-scan",
        true,
    ),
    (
        "log-review",
        "diagnostic_artifact",
        "artifacts/log-review",
        true,
    ),
    (
        "quality-gate",
        "diagnostic_artifact",
        "artifacts/quality-gate",
        true,
    ),
    (
        "performance",
        "diagnostic_artifact",
        "artifacts/performance",
        true,
    ),
    (
        "native-api",
        "diagnostic_artifact",
        "artifacts/native-api",
        true,
    ),
    ("runtime-feeds", "feed_content", "feeds", false),
    ("feed-cache", "feed_content", "feed-cache", false),
    ("runtime-logs", "diagnostic_artifact", "logs", false),
    ("runtime-state", "temporary_runtime_state", "state", false),
];

const DATA_STATE_DB_OWNED_EXPORT_SOURCES: [(&str, &[&str]); 3] = [
    ("reports", &["reports", "results", "report_hosts"]),
    ("scope-reports", &["scope_reports", "scope_report_sources"]),
    (
        "metrics",
        &[
            "reports",
            "results",
            "report_hosts",
            "scope_report_system_metrics",
            "scope_report_vulnerability_metrics",
        ],
    ),
];

pub fn command_runtime_data_state(repo_root: &Path) -> ResultEnvelope {
    command_runtime_data_state_with(repo_root, &SystemCommandRunner)
}

fn command_runtime_data_state_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let artifact = runtime_dir(repo_root).join("artifacts/data-state/data-state.json");
    let mut findings = Vec::new();
    let mut details = Map::new();
    details.insert(
        "database".into(),
        json!({ "classification": "system_of_record" }),
    );
    details.insert("paths".into(), Value::Object(Map::new()));

    let lock_details = runtime_manager_lock_details(repo_root, &mut findings);
    details.insert("runtime_manager_lock".into(), lock_details);

    if !service_running(repo_root, "postgres", runner) {
        findings.push(Finding::new(
            "warn",
            "data-state.postgres",
            "Postgres is not running; database state is unavailable.".into(),
        ));
    } else {
        inspect_database(repo_root, runner, &mut details, &mut findings);
    }

    inspect_paths(repo_root, &mut details, &mut findings);
    let paths = details
        .get("paths")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let outside_db = summarize_data_outside_db(&paths);
    findings.push(
        Finding::new(
            "pass",
            "data-state.outside-db",
            "Non-database runtime state summary captured.".into(),
        )
        .with_details(json!({ "summary": outside_db })),
    );
    details.insert("data_outside_db".into(), outside_db);

    let audit = product_data_audit(&details);
    let audit_status = audit
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("warn");
    findings.push(
        Finding::new(
            audit_status,
            "data-state.product-data-audit",
            if audit_status == "pass" {
                "Product data exports have database sources of record.".into()
            } else {
                "Product data exports are missing expected database sources of record.".into()
            },
        )
        .with_details(json!({ "audit": audit })),
    );
    details.insert("product_data_audit".into(), audit);

    let mut result = make_result(
        metadata(repo_root, "runtime-data-state", runner),
        "Runtime data-state diagnostic completed.".into(),
        findings,
    )
    .with_artifacts(vec![artifact.display().to_string()])
    .with_details(Value::Object(details));
    if let Err(error) = write_secure_json_artifact(&artifact, &result) {
        result.findings.push(
            Finding::new(
                "fail",
                "data-state.artifact",
                format!("Runtime data-state artifact write failed: {error}."),
            )
            .with_path(&artifact.display().to_string()),
        );
        result.status = "fail".into();
    }
    result
}

fn runtime_manager_lock_details(repo_root: &Path, findings: &mut Vec<Finding>) -> Value {
    match inspect_runtime_lock(repo_root, "runtime-manager") {
        Ok(status) => {
            let details = json!({
                "name": status.name,
                "active": status.active,
                "path": status.path,
                "metadata_path": status.metadata_path,
                "metadata": status.metadata,
            });
            if status.active {
                findings.push(
                    Finding::new(
                        "warn",
                        "data-state.runtime-manager-lock",
                        "runtime-manager-init or another manager operation is currently active; data-state may be transient.".into(),
                    )
                    .with_details(json!({ "lock": details })),
                );
            }
            details
        }
        Err(error) => {
            let (path, metadata_path) = runtime_lock_paths(repo_root, "runtime-manager");
            findings.push(Finding::new(
                "fail",
                "data-state.runtime-manager-lock",
                format!("Runtime manager lock inspection failed: {error:?}."),
            ));
            json!({
                "name": "runtime-manager",
                "active": false,
                "path": path,
                "metadata_path": metadata_path,
                "metadata": {},
            })
        }
    }
}

fn inspect_database(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    details: &mut Map<String, Value>,
    findings: &mut Vec<Finding>,
) {
    let version = psql(
        repo_root,
        "SELECT COALESCE((SELECT value FROM meta WHERE name = 'database_version'), 'missing');",
        runner,
    );
    let value = if version.success {
        psql_value(&version.stdout)
    } else {
        ""
    };
    if let Some(database) = details.get_mut("database").and_then(Value::as_object_mut) {
        database.insert("database_version".into(), Value::from(value));
    }
    findings.push(
        Finding::new(
            if version.success && !value.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "data-state.database-version",
            format!(
                "Manager database version is {}.",
                if value.is_empty() { "unknown" } else { value }
            ),
        )
        .with_details(json!({ "output_tail": output_tail(&version.stdout, 40) })),
    );

    for (label, tables, expected_present) in [
        ("core", DATABASE_CORE_TABLES.as_slice(), true),
        ("scope", DATABASE_SCOPE_TABLES.as_slice(), true),
        ("removed", DATABASE_REMOVED_TABLES.as_slice(), false),
    ] {
        inspect_table_group(
            repo_root,
            runner,
            details,
            findings,
            label,
            tables,
            expected_present,
        );
    }
}

fn inspect_table_group(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    details: &mut Map<String, Value>,
    findings: &mut Vec<Finding>,
    label: &str,
    tables: &[&str],
    expected_present: bool,
) {
    let (presence_output, presence) = table_presence_rows(repo_root, runner, tables);
    let mut rows = Map::new();
    for table in tables {
        let exists = presence.get(*table).copied().unwrap_or(false);
        let mut entry = Map::new();
        entry.insert("exists".into(), Value::from(exists));
        if exists {
            let (_, count) = table_row_count_output(repo_root, table, runner);
            entry.insert(
                "row_count".into(),
                count.map(Value::from).unwrap_or(Value::Null),
            );
        }
        rows.insert((*table).into(), Value::Object(entry));
    }
    if let Some(database) = details.get_mut("database").and_then(Value::as_object_mut) {
        database.insert(format!("{label}_tables"), Value::Object(rows));
    }
    if !presence_output.success {
        findings.push(
            Finding::new(
                "fail",
                &format!("data-state.{label}-tables"),
                format!("Could not inspect {label} table presence."),
            )
            .with_details(json!({ "output_tail": output_tail(&presence_output.stdout, 80) })),
        );
        return;
    }
    let mismatches = tables
        .iter()
        .filter(|table| presence.get(**table).copied().unwrap_or(false) != expected_present)
        .map(|table| (*table).to_string())
        .collect::<Vec<_>>();
    findings.push(
        Finding::new(
            if mismatches.is_empty() {
                "pass"
            } else {
                "fail"
            },
            &format!("data-state.{label}-tables"),
            if mismatches.is_empty() {
                format!("{label} table presence matches expectation.")
            } else {
                format!(
                    "{label} table presence mismatch: {}.",
                    mismatches.join(", ")
                )
            },
        )
        .with_details(json!({ "mismatches": mismatches, "expected_present": expected_present })),
    );
}

fn inspect_paths(repo_root: &Path, details: &mut Map<String, Value>, findings: &mut Vec<Finding>) {
    let runtime = runtime_dir(repo_root);
    let paths = details
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .expect("paths is initialized");
    for (name, classification, relative, recursive) in DATA_STATE_ARTIFACT_PATHS {
        let path = runtime.join(relative);
        match path_tree_summary_checked(&path, recursive) {
            Ok(mut summary) => {
                summary.insert("classification".into(), Value::from(classification));
                findings.push(
                    Finding::new(
                        if summary.get("exists").and_then(Value::as_bool) == Some(true) {
                            "pass"
                        } else {
                            "warn"
                        },
                        "data-state.path",
                        format!("{name} classified as {classification}."),
                    )
                    .with_path(&path.display().to_string())
                    .with_details(json!({ "summary": summary })),
                );
                paths.insert(name.into(), Value::Object(summary));
            }
            Err(error) => {
                let summary = json!({
                    "path": path,
                    "exists": false,
                    "kind": "missing",
                    "file_count": 0,
                    "directory_count": 0,
                    "byte_count": 0,
                    "latest_mtime": Value::Null,
                    "classification": classification,
                });
                findings.push(
                    Finding::new(
                        "fail",
                        "data-state.path",
                        format!("{name} inspection failed: {error}."),
                    )
                    .with_path(&path.display().to_string())
                    .with_details(json!({ "summary": summary })),
                );
                paths.insert(name.into(), summary);
            }
        }
    }
}

fn summarize_data_outside_db(paths: &Map<String, Value>) -> Value {
    let mut classes: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut total_byte_count = 0_u64;
    let mut total_file_count = 0_u64;
    let ordered_names = DATA_STATE_ARTIFACT_PATHS
        .iter()
        .map(|(name, _, _, _)| *name)
        .chain(paths.keys().map(String::as_str).filter(|name| {
            !DATA_STATE_ARTIFACT_PATHS
                .iter()
                .any(|(registered, _, _, _)| registered == name)
        }));
    for name in ordered_names {
        let Some(summary) = paths.get(name) else {
            continue;
        };
        let Some(summary) = summary.as_object() else {
            continue;
        };
        let classification = summary
            .get("classification")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let bucket = classes.entry(classification.into()).or_insert_with(|| {
            let mut bucket = Map::new();
            bucket.insert("path_count".into(), Value::from(0_u64));
            bucket.insert("existing_path_count".into(), Value::from(0_u64));
            bucket.insert("file_count".into(), Value::from(0_u64));
            bucket.insert("byte_count".into(), Value::from(0_u64));
            bucket.insert("paths".into(), Value::Array(Vec::new()));
            bucket
        });
        increment(bucket, "path_count", 1);
        if summary.get("exists").and_then(Value::as_bool) == Some(true) {
            increment(bucket, "existing_path_count", 1);
        }
        let files = summary
            .get("file_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let bytes = summary
            .get("byte_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        increment(bucket, "file_count", files);
        increment(bucket, "byte_count", bytes);
        total_file_count += files;
        total_byte_count += bytes;
        bucket
            .get_mut("paths")
            .and_then(Value::as_array_mut)
            .expect("paths initialized")
            .push(Value::from(name));
    }
    json!({
        "by_classification": classes,
        "total_byte_count": total_byte_count,
        "total_file_count": total_file_count,
    })
}

fn increment(map: &mut Map<String, Value>, key: &str, value: u64) {
    let previous = map.get(key).and_then(Value::as_u64).unwrap_or(0);
    map.insert(key.into(), Value::from(previous + value));
}

fn product_data_audit(details: &Map<String, Value>) -> Value {
    let database = details.get("database").and_then(Value::as_object);
    let paths = details.get("paths").and_then(Value::as_object);
    let mut exports = Map::new();
    let mut unowned = Vec::new();
    for (name, required_tables) in DATA_STATE_DB_OWNED_EXPORT_SOURCES {
        let Some(summary) = paths
            .and_then(|paths| paths.get(name))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let exists = summary.get("exists").and_then(Value::as_bool) == Some(true);
        let missing_tables = required_tables
            .iter()
            .filter(|table| !database_table_exists(database, table))
            .map(|table| Value::from(*table))
            .collect::<Vec<_>>();
        let export = json!({
            "exists": exists,
            "path": summary.get("path").cloned().unwrap_or(Value::Null),
            "source_of_record": "gvmd/postgresql",
            "required_tables": required_tables,
            "missing_tables": missing_tables,
        });
        if exists && !missing_tables.is_empty() {
            unowned.push(json!({ "path": name, "missing_tables": missing_tables }));
        }
        exports.insert(name.into(), export);
    }
    json!({
        "db_owned_exports": exports,
        "unowned_product_data": unowned,
        "status": if unowned.is_empty() { "pass" } else { "warn" },
    })
}

fn database_table_exists(database: Option<&Map<String, Value>>, table: &str) -> bool {
    ["core_tables", "scope_tables"].iter().any(|group| {
        database
            .and_then(|database| database.get(*group))
            .and_then(Value::as_object)
            .and_then(|tables| tables.get(table))
            .and_then(Value::as_object)
            .and_then(|row| row.get("exists"))
            .and_then(Value::as_bool)
            == Some(true)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct AbsentRunner;
    impl CommandRunner for AbsentRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            None
        }
    }

    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvs-data-state-{name}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    #[test]
    fn table_registries_match_the_data_state_contract() {
        assert_eq!(
            DATABASE_CORE_TABLES,
            [
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
                "alerts"
            ]
        );
        assert_eq!(
            DATABASE_SCOPE_TABLES,
            [
                "scopes",
                "scope_targets",
                "scope_hosts",
                "scope_reports",
                "scope_report_sources",
                "scope_report_system_metrics",
                "scope_report_vulnerability_metrics"
            ]
        );
        assert_eq!(
            DATABASE_REMOVED_TABLES,
            [
                "roles",
                "groups",
                "permissions",
                "oci_image_targets",
                "oci_image_targets_trash",
                "notes",
                "tickets",
                "agents",
                "agent_groups",
                "agent_installers",
                "audits",
                "audit_reports"
            ]
        );
    }

    #[test]
    fn absent_runtime_has_stable_warning_shape_and_order() {
        let (root, repo) = fixture("absent");
        let result = command_runtime_data_state_with(&repo, &AbsentRunner);
        assert_eq!(result.status, "warn");
        assert_eq!(result.findings[0].check, "data-state.postgres");
        assert_eq!(result.findings[0].status, "warn");
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.check != "data-state.runtime-manager-lock")
        );
        assert_eq!(
            result.findings.last().unwrap().check,
            "data-state.product-data-audit"
        );
        let details = result.details.unwrap();
        assert_eq!(details["database"]["classification"], "system_of_record");
        assert_eq!(details["runtime_manager_lock"]["name"], "runtime-manager");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn outside_db_aggregation_groups_paths() {
        let paths = json!({
            "reports": {"classification":"db_owned_export","exists":true,"file_count":2,"byte_count":7},
            "logs": {"classification":"diagnostic_artifact","exists":false,"file_count":1,"byte_count":3},
        });
        let summary = summarize_data_outside_db(paths.as_object().unwrap());
        assert_eq!(
            summary["by_classification"]["db_owned_export"]["existing_path_count"],
            1
        );
        assert_eq!(
            summary["by_classification"]["diagnostic_artifact"]["file_count"],
            1
        );
        assert_eq!(summary["total_byte_count"], 10);
        assert_eq!(
            summary["by_classification"]["db_owned_export"]["paths"],
            json!(["reports"])
        );
    }

    #[test]
    fn product_audit_passes_and_warns_only_for_existing_exports() {
        let mut details = Map::new();
        details.insert(
            "database".into(),
            json!({"core_tables": {
                "reports":{"exists":true}, "results":{"exists":true}, "report_hosts":{"exists":true}
            }}),
        );
        details.insert(
            "paths".into(),
            json!({
                "reports":{"classification":"db_owned_export","exists":true,"path":"reports"},
                "scope-reports":{"classification":"db_owned_export","exists":false,"path":"scope"}
            }),
        );
        let initial_audit = product_data_audit(&details);
        assert_eq!(initial_audit["status"], "pass");
        assert_eq!(
            initial_audit["db_owned_exports"]["scope-reports"]["exists"],
            false
        );
        assert_eq!(
            initial_audit["db_owned_exports"]["scope-reports"]["missing_tables"],
            json!(["scope_reports", "scope_report_sources"])
        );
        details.insert(
            "database".into(),
            json!({"core_tables": {"reports":{"exists":true}}}),
        );
        let audit = product_data_audit(&details);
        assert_eq!(audit["status"], "warn");
        assert_eq!(
            audit["unowned_product_data"][0]["missing_tables"],
            json!(["results", "report_hosts"])
        );
    }

    #[test]
    fn symlink_path_is_rejected_without_traversal() {
        let (root, repo) = fixture("symlink-path");
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("secret"), b"secret").unwrap();
        let link = repo.join("link");
        symlink(&target, &link).unwrap();
        assert!(path_tree_summary_checked(&link, true).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preplaced_artifact_symlink_is_refused() {
        let (root, repo) = fixture("artifact-link");
        let artifact = runtime_dir(&repo).join("artifacts/data-state/data-state.json");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let target = root.join("target");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &artifact).unwrap();
        let result = command_runtime_data_state_with(&repo, &AbsentRunner);
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings.last().unwrap().check, "data-state.artifact");
        assert_eq!(fs::read(target).unwrap(), b"target");
        fs::remove_dir_all(root).unwrap();
    }
}
