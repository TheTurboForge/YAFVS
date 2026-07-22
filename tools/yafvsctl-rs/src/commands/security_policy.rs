// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const SECURITY_POLICY_DOC: &str = "docs/SECURITY_POLICY.md";
const SECURITY_SENSITIVE_PATHS_FILE: &str = "policy/security-sensitive-paths.toml";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PolicyArea {
    id: String,
    title: String,
    risk: String,
    paths: Vec<String>,
    required_checks: Vec<String>,
}

pub fn command_security_policy_check(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_security_policy_check_with(repo_root, status_only, &SystemCommandRunner)
}

fn command_security_policy_check_with(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let doc_path = repo_root.join(SECURITY_POLICY_DOC);
    let policy_path = repo_root.join(SECURITY_SENSITIVE_PATHS_FILE);
    let artifacts = vec![
        SECURITY_POLICY_DOC.to_string(),
        SECURITY_SENSITIVE_PATHS_FILE.to_string(),
    ];
    let mut findings = vec![
        Finding::new(
            if doc_path.is_file() { "pass" } else { "fail" },
            "security-policy.doc",
            if doc_path.is_file() {
                "Security policy documentation exists.".to_string()
            } else {
                "Security policy documentation is missing.".to_string()
            },
        )
        .with_path(SECURITY_POLICY_DOC),
        Finding::new(
            if policy_path.is_file() {
                "pass"
            } else {
                "fail"
            },
            "security-policy.paths-file",
            if policy_path.is_file() {
                "Security-sensitive path policy exists.".to_string()
            } else {
                "Security-sensitive path policy is missing.".to_string()
            },
        )
        .with_path(SECURITY_SENSITIVE_PATHS_FILE),
    ];
    if !policy_path.is_file() {
        return base_result(
            repo_root,
            "Security-sensitive path policy check failed before parsing.",
            findings,
            artifacts,
            runner,
        );
    }
    let parsed = match fs::read_to_string(&policy_path)
        .map_err(|error| error.to_string())
        .and_then(|text| {
            text.parse::<toml::Table>()
                .map_err(|error| error.to_string())
        }) {
        Ok(parsed) => parsed,
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "security-policy.parse",
                    "Security-sensitive path policy could not be parsed.".to_string(),
                )
                .with_path(SECURITY_SENSITIVE_PATHS_FILE)
                .with_details(json!({ "error": error })),
            );
            return base_result(
                repo_root,
                "Security-sensitive path policy check failed while parsing.",
                findings,
                artifacts,
                runner,
            );
        }
    };
    let raw_areas = parsed
        .get("areas")
        .and_then(toml::Value::as_array)
        .filter(|areas| !areas.is_empty());
    let Some(raw_areas) = raw_areas else {
        findings.push(
            Finding::new(
                "fail",
                "security-policy.areas",
                "Security-sensitive path policy does not define any areas.".to_string(),
            )
            .with_path(SECURITY_SENSITIVE_PATHS_FILE),
        );
        return base_result(
            repo_root,
            "Security-sensitive path policy has no areas.",
            findings,
            artifacts,
            runner,
        );
    };
    let areas = raw_areas
        .iter()
        .filter_map(toml::Value::as_table)
        .map(normalize_area)
        .collect::<Vec<_>>();
    findings.push(
        Finding::new(
            "pass",
            "security-policy.parse",
            "Security-sensitive path policy parsed successfully.".to_string(),
        )
        .with_path(SECURITY_SENSITIVE_PATHS_FILE)
        .with_details(json!({ "area_count": areas.len() })),
    );
    findings.extend(area_findings(repo_root, &areas));
    let mut result = base_result(
        repo_root,
        "Security-sensitive path policy checked.",
        findings,
        artifacts,
        runner,
    )
    .with_details(json!({
        "areas": areas,
        "area_count": areas.len(),
    }));
    if status_only {
        compact_status_only(&mut result);
    }
    result
}

fn normalize_area(table: &toml::Table) -> PolicyArea {
    PolicyArea {
        id: string_value(table, "id"),
        title: string_value(table, "title"),
        risk: string_value(table, "risk"),
        paths: string_array(table, "paths"),
        required_checks: string_array(table, "required_checks"),
    }
}

fn string_value(table: &toml::Table, key: &str) -> String {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn string_array(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn area_findings(repo_root: &Path, areas: &[PolicyArea]) -> Vec<Finding> {
    let mut seen_ids = BTreeSet::new();
    areas
        .iter()
        .map(|area| {
            let area_id = if area.id.is_empty() {
                "<missing-id>"
            } else {
                &area.id
            };
            let mut missing_fields = Vec::new();
            for (field, missing) in [
                ("id", area.id.is_empty()),
                ("title", area.title.is_empty()),
                ("risk", area.risk.is_empty()),
                ("paths", area.paths.is_empty()),
                ("required_checks", area.required_checks.is_empty()),
            ] {
                if missing {
                    missing_fields.push(field);
                }
            }
            let duplicate_id = !area.id.is_empty() && !seen_ids.insert(area.id.clone());
            let missing_paths = area
                .paths
                .iter()
                .filter(|path| !repo_root.join(path).exists())
                .cloned()
                .collect::<Vec<_>>();
            let status = if !missing_fields.is_empty() || duplicate_id {
                "fail"
            } else if !missing_paths.is_empty() {
                "warn"
            } else {
                "pass"
            };
            Finding::new(
                status,
                "security-policy.area",
                format!(
                    "Security policy area {area_id} is {}.",
                    if status == "pass" {
                        "valid"
                    } else {
                        "not fully valid"
                    }
                ),
            )
            .with_details(json!({
                "id": area.id,
                "title": area.title,
                "risk": area.risk,
                "paths": area.paths,
                "required_checks": area.required_checks,
                "missing_fields": missing_fields,
                "duplicate_id": duplicate_id,
                "missing_paths": missing_paths,
            }))
        })
        .collect()
}

fn base_result(
    repo_root: &Path,
    summary: &str,
    findings: Vec<Finding>,
    artifacts: Vec<String>,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    make_result(
        metadata(repo_root, "security-policy-check", runner),
        summary.to_string(),
        findings,
    )
    .with_artifacts(artifacts)
}

fn compact_status_only(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let area_count = result
        .details
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|details| details.get("area_count"))
        .cloned()
        .unwrap_or_else(|| json!(0));
    result.details = Some(json!({
        "area_count": area_count,
        "finding_count": finding_count,
        "non_pass_count": non_pass.len(),
    }));
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "security-policy.status-only",
            "Security policy check passed; no non-pass findings.".to_string(),
        ));
    }
    result.findings = non_pass;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(id: &str, path: &str) -> PolicyArea {
        PolicyArea {
            id: id.to_string(),
            title: "title".to_string(),
            risk: "risk".to_string(),
            paths: vec![path.to_string()],
            required_checks: vec!["check".to_string()],
        }
    }

    #[test]
    fn duplicate_ids_fail_and_missing_paths_warn() {
        let root =
            std::env::temp_dir().join(format!("yafvsctl-security-policy-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let findings = area_findings(&root, &[area("one", "missing"), area("one", "other")]);
        assert_eq!(findings[0].status, "warn");
        assert_eq!(findings[1].status, "fail");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn normalization_ignores_non_string_array_entries() {
        let table =
            "id = 'a'\ntitle = 'b'\nrisk = 'c'\npaths = ['one', 2]\nrequired_checks = ['check']\n"
                .parse::<toml::Table>()
                .unwrap();
        let normalized = normalize_area(&table);
        assert_eq!(normalized.paths, vec!["one"]);
    }
}
