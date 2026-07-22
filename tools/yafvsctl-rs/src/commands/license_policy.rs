// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later
// YAFVS-Derivation: original

use super::common::run_git;
use crate::process::CommandRunner;
use crate::result::Finding;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const BOUNDARY_POLICY_PATH: &str = "policy/license-boundaries.toml";
const DERIVATION_POLICY_PATH: &str = "policy/derivation-provenance.toml";

#[derive(Debug, Deserialize)]
struct BoundaryPolicy {
    schema_version: u32,
    policy_epoch: String,
    path_rules: Vec<PathRule>,
    artifacts: Vec<Artifact>,
    #[serde(default)]
    dependency_edges: Vec<DependencyEdge>,
}

#[derive(Debug, Deserialize)]
struct PathRule {
    id: String,
    prefix: String,
    allowed_licenses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    id: String,
    concluded_license: String,
}

#[derive(Debug, Deserialize)]
struct DependencyEdge {
    from: String,
    to: String,
    relationship: String,
    rationale: String,
}

#[derive(Debug, Deserialize)]
struct DerivationPolicy {
    schema_version: u32,
    policy_epoch: String,
    source_suffixes: Vec<String>,
    allowed_derivations: Vec<String>,
    #[serde(default)]
    review_surfaces: Vec<ReviewSurface>,
}

#[derive(Debug, Deserialize)]
struct ReviewSurface {
    id: String,
    path: String,
    status: String,
    question: String,
}

#[derive(Debug)]
struct AddedSource {
    path: String,
    source: String,
}

pub(super) fn license_policy_findings(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> Vec<Finding> {
    let boundary = read_policy::<BoundaryPolicy>(repo_root, BOUNDARY_POLICY_PATH);
    let derivation = read_policy::<DerivationPolicy>(repo_root, DERIVATION_POLICY_PATH);
    let mut findings = vec![
        policy_parse_finding("license.boundary-policy", BOUNDARY_POLICY_PATH, &boundary),
        policy_parse_finding(
            "license.derivation-policy",
            DERIVATION_POLICY_PATH,
            &derivation,
        ),
    ];

    let (Ok(boundary), Ok(derivation)) = (boundary, derivation) else {
        return findings;
    };
    let policy_shape_errors = validate_policy_shape(&boundary, &derivation);
    findings.push(
        Finding::new(
            if policy_shape_errors.is_empty() {
                "pass"
            } else {
                "fail"
            },
            "license.policy-shape",
            if policy_shape_errors.is_empty() {
                "License boundary and derivation policies are internally consistent.".to_string()
            } else {
                "License boundary or derivation policy is internally inconsistent.".to_string()
            },
        )
        .with_details(json!({ "errors": policy_shape_errors })),
    );

    let added = added_sources(repo_root, runner, &boundary.policy_epoch);
    match added {
        Some(added) => {
            findings.push(path_license_finding(repo_root, &boundary, &added));
            findings.push(derivation_finding(repo_root, &derivation, &added));
        }
        None => {
            findings.push(Finding::new(
                "fail",
                "license.path-license",
                "Could not enumerate files added after the license-policy epoch.".to_string(),
            ));
            findings.push(Finding::new(
                "fail",
                "license.derivation-provenance",
                "Could not enumerate files added after the derivation-policy epoch.".to_string(),
            ));
        }
    }
    findings.push(artifact_graph_finding(&boundary));
    findings.push(review_surface_finding(&derivation));
    findings
}

fn read_policy<T: for<'de> Deserialize<'de>>(
    repo_root: &Path,
    relative: &str,
) -> Result<T, String> {
    let text = fs::read_to_string(repo_root.join(relative))
        .map_err(|error| format!("{relative}: {error}"))?;
    toml::from_str(&text).map_err(|error| format!("{relative}: {error}"))
}

fn policy_parse_finding<T>(check: &str, path: &str, result: &Result<T, String>) -> Finding {
    Finding::new(
        if result.is_ok() { "pass" } else { "fail" },
        check,
        match result {
            Ok(_) => format!("{path} parsed successfully."),
            Err(_) => format!("{path} is missing or invalid."),
        },
    )
    .with_path(path)
    .with_details(json!({ "error": result.as_ref().err() }))
}

fn validate_policy_shape(boundary: &BoundaryPolicy, derivation: &DerivationPolicy) -> Vec<String> {
    let mut errors = Vec::new();
    if boundary.schema_version != 1 {
        errors.push(format!(
            "unsupported boundary schema version {}",
            boundary.schema_version
        ));
    }
    if derivation.schema_version != 1 {
        errors.push(format!(
            "unsupported derivation schema version {}",
            derivation.schema_version
        ));
    }
    if boundary.policy_epoch != derivation.policy_epoch {
        errors.push("policy epochs do not match".to_string());
    }
    if !boundary
        .path_rules
        .iter()
        .any(|rule| rule.prefix.is_empty())
    {
        errors.push("a default empty-prefix path rule is required".to_string());
    }
    duplicate_values(
        boundary.path_rules.iter().map(|rule| rule.id.as_str()),
        "path-rule id",
        &mut errors,
    );
    duplicate_values(
        boundary
            .artifacts
            .iter()
            .map(|artifact| artifact.id.as_str()),
        "artifact id",
        &mut errors,
    );
    errors
}

fn duplicate_values<'a>(
    values: impl Iterator<Item = &'a str>,
    kind: &str,
    errors: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            errors.push(format!("duplicate {kind}: {value}"));
        }
    }
}

fn added_sources(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    epoch: &str,
) -> Option<Vec<AddedSource>> {
    let range = format!("{epoch}..HEAD");
    let committed = run_git(
        runner,
        repo_root,
        &["diff", "--find-renames", "--name-status", &range],
    )?;
    let staged = run_git(
        runner,
        repo_root,
        &["diff", "--find-renames", "--cached", "--name-status"],
    )?;
    let worktree = run_git(
        runner,
        repo_root,
        &["diff", "--find-renames", "--name-status"],
    )?;
    let untracked = run_git(
        runner,
        repo_root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?;
    let mut paths = BTreeMap::new();
    collect_added_rows(&committed, "committed", &mut paths);
    collect_added_rows(&staged, "staged", &mut paths);
    collect_added_rows(&worktree, "worktree", &mut paths);
    for path in untracked.split('\0').filter(|path| !path.is_empty()) {
        paths.insert(path.to_string(), "untracked".to_string());
    }
    Some(
        paths
            .into_iter()
            .map(|(path, source)| AddedSource { path, source })
            .collect(),
    )
}

fn collect_added_rows(output: &str, source: &str, paths: &mut BTreeMap<String, String>) {
    for line in output.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() >= 2 && (fields[0].starts_with('A') || fields[0].starts_with('C')) {
            if let Some(path) = fields.last() {
                paths.insert((*path).to_string(), source.to_string());
            }
        }
    }
}

fn path_license_finding(
    repo_root: &Path,
    policy: &BoundaryPolicy,
    added: &[AddedSource],
) -> Finding {
    let mut violations = Vec::new();
    let mut checked = Vec::new();
    for item in added {
        let path = repo_root.join(&item.path);
        if !path.is_file() || !license_header_candidate(&path) {
            continue;
        }
        let rule = matching_rule(&policy.path_rules, &item.path);
        let license = spdx_license(&path);
        let allowed = rule.is_some_and(|rule| {
            license.as_ref().is_some_and(|license| {
                rule.allowed_licenses
                    .iter()
                    .any(|allowed| allowed == license)
            })
        });
        let row = json!({
            "path": item.path,
            "source": item.source,
            "license": license,
            "rule": rule.map(|rule| rule.id.as_str()),
            "allowed_licenses": rule.map(|rule| &rule.allowed_licenses),
        });
        if allowed {
            checked.push(row);
        } else {
            violations.push(row);
        }
    }
    Finding::new(
        if violations.is_empty() {
            "pass"
        } else {
            "fail"
        },
        "license.path-license",
        if violations.is_empty() {
            "Files added after the policy epoch use licenses allowed at their paths.".to_string()
        } else {
            "Files added after the policy epoch violate a path license boundary.".to_string()
        },
    )
    .with_details(json!({
        "epoch": policy.policy_epoch,
        "checked": checked,
        "violations": violations,
    }))
}

fn license_header_candidate(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "c" | "h"
                    | "cc"
                    | "cpp"
                    | "rs"
                    | "py"
                    | "js"
                    | "jsx"
                    | "ts"
                    | "tsx"
                    | "sql"
                    | "sh"
                    | "toml"
                    | "yaml"
                    | "yml"
            )
        })
}

fn matching_rule<'a>(rules: &'a [PathRule], path: &str) -> Option<&'a PathRule> {
    rules
        .iter()
        .filter(|rule| path.starts_with(&rule.prefix))
        .max_by_key(|rule| rule.prefix.len())
}

fn spdx_license(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.lines().take(60).find_map(|line| {
        line.split_once("SPDX-License-Identifier:")
            .map(|(_, value)| {
                value
                    .trim()
                    .trim_end_matches("*/")
                    .trim_end_matches("-->")
                    .trim()
                    .to_string()
            })
    })
}

fn derivation_finding(
    repo_root: &Path,
    policy: &DerivationPolicy,
    added: &[AddedSource],
) -> Finding {
    let mut violations = Vec::new();
    let mut checked = Vec::new();
    for item in added {
        let path = PathBuf::from(&item.path);
        let suffix = path.extension().and_then(|value| value.to_str());
        if !suffix.is_some_and(|suffix| policy.source_suffixes.iter().any(|item| item == suffix)) {
            continue;
        }
        let text = fs::read_to_string(repo_root.join(&item.path)).unwrap_or_default();
        let derivation = marker_value(&text, "YAFVS-Derivation:");
        let provenance = marker_value(&text, "YAFVS-Source-Provenance:");
        let valid_derivation = derivation
            .as_ref()
            .is_some_and(|value| policy.allowed_derivations.iter().any(|item| item == value));
        let provenance_required = derivation
            .as_deref()
            .is_some_and(|value| value != "original");
        let valid = valid_derivation && (!provenance_required || provenance.is_some());
        let row = json!({
            "path": item.path,
            "source": item.source,
            "derivation": derivation,
            "source_provenance": provenance,
            "source_provenance_required": provenance_required,
        });
        if valid {
            checked.push(row);
        } else {
            violations.push(row);
        }
    }
    Finding::new(
        if violations.is_empty() {
            "pass"
        } else {
            "fail"
        },
        "license.derivation-provenance",
        if violations.is_empty() {
            "New source files declare their derivation class and required source provenance."
                .to_string()
        } else {
            "New source files are missing valid derivation or source-provenance declarations."
                .to_string()
        },
    )
    .with_details(json!({
        "epoch": policy.policy_epoch,
        "allowed_derivations": policy.allowed_derivations,
        "checked": checked,
        "violations": violations,
    }))
}

fn marker_value(text: &str, marker: &str) -> Option<String> {
    text.lines().take(60).find_map(|line| {
        line.split_once(marker).map(|(_, value)| {
            value
                .trim()
                .trim_end_matches("*/")
                .trim_end_matches("-->")
                .trim()
                .to_string()
        })
    })
}

fn artifact_graph_finding(policy: &BoundaryPolicy) -> Finding {
    let licenses = policy
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact.concluded_license.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();
    let mut checked = Vec::new();
    for edge in &policy.dependency_edges {
        let from_license = licenses.get(edge.from.as_str()).copied();
        let to_license = licenses.get(edge.to.as_str()).copied();
        let known_relationship = matches!(
            edge.relationship.as_str(),
            "static-link" | "dynamic-link" | "process" | "data"
        );
        let incompatible = matches!(edge.relationship.as_str(), "static-link" | "dynamic-link")
            && from_license == Some("GPL-2.0-only")
            && to_license.is_some_and(is_gpl3_or_agpl3);
        let valid = from_license.is_some()
            && to_license.is_some()
            && known_relationship
            && !edge.rationale.trim().is_empty()
            && !incompatible;
        let row = json!({
            "from": edge.from,
            "from_license": from_license,
            "to": edge.to,
            "to_license": to_license,
            "relationship": edge.relationship,
            "rationale": edge.rationale,
            "incompatible": incompatible,
        });
        if valid {
            checked.push(row);
        } else {
            violations.push(row);
        }
    }
    Finding::new(
        if violations.is_empty() {
            "pass"
        } else {
            "fail"
        },
        "license.artifact-graph",
        if violations.is_empty() {
            "Declared artifact relationships do not cross a known incompatible link boundary."
                .to_string()
        } else {
            "Artifact graph contains unknown or license-incompatible relationships.".to_string()
        },
    )
    .with_details(json!({ "checked": checked, "violations": violations }))
}

fn is_gpl3_or_agpl3(license: &str) -> bool {
    license.starts_with("GPL-3.0") || license.starts_with("AGPL-3.0")
}

fn review_surface_finding(policy: &DerivationPolicy) -> Finding {
    let open = policy
        .review_surfaces
        .iter()
        .filter(|surface| surface.status != "resolved")
        .map(|surface| {
            json!({
                "id": surface.id,
                "path": surface.path,
                "status": surface.status,
                "question": surface.question,
            })
        })
        .collect::<Vec<_>>();
    Finding::new(
        "pass",
        "license.derivation-review-register",
        if open.is_empty() {
            "No unresolved derivation-classification reviews are registered.".to_string()
        } else {
            "Unresolved derivation reviews are explicitly registered and remain release blockers where applicable."
                .to_string()
        },
    )
    .with_details(json!({ "open_reviews": open }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yafvs-license-policy-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn rule(prefix: &str, licenses: &[&str]) -> PathRule {
        PathRule {
            id: prefix.to_string(),
            prefix: prefix.to_string(),
            allowed_licenses: licenses.iter().map(|item| (*item).to_string()).collect(),
        }
    }

    #[test]
    fn longest_path_rule_wins() {
        let rules = vec![
            rule("", &["GPL-3.0-or-later"]),
            rule("components/openvas-scanner/", &["GPL-2.0-only"]),
        ];
        assert_eq!(
            matching_rule(&rules, "components/openvas-scanner/src/main.c")
                .unwrap()
                .allowed_licenses,
            vec!["GPL-2.0-only"]
        );
    }

    #[test]
    fn gpl3_source_is_rejected_under_gpl2_scanner_boundary() {
        let root = root();
        let relative = "components/openvas-scanner/src/new.rs";
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "// SPDX-License-Identifier: GPL-3.0-or-later\n// YAFVS-Derivation: original\n",
        )
        .unwrap();
        let policy = BoundaryPolicy {
            schema_version: 1,
            policy_epoch: "epoch".to_string(),
            path_rules: vec![
                rule("", &["GPL-3.0-or-later"]),
                rule(
                    "components/openvas-scanner/",
                    &["GPL-2.0-only", "GPL-2.0-or-later"],
                ),
            ],
            artifacts: Vec::new(),
            dependency_edges: Vec::new(),
        };
        let finding = path_license_finding(
            &root,
            &policy,
            &[AddedSource {
                path: relative.to_string(),
                source: "untracked".to_string(),
            }],
        );
        assert_eq!(finding.status, "fail");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn gpl2_only_artifact_cannot_link_gpl3_artifact() {
        let policy = BoundaryPolicy {
            schema_version: 1,
            policy_epoch: "epoch".to_string(),
            path_rules: vec![rule("", &["GPL-3.0-or-later"])],
            artifacts: vec![
                Artifact {
                    id: "scanner".to_string(),
                    concluded_license: "GPL-2.0-only".to_string(),
                },
                Artifact {
                    id: "manager".to_string(),
                    concluded_license: "GPL-3.0-or-later".to_string(),
                },
            ],
            dependency_edges: vec![DependencyEdge {
                from: "scanner".to_string(),
                to: "manager".to_string(),
                relationship: "static-link".to_string(),
                rationale: "test".to_string(),
            }],
        };
        assert_eq!(artifact_graph_finding(&policy).status, "fail");
    }

    #[test]
    fn process_boundary_does_not_create_a_link_violation() {
        let policy = BoundaryPolicy {
            schema_version: 1,
            policy_epoch: "epoch".to_string(),
            path_rules: vec![rule("", &["GPL-3.0-or-later"])],
            artifacts: vec![
                Artifact {
                    id: "scanner".to_string(),
                    concluded_license: "GPL-2.0-only".to_string(),
                },
                Artifact {
                    id: "manager".to_string(),
                    concluded_license: "AGPL-3.0-or-later".to_string(),
                },
            ],
            dependency_edges: vec![DependencyEdge {
                from: "scanner".to_string(),
                to: "manager".to_string(),
                relationship: "process".to_string(),
                rationale: "HTTP boundary".to_string(),
            }],
        };
        assert_eq!(artifact_graph_finding(&policy).status, "pass");
    }

    #[test]
    fn adaptations_require_source_provenance() {
        let root = root();
        let relative = "services/example.rs";
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "// YAFVS-Derivation: adaptation\n").unwrap();
        let policy = DerivationPolicy {
            schema_version: 1,
            policy_epoch: "epoch".to_string(),
            source_suffixes: vec!["rs".to_string()],
            allowed_derivations: vec!["original".to_string(), "adaptation".to_string()],
            review_surfaces: Vec::new(),
        };
        let finding = derivation_finding(
            &root,
            &policy,
            &[AddedSource {
                path: relative.to_string(),
                source: "untracked".to_string(),
            }],
        );
        assert_eq!(finding.status, "fail");
        let _ = fs::remove_dir_all(root);
    }
}
