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
    #[serde(default)]
    manifest: Option<String>,
    #[serde(default)]
    allowed_link_licenses: Vec<String>,
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
    dco_epoch: String,
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
    findings.push(cargo_path_dependency_finding(repo_root, &boundary));
    findings.push(dco_finding(repo_root, runner, &derivation.dco_epoch));
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
    if derivation.dco_epoch.trim().is_empty() {
        errors.push("DCO epoch must not be empty".to_string());
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
    let artifacts = policy
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();
    let mut checked = Vec::new();
    for edge in &policy.dependency_edges {
        let from_artifact = artifacts.get(edge.from.as_str()).copied();
        let to_artifact = artifacts.get(edge.to.as_str()).copied();
        let from_license = from_artifact.map(|artifact| artifact.concluded_license.as_str());
        let to_license = to_artifact.map(|artifact| artifact.concluded_license.as_str());
        let known_relationship = matches!(
            edge.relationship.as_str(),
            "static-link" | "dynamic-link" | "process" | "data"
        );
        let linked = matches!(edge.relationship.as_str(), "static-link" | "dynamic-link");
        let incompatible = linked
            && from_artifact.is_some_and(|artifact| {
                artifact.concluded_license == "GPL-2.0-only"
                    && !to_license.is_some_and(|license| {
                        artifact
                            .allowed_link_licenses
                            .iter()
                            .any(|allowed| allowed == license)
                    })
            });
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

fn cargo_path_dependency_finding(repo_root: &Path, policy: &BoundaryPolicy) -> Finding {
    let configured_manifests = policy
        .artifacts
        .iter()
        .filter_map(|artifact| {
            artifact
                .manifest
                .as_ref()
                .map(|manifest| (repo_root.join(manifest), artifact))
        })
        .collect::<Vec<_>>();
    let mut manifest_artifacts = BTreeMap::new();
    for (manifest, artifact) in &configured_manifests {
        if let Ok(canonical) = fs::canonicalize(manifest) {
            manifest_artifacts.insert(canonical, *artifact);
        }
    }

    let mut checked = Vec::new();
    let mut violations = Vec::new();
    for (manifest, artifact) in configured_manifests {
        let source_root = manifest.parent().unwrap_or(repo_root);
        let source_root =
            fs::canonicalize(source_root).unwrap_or_else(|_| source_root.to_path_buf());
        let Ok(text) = fs::read_to_string(&manifest) else {
            violations.push(json!({
                "artifact": artifact.id,
                "manifest": manifest.strip_prefix(repo_root).unwrap_or(&manifest),
                "error": "manifest is missing or unreadable",
            }));
            continue;
        };
        let Ok(value) = toml::from_str::<toml::Value>(&text) else {
            violations.push(json!({
                "artifact": artifact.id,
                "manifest": manifest.strip_prefix(repo_root).unwrap_or(&manifest),
                "error": "manifest is invalid TOML",
            }));
            continue;
        };
        let mut dependencies = Vec::new();
        collect_cargo_path_dependencies(&value, &mut dependencies);
        for (name, relative) in dependencies {
            let dependency_manifest = source_root.join(&relative).join("Cargo.toml");
            let Ok(canonical) = fs::canonicalize(&dependency_manifest) else {
                violations.push(json!({
                    "artifact": artifact.id,
                    "dependency": name,
                    "path": relative,
                    "error": "path dependency manifest is missing",
                }));
                continue;
            };
            if canonical.starts_with(&source_root) {
                checked.push(json!({
                    "artifact": artifact.id,
                    "dependency": name,
                    "relationship": "internal-path",
                    "path": canonical.strip_prefix(repo_root).unwrap_or(&canonical),
                }));
                continue;
            }
            let target_artifact = manifest_artifacts.get(&canonical).copied();
            let target_license = target_artifact
                .map(|target| target.concluded_license.clone())
                .or_else(|| cargo_manifest_license(&canonical));
            let declared = target_artifact.is_some_and(|target| {
                policy.dependency_edges.iter().any(|edge| {
                    edge.from == artifact.id
                        && edge.to == target.id
                        && matches!(edge.relationship.as_str(), "static-link" | "dynamic-link")
                })
            });
            let incompatible = artifact.concluded_license == "GPL-2.0-only"
                && !target_license.as_deref().is_some_and(|license| {
                    artifact
                        .allowed_link_licenses
                        .iter()
                        .any(|allowed| allowed == license)
                });
            let row = json!({
                "artifact": artifact.id,
                "artifact_license": artifact.concluded_license,
                "dependency": name,
                "dependency_artifact": target_artifact.map(|target| target.id.as_str()),
                "dependency_license": target_license,
                "path": canonical.strip_prefix(repo_root).unwrap_or(&canonical),
                "declared_edge": declared,
                "incompatible": incompatible,
            });
            if declared && !incompatible && row["dependency_license"].is_string() {
                checked.push(row);
            } else {
                violations.push(row);
            }
        }
    }
    Finding::new(
        if violations.is_empty() {
            "pass"
        } else {
            "fail"
        },
        "license.cargo-path-dependencies",
        if violations.is_empty() {
            "Configured Rust path dependencies are declared and license-compatible.".to_string()
        } else {
            "A Rust path dependency is undeclared, unlicensed, missing, or license-incompatible."
                .to_string()
        },
    )
    .with_details(json!({ "checked": checked, "violations": violations }))
}

fn collect_cargo_path_dependencies(value: &toml::Value, found: &mut Vec<(String, String)>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, value) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            if let Some(dependencies) = value.as_table() {
                for (name, dependency) in dependencies {
                    if let Some(path) = dependency
                        .as_table()
                        .and_then(|table| table.get("path"))
                        .and_then(toml::Value::as_str)
                    {
                        found.push((name.clone(), path.to_string()));
                    }
                }
            }
        } else {
            collect_cargo_path_dependencies(value, found);
        }
    }
}

fn cargo_manifest_license(manifest: &Path) -> Option<String> {
    let text = fs::read_to_string(manifest).ok()?;
    let value = toml::from_str::<toml::Value>(&text).ok()?;
    value
        .get("package")?
        .get("license")?
        .as_str()
        .map(str::to_string)
}

fn dco_finding(repo_root: &Path, runner: &dyn CommandRunner, epoch: &str) -> Finding {
    let range = format!("{epoch}..HEAD");
    let Some(output) = run_git(runner, repo_root, &["log", "--format=%H%x1f%B%x1e", &range]) else {
        return Finding::new(
            "fail",
            "license.commit-dco",
            "Could not inspect commits for Developer Certificate of Origin sign-offs.".to_string(),
        );
    };
    let missing = output
        .split('\u{1e}')
        .filter_map(|record| {
            let (commit, body) = record.trim().split_once('\u{1f}')?;
            (!body.lines().any(valid_signoff)).then(|| commit.to_string())
        })
        .collect::<Vec<_>>();
    Finding::new(
        if missing.is_empty() { "pass" } else { "fail" },
        "license.commit-dco",
        if missing.is_empty() {
            "Commits after the DCO epoch contain Signed-off-by attestations.".to_string()
        } else {
            "Commits after the DCO epoch are missing Signed-off-by attestations.".to_string()
        },
    )
    .with_details(json!({ "epoch": epoch, "missing_commits": missing }))
}

fn valid_signoff(line: &str) -> bool {
    let Some(value) = line.strip_prefix("Signed-off-by: ") else {
        return false;
    };
    let Some((name, address)) = value.rsplit_once(" <") else {
        return false;
    };
    !name.trim().is_empty() && address.ends_with('>') && address[..address.len() - 1].contains('@')
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
                    manifest: None,
                    allowed_link_licenses: Vec::new(),
                },
                Artifact {
                    id: "manager".to_string(),
                    concluded_license: "GPL-3.0-or-later".to_string(),
                    manifest: None,
                    allowed_link_licenses: Vec::new(),
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
                    manifest: None,
                    allowed_link_licenses: Vec::new(),
                },
                Artifact {
                    id: "manager".to_string(),
                    concluded_license: "AGPL-3.0-or-later".to_string(),
                    manifest: None,
                    allowed_link_licenses: Vec::new(),
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
    fn gpl2_only_link_requires_an_explicit_compatible_allowlist_entry() {
        let policy = BoundaryPolicy {
            schema_version: 1,
            policy_epoch: "epoch".to_string(),
            path_rules: vec![rule("", &["GPL-3.0-or-later"])],
            artifacts: vec![
                Artifact {
                    id: "scanner".to_string(),
                    concluded_license: "GPL-2.0-only".to_string(),
                    manifest: None,
                    allowed_link_licenses: vec!["GPL-2.0-or-later".to_string()],
                },
                Artifact {
                    id: "library".to_string(),
                    concluded_license: "GPL-2.0-or-later".to_string(),
                    manifest: None,
                    allowed_link_licenses: Vec::new(),
                },
            ],
            dependency_edges: vec![DependencyEdge {
                from: "scanner".to_string(),
                to: "library".to_string(),
                relationship: "dynamic-link".to_string(),
                rationale: "explicit reviewed compatibility".to_string(),
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
            dco_epoch: "dco-epoch".to_string(),
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

    #[test]
    fn cargo_path_dependency_checks_the_real_manifest_edge() {
        let root = root();
        fs::create_dir_all(root.join("scanner")).unwrap();
        fs::create_dir_all(root.join("manager")).unwrap();
        fs::write(
            root.join("scanner/Cargo.toml"),
            "[package]\nname = \"scanner\"\nversion = \"0.1.0\"\nlicense = \"GPL-2.0-only\"\n[dependencies]\nmanager = { path = \"../manager\" }\n",
        )
        .unwrap();
        fs::write(
            root.join("manager/Cargo.toml"),
            "[package]\nname = \"manager\"\nversion = \"0.1.0\"\nlicense = \"GPL-3.0-or-later\"\n",
        )
        .unwrap();
        let policy = BoundaryPolicy {
            schema_version: 1,
            policy_epoch: "epoch".to_string(),
            path_rules: vec![rule("", &["GPL-3.0-or-later"])],
            artifacts: vec![
                Artifact {
                    id: "scanner".to_string(),
                    concluded_license: "GPL-2.0-only".to_string(),
                    manifest: Some("scanner/Cargo.toml".to_string()),
                    allowed_link_licenses: vec!["GPL-2.0-or-later".to_string()],
                },
                Artifact {
                    id: "manager".to_string(),
                    concluded_license: "GPL-3.0-or-later".to_string(),
                    manifest: Some("manager/Cargo.toml".to_string()),
                    allowed_link_licenses: Vec::new(),
                },
            ],
            dependency_edges: vec![DependencyEdge {
                from: "scanner".to_string(),
                to: "manager".to_string(),
                relationship: "static-link".to_string(),
                rationale: "test edge".to_string(),
            }],
        };
        assert_eq!(cargo_path_dependency_finding(&root, &policy).status, "fail");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dco_signoff_requires_a_name_and_email_shape() {
        assert!(valid_signoff(
            "Signed-off-by: Robert Pelfrey <Robert@Pelfrey.de>"
        ));
        assert!(!valid_signoff("Signed-off-by: no-address"));
        assert!(!valid_signoff("signed-off-by: Robert <r@example.test>"));
    }
}
