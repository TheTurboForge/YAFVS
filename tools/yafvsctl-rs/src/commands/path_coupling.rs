// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, git_tracked_files, metadata};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use regex::Regex;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

static PATH_COUPLING_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        (
            "absolute_home_checkout_path",
            r#"/home/[^/\s\"'`]+/(?:Projects|Projekte)/TurboVAS(?:/|\b)"#,
        ),
        (
            "absolute_home_runtime_path",
            r#"/home/[^/\s\"'`]+/(?:Projects|Projekte)/TurboVAS-runtime(?:/|\b)"#,
        ),
        ("build_prefix_path", r"build/prefix(?:/|\b)"),
        ("container_runtime_path", r"/runtime/"),
        ("workspace_mount_path", r"/workspace(?:/|\b)"),
    ]
    .into_iter()
    .map(|(name, pattern)| {
        (
            name,
            Regex::new(pattern).expect("static path-coupling regex"),
        )
    })
    .collect()
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PathCouplingReference {
    path: String,
    category: String,
    markers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PathBucket {
    count: usize,
    paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PathCouplingSummary {
    total_references: usize,
    by_category: BTreeMap<String, PathBucket>,
    by_marker: BTreeMap<String, PathBucket>,
    non_documentation_dev_checkout_paths: Vec<String>,
}

pub fn command_path_coupling_state(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_path_coupling_state_with(repo_root, status_only, &SystemCommandRunner)
}

fn command_path_coupling_state_with(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let references = path_coupling_references(repo_root, runner);
    let summary = summarize_path_coupling(&references);
    let warning_paths = summary.non_documentation_dev_checkout_paths.clone();
    let findings = vec![
        Finding::new(
            "pass",
            "path-coupling.source-map",
            format!(
                "Classified {} tracked path-coupling reference(s).",
                references.len()
            ),
        )
        .with_details(json!(summary)),
        Finding::new(
            if warning_paths.is_empty() {
                "pass"
            } else {
                "warn"
            },
            "path-coupling.dev-checkout",
            if warning_paths.is_empty() {
                "No hard-coded development checkout paths found outside documentation.".to_string()
            } else {
                "Hard-coded development checkout paths exist outside documentation.".to_string()
            },
        )
        .with_details(json!({ "paths": warning_paths })),
    ];
    let mut result = make_result(
        metadata(repo_root, "path-coupling-state", runner),
        "Absolute path and runtime path coupling state collected.".to_string(),
        findings,
    )
    .with_details(json!({
        "references": references.iter().take(200).collect::<Vec<_>>(),
        "summary": summary,
        "reference_count": references.len(),
    }));
    if status_only {
        compact_status_only(&mut result);
    }
    result
}

fn path_coupling_category(relative_path: &str) -> &'static str {
    if relative_path.starts_with("docs/")
        || [".md", ".rst", ".txt"]
            .iter()
            .any(|suffix| relative_path.ends_with(suffix))
        || matches!(relative_path, "README.md" | "BUILDING.md")
    {
        "documentation"
    } else if ["compose/", "docker/", "ops/"]
        .iter()
        .any(|prefix| relative_path.starts_with(prefix))
        || matches!(relative_path, "justfile" | "tools/yafvsctl")
    {
        "runtime_tooling"
    } else if relative_path.starts_with("tools/") {
        "diagnostic_tooling"
    } else if relative_path.starts_with("components/") {
        "component_source"
    } else {
        "other_tracked_source"
    }
}

fn path_coupling_markers(text: &str) -> Vec<String> {
    PATH_COUPLING_PATTERNS
        .iter()
        .filter(|(_, pattern)| pattern.is_match(text))
        .map(|(name, _)| (*name).to_string())
        .collect()
}

fn path_coupling_references(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> Vec<PathCouplingReference> {
    let mut references = git_tracked_files(runner, repo_root)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|relative_path| {
            let bytes = std::fs::read(repo_root.join(&relative_path)).ok()?;
            let text = String::from_utf8_lossy(&bytes);
            let markers = path_coupling_markers(&text);
            (!markers.is_empty()).then(|| PathCouplingReference {
                category: path_coupling_category(&relative_path).to_string(),
                path: relative_path,
                markers,
            })
        })
        .collect::<Vec<_>>();
    references.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.path.cmp(&right.path))
    });
    references
}

fn summarize_path_coupling(references: &[PathCouplingReference]) -> PathCouplingSummary {
    let mut category_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut marker_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut warning_paths = BTreeSet::new();
    for reference in references {
        category_paths
            .entry(reference.category.clone())
            .or_default()
            .push(reference.path.clone());
        for marker in &reference.markers {
            marker_paths
                .entry(marker.clone())
                .or_default()
                .push(reference.path.clone());
        }
        if matches!(
            reference.category.as_str(),
            "component_source" | "other_tracked_source"
        ) && reference
            .markers
            .iter()
            .any(|marker| marker == "absolute_home_checkout_path")
        {
            warning_paths.insert(reference.path.clone());
        }
    }
    PathCouplingSummary {
        total_references: references.len(),
        by_category: category_paths
            .into_iter()
            .map(|(category, paths)| {
                let count = paths.len();
                (
                    category,
                    PathBucket {
                        count,
                        paths: paths.into_iter().take(50).collect(),
                    },
                )
            })
            .collect(),
        by_marker: marker_paths
            .into_iter()
            .map(|(marker, paths)| {
                let count = paths.len();
                (
                    marker,
                    PathBucket {
                        count,
                        paths: paths.into_iter().take(50).collect(),
                    },
                )
            })
            .collect(),
        non_documentation_dev_checkout_paths: warning_paths.into_iter().take(100).collect(),
    }
}

fn compact_status_only(result: &mut ResultEnvelope) {
    let finding_count = result.findings.len();
    let mut non_pass = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect::<Vec<_>>();
    let reference_count = result
        .details
        .as_ref()
        .and_then(|details| details.get("reference_count"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let warning_path_count = result
        .details
        .as_ref()
        .and_then(|details| details.pointer("/summary/non_documentation_dev_checkout_paths"))
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let non_pass_count = non_pass.len();
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "path-coupling.status-only",
            "Path-coupling check passed; no non-pass findings.".to_string(),
        ));
    }
    result.details = Some(json!({
        "reference_count": reference_count,
        "non_documentation_dev_checkout_path_count": warning_path_count,
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
    }));
    result.findings = non_pass;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_expected_paths_and_markers() {
        assert_eq!(path_coupling_category("docs/README.md"), "documentation");
        assert_eq!(
            path_coupling_category("docker/runtime/README.md"),
            "documentation"
        );
        assert_eq!(
            path_coupling_category("compose/dev.yaml"),
            "runtime_tooling"
        );
        assert_eq!(
            path_coupling_category("tools/tests/test_yafvsctl.py"),
            "diagnostic_tooling"
        );
        assert_eq!(
            path_coupling_markers("/home/example/Projects/TurboVAS build/prefix /runtime/state"),
            vec![
                "absolute_home_checkout_path",
                "build_prefix_path",
                "container_runtime_path",
            ]
        );
    }

    #[test]
    fn warns_only_for_product_checkout_paths() {
        let summary = summarize_path_coupling(&[
            PathCouplingReference {
                path: "components/example.c".to_string(),
                category: "component_source".to_string(),
                markers: vec!["absolute_home_checkout_path".to_string()],
            },
            PathCouplingReference {
                path: "tools/yafvsctl".to_string(),
                category: "runtime_tooling".to_string(),
                markers: vec!["absolute_home_checkout_path".to_string()],
            },
        ]);
        assert_eq!(
            summary.non_documentation_dev_checkout_paths,
            ["components/example.c"]
        );
    }
}
