// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{git_tracked_files, metadata};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use std::path::Path;

const BRANDING_MARKERS: [&str; 5] = ["OpenVAS", "OPENVAS", "Greenbone", "greenbone", "GSA"];
const BRANDING_PATH_MARKERS: [&str; 8] = [
    "OpenVAS",
    "openvas",
    "OPENVAS",
    "Greenbone",
    "greenbone",
    "GSA",
    "gsa",
    "Enterprise_",
];
const BRANDING_LOCALE_TECHNICAL_PHRASES: [&str; 8] = [
    "Default OpenVAS Scan Config",
    "Default OpenVAS Scanner",
    "OpenVAS Scanner",
    "OpenVASD Scanner",
    "OpenVASD Sensor",
    "OPENVAS COMMUNITY FEED",
    "\"Greenbone\": \"Greenbone\"",
    "https://www.greenbone.net/en/feed-comparison/",
];
const BRANDING_PROVENANCE_FILES: [&str; 6] = [
    "README.md",
    "UPSTREAMS.md",
    "LICENSE_AUDIT.md",
    "docs/CHANGES_FROM_UPSTREAM.md",
    "docs/USER_MANUAL.md",
    "docs/PUBLIC_RELEASE_READINESS.md",
];

fn branding_scan_candidate(relative_path: &str) -> bool {
    matches!(
        relative_path,
        "README.md"
            | "UPSTREAMS.md"
            | "LICENSE_AUDIT.md"
            | "components/gsa/index.html"
            | "components/gsa/package.json"
            | "components/gsa/public/locales/gsa-en.json"
    ) || relative_path.starts_with("docs/")
        || relative_path.starts_with("components/gsa/public/img/")
        || relative_path.starts_with("components/gsa/src/web/components/icon/svg/")
}

fn branding_markers(path: &Path, relative_path: &str) -> Vec<String> {
    let filename = relative_path.rsplit('/').next().unwrap_or(relative_path);
    let mut markers = BRANDING_PATH_MARKERS
        .iter()
        .filter(|marker| filename.contains(**marker))
        .map(|marker| (*marker).to_string())
        .collect::<Vec<_>>();
    if let Ok(bytes) = std::fs::read(path) {
        let text = String::from_utf8_lossy(&bytes);
        markers.extend(
            BRANDING_MARKERS
                .iter()
                .filter(|marker| text.contains(**marker))
                .map(|marker| (*marker).to_string()),
        );
    }
    markers.sort();
    markers.dedup();
    markers
}

fn branding_locale_line_category(line: &str) -> &'static str {
    if BRANDING_LOCALE_TECHNICAL_PHRASES
        .iter()
        .any(|phrase| line.contains(phrase))
    {
        "technical_doc_context"
    } else {
        "active_product_surface"
    }
}

fn branding_locale_items(path: &Path, relative_path: &str) -> Vec<Value> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    text.lines().enumerate().filter_map(|(index, line)| {
        let markers = BRANDING_MARKERS.iter().filter(|marker| line.contains(**marker))
            .map(|marker| Value::String((*marker).to_string())).collect::<Vec<_>>();
        (!markers.is_empty()).then(|| json!({
            "path": relative_path, "line": index + 1, "category": branding_locale_line_category(line),
            "markers": markers, "text": line.trim(),
        }))
    }).collect()
}

pub(crate) fn branding_category(relative_path: &str) -> &'static str {
    if BRANDING_PROVENANCE_FILES.contains(&relative_path) {
        return "provenance_or_non_affiliation";
    }
    if relative_path.starts_with("docs/")
        || relative_path.starts_with("components/gsa/public/img/os_")
    {
        return "technical_doc_context";
    }
    if relative_path.starts_with("components/gsa/src/web/components/icon/svg/")
        || relative_path.starts_with("components/gsa/public/")
        || matches!(
            relative_path,
            "components/gsa/index.html" | "components/gsa/package.json"
        )
    {
        return "active_product_surface";
    }
    "unknown"
}

fn branding_item_category(relative_path: &str, markers: &[String]) -> &'static str {
    if relative_path == "components/gsa/package.json" && markers == ["greenbone"] {
        "technical_doc_context"
    } else {
        branding_category(relative_path)
    }
}

fn branding_inventory(repo_root: &Path, runner: &dyn CommandRunner) -> Vec<Value> {
    let mut items = Vec::new();
    for relative_path in git_tracked_files(runner, repo_root).unwrap_or_default() {
        if !branding_scan_candidate(&relative_path) {
            continue;
        }
        let path = repo_root.join(&relative_path);
        if !path.is_file() {
            continue;
        }
        if relative_path == "components/gsa/public/locales/gsa-en.json" {
            items.extend(branding_locale_items(&path, &relative_path));
            continue;
        }
        let markers = branding_markers(&path, &relative_path);
        if markers.is_empty() {
            continue;
        }
        items.push(json!({ "path": relative_path, "category": branding_item_category(&relative_path, &markers), "markers": markers }));
    }
    items.sort_by(|left, right| {
        left["category"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["category"].as_str().unwrap_or_default())
            .then_with(|| {
                left["path"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["path"].as_str().unwrap_or_default())
            })
    });
    items
}

fn summarize_branding(items: &[Value]) -> Value {
    let categories = [
        "active_product_surface",
        "technical_doc_context",
        "provenance_or_non_affiliation",
        "unknown",
    ];
    let by_category = categories.iter().map(|category| {
        let mut paths = items.iter().filter(|item| item["category"] == *category)
            .filter_map(|item| item["path"].as_str()).collect::<Vec<_>>();
        paths.sort_unstable(); paths.dedup();
        ((*category).to_string(), json!({ "count": items.iter().filter(|item| item["category"] == *category).count(), "paths": paths }))
    }).collect::<serde_json::Map<_, _>>();
    json!({ "total_items": items.len(), "by_category": by_category })
}

pub fn command_branding_state(repo_root: &Path) -> ResultEnvelope {
    command_branding_state_with(repo_root, &SystemCommandRunner)
}

pub(crate) fn command_branding_state_with(
    repo_root: &Path,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let items = branding_inventory(repo_root, runner);
    let summary = summarize_branding(&items);
    let active_count = summary["by_category"]["active_product_surface"]["count"]
        .as_u64()
        .unwrap_or_default();
    let unknown_count = summary["by_category"]["unknown"]["count"]
        .as_u64()
        .unwrap_or_default();
    let findings = vec![
        Finding::new("pass", "branding.inventory", format!("Classified {} branding/identity marker surface(s).", items.len())).with_details(summary.clone()),
        Finding::new(if active_count > 0 { "warn" } else { "pass" }, "branding.active-product-surface", if active_count > 0 { format!("{active_count} active product marker(s) still contain inherited OpenVAS/Greenbone/GSA identity wording.") } else { "No active product branding residue found in the scanned surfaces.".to_string() }).with_details(json!({ "paths": summary["by_category"]["active_product_surface"]["paths"] })),
        Finding::new(if unknown_count > 0 { "warn" } else { "pass" }, "branding.unknown", if unknown_count > 0 { format!("{unknown_count} branding marker surface(s) are not classified.") } else { "No branding marker surfaces were left unclassified.".to_string() }).with_details(json!({ "paths": summary["by_category"]["unknown"]["paths"] })),
        Finding::new("pass", "branding.provenance-boundary", "OpenVAS/Greenbone wording remains allowed in provenance, non-affiliation, and technical component contexts.".to_string()),
    ];
    make_result(metadata(repo_root, "branding-state", runner), "Branding and upstream-identity state collected.".to_string(), findings)
        .with_details(json!({ "items": items, "total_items": summary["total_items"], "by_category": summary["by_category"] }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::fs;

    struct TrackedRunner(&'static str);
    impl CommandRunner for TrackedRunner {
        fn run(&self, _program: &str, args: &[&str]) -> Option<ProcessOutput> {
            let stdout = if args.ends_with(&["ls-files", "-z"]) {
                self.0
            } else {
                ""
            };
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn classification_separates_provenance_and_active_surfaces() {
        assert_eq!(
            branding_category("README.md"),
            "provenance_or_non_affiliation"
        );
        assert_eq!(
            branding_category("components/gsa/public/locales/gsa-en.json"),
            "active_product_surface"
        );
        assert_eq!(
            branding_category("components/gsa/public/img/os_ipfire.svg"),
            "technical_doc_context"
        );
    }

    #[test]
    fn locale_lines_and_package_exception_match_reference() {
        assert_eq!(
            branding_locale_line_category("\"OpenVAS Scanner\": \"OpenVAS Scanner\","),
            "technical_doc_context"
        );
        assert_eq!(
            branding_locale_line_category("\"Greenbone Product\": \"Greenbone Product\","),
            "active_product_surface"
        );
        assert_eq!(
            branding_item_category("components/gsa/package.json", &["greenbone".to_string()]),
            "technical_doc_context"
        );
    }

    #[test]
    fn inventory_summary_is_deterministic() {
        let root = std::env::temp_dir().join(format!("yafvs-branding-{}", std::process::id()));
        let _ = fs::create_dir_all(root.join("docs"));
        fs::write(root.join("README.md"), "OpenVAS provenance").unwrap();
        fs::write(root.join("docs/example.md"), "Greenbone docs").unwrap();
        let tracked = "docs/example.md\0README.md\0";
        let first = command_branding_state_with(&root, &TrackedRunner(tracked));
        let second = command_branding_state_with(&root, &TrackedRunner(tracked));
        assert_eq!(first.details, second.details);
        let _ = fs::remove_dir_all(root);
    }
}
