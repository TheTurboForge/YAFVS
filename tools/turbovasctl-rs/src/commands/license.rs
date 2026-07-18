// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{git_tracked_files, metadata, run_git};
use super::repository::component_specs;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const IMPORT_BASELINE_COMMIT: &str = "def84d156dd45c27cad0a75bc2302ce151585d3c";
const TURBOVAS_MODIFICATION_NOTICE: &str =
    "TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.";
const COMMENT_NOTICE_SUFFIXES: &[&str] = &[
    "c", "h", "js", "jsx", "ts", "tsx", "py", "cmake", "rs", "sh", "sql", "xml", "in", "md", "txt",
    "toml", "yml", "yaml",
];
const COMMENT_NOTICE_NAMES: &[&str] = &["Makefile", ".dockerignore", ".gitignore"];
const IMPORTED_ADDED_PREFIXES: &[&str] = &["components/pg-gvm/"];
const FEED_CONTENT_TRACKED_PREFIXES: &[&str] = &[
    "TurboVAS-runtime/",
    "feed-cache/",
    "feeds/openvas/plugins/",
    "feeds/notus/",
    "feeds/gvm/scap-data/",
    "feeds/gvm/cert-data/",
    "feeds/gvm/data-objects/",
];
const PUBLIC_READINESS_LICENSE_ITEMS: &[&str] = &[
    "source-public license/provenance boundary for original TurboVAS-only files and docs",
    "AGPL source-publication procedure for network services",
    "openvas-smb Samba-derived provenance documentation",
    "Greenbone Community Feed source-public boundary without feed bundling or redistribution",
    "Greenbone non-affiliation, trademark, and residual branding review",
    "release-time secret scan, attribution review, and source-publication evidence checklist",
];
const ENTERPRISE_FEED_KEY_UNSUPPORTED_MARKERS: &[&str] = &[
    "--greenbone-enterprise-feed-key",
    "greenbone-enterprise-feed-key",
    "GREENBONE_FEED_SYNC_ENTERPRISE_FEED_KEY",
    "DEFAULT_ENTERPRISE_KEY_PATH",
    "EnterpriseSettings",
];
const ENTERPRISE_FEED_KEY_SUPPORT_SCAN_PATHS: &[&str] = &[
    "components/greenbone-feed-sync/greenbone/feed/sync/config.py",
    "components/greenbone-feed-sync/greenbone/feed/sync/parser.py",
    "components/greenbone-feed-sync/greenbone/feed/sync/main.py",
    "components/greenbone-feed-sync/README.md",
    "README.md",
    "UPSTREAMS.md",
    "LICENSE_AUDIT.md",
    "docs/CHANGES_FROM_UPSTREAM.md",
    "docs/USER_MANUAL.md",
    "docs/PUBLIC_RELEASE_READINESS.md",
];

#[derive(Debug, Clone)]
struct NameStatus {
    status: String,
    source_path: Option<String>,
    path: String,
}

pub fn command_license_report(
    repo_root: &Path,
    public_release: bool,
    mode: &str,
    diff_scope: &str,
    modified_imported_only: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_license_report_with_runner(
        repo_root,
        public_release,
        mode,
        diff_scope,
        modified_imported_only,
        status_only,
        &SystemCommandRunner,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn command_license_report_with_runner(
    repo_root: &Path,
    public_release: bool,
    mode: &str,
    diff_scope: &str,
    modified_imported_only: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    if modified_imported_only {
        let rows = git_name_status_for_scope(runner, repo_root, diff_scope, &["components"]);
        let baseline_rows =
            git_name_status(runner, repo_root, IMPORT_BASELINE_COMMIT, &["components"]);
        let findings = modified_imported_license_findings(
            repo_root,
            rows.as_deref(),
            diff_scope,
            diff_scope == "baseline",
            &notice_exempt_paths(baseline_rows.as_deref()),
            runner,
        );
        let mut result = make_result(
            metadata(repo_root, "license-report", runner),
            "Modified imported file license/provenance checks completed.".to_string(),
            findings,
        )
        .with_details(json!({
            "diff_scope": diff_scope,
            "modified_imported_only": true,
        }));
        if status_only {
            result = license_status_only_result(result);
        }
        return result;
    }

    if diff_scope != "baseline" {
        let mut result =
            make_result(
                metadata(repo_root, "license-report", runner),
                "License/provenance checks completed.".to_string(),
                vec![Finding::new(
                "fail",
                "license.diff-scope",
                "Non-baseline diff scopes are only supported with --modified-imported-only."
                    .to_string(),
            )
            .with_details(json!({ "diff_scope": diff_scope }))],
            );
        if status_only {
            result = license_status_only_result(result);
        }
        return result;
    }

    let mut findings = Vec::new();
    for component in component_specs() {
        for license_file in component.licenses {
            let relative = format!("{}/{}", component.path, license_file);
            findings.push(
                Finding::new(
                    if repo_root.join(&relative).is_file() {
                        "pass"
                    } else {
                        "fail"
                    },
                    "license.file",
                    format!("{}: expected {license_file}", component.name),
                )
                .with_path(&relative),
            );
        }
    }

    let all_rows = git_name_status(runner, repo_root, IMPORT_BASELINE_COMMIT, &[]);
    let rows = git_name_status(runner, repo_root, IMPORT_BASELINE_COMMIT, &["components"]);
    let notice_exempt = notice_exempt_paths(rows.as_deref());
    match rows.as_deref() {
        Some(rows) => findings.extend(modified_imported_license_findings(
            repo_root,
            Some(rows),
            "baseline",
            true,
            &notice_exempt,
            runner,
        )),
        None => findings.push(Finding::new(
            "fail",
            "license.git-history",
            format!("Could not compare against import baseline {IMPORT_BASELINE_COMMIT}."),
        )),
    }
    for scope in ["staged", "worktree"] {
        let transient = git_name_status_for_scope(runner, repo_root, scope, &["components"]);
        findings.extend(modified_imported_license_findings(
            repo_root,
            transient.as_deref(),
            scope,
            false,
            &notice_exempt,
            runner,
        ));
    }

    match all_rows.as_deref() {
        Some(rows) => {
            let missing = added_turbovas_spdx_gaps(repo_root, rows);
            findings.push(
                Finding::new(
                    if missing.is_empty() { "pass" } else { "fail" },
                    "license.new-file-spdx",
                    if missing.is_empty() {
                        "New TurboVAS-created files have SPDX copyright and license headers."
                            .to_string()
                    } else {
                        "New TurboVAS-created files are missing SPDX copyright or license headers."
                            .to_string()
                    },
                )
                .with_details(json!({ "missing": missing })),
            );
        }
        None => findings.push(Finding::new(
            "fail",
            "license.new-file-spdx",
            format!(
                "Could not compare new files against import baseline {IMPORT_BASELINE_COMMIT}."
            ),
        )),
    }

    match git_tracked_files(runner, repo_root) {
        Some(paths) => {
            let tracked = paths
                .into_iter()
                .filter(|path| {
                    FEED_CONTENT_TRACKED_PREFIXES
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
                })
                .collect::<Vec<_>>();
            findings.push(
                Finding::new(
                    if tracked.is_empty() { "pass" } else { "fail" },
                    "license.feed-content-tracking",
                    if tracked.is_empty() {
                        "No runtime feed/cache content is tracked in Git.".to_string()
                    } else {
                        "Runtime feed/cache content appears to be tracked in Git.".to_string()
                    },
                )
                .with_details(json!({ "tracked_paths": tracked })),
            );
        }
        None => findings.push(Finding::new(
            "fail",
            "license.feed-content-tracking",
            "Could not list tracked files to verify feed content is untracked.".to_string(),
        )),
    }
    findings.push(enterprise_feed_key_support_finding(repo_root));
    findings.push(public_readiness_finding(public_release, mode));

    let mut result = make_result(
        metadata(repo_root, "license-report", runner),
        "License/provenance checks completed.".to_string(),
        findings,
    );
    if status_only {
        result = license_status_only_result(result);
    }
    result
}

fn git_name_status(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    base: &str,
    pathspecs: &[&str],
) -> Option<Vec<NameStatus>> {
    let range = format!("{base}..HEAD");
    let mut args = vec![
        "diff",
        "--find-renames",
        "--find-copies-harder",
        "-l0",
        "--name-status",
        range.as_str(),
    ];
    if !pathspecs.is_empty() {
        args.push("--");
        args.extend_from_slice(pathspecs);
    }
    run_git(runner, repo_root, &args).map(|output| parse_name_status(&output))
}

fn git_name_status_for_scope(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    scope: &str,
    pathspecs: &[&str],
) -> Option<Vec<NameStatus>> {
    if scope == "baseline" {
        return git_name_status(runner, repo_root, IMPORT_BASELINE_COMMIT, pathspecs);
    }
    let mut args = vec!["diff", "--find-renames", "--find-copies-harder", "-l0"];
    if scope == "staged" {
        args.push("--cached");
    } else if scope != "worktree" {
        return None;
    }
    args.push("--name-status");
    if !pathspecs.is_empty() {
        args.push("--");
        args.extend_from_slice(pathspecs);
    }
    run_git(runner, repo_root, &args).map(|output| parse_name_status(&output))
}

fn parse_name_status(output: &str) -> Vec<NameStatus> {
    output
        .lines()
        .filter_map(|line| {
            let parts = line.split('\t').collect::<Vec<_>>();
            (parts.len() >= 2).then(|| NameStatus {
                status: parts[0].to_string(),
                source_path: (parts.len() >= 3).then(|| parts[1].to_string()),
                path: parts[parts.len() - 1].to_string(),
            })
        })
        .collect()
}

fn notice_exempt_paths(rows: Option<&[NameStatus]>) -> BTreeSet<String> {
    let mut paths = turbovas_added_paths(rows);
    for row in rows.unwrap_or_default() {
        if (row.status.starts_with('R') || row.status.starts_with('C'))
            && imported_added_path(&row.path)
        {
            paths.insert(row.path.clone());
        }
    }
    paths
}

fn turbovas_added_paths(rows: Option<&[NameStatus]>) -> BTreeSet<String> {
    rows.unwrap_or_default()
        .iter()
        .filter(|row| row.status.starts_with('A') && !imported_added_path(&row.path))
        .map(|row| row.path.clone())
        .collect()
}

fn imported_added_path(path: &str) -> bool {
    IMPORTED_ADDED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn modified_imported_license_findings(
    repo_root: &Path,
    rows: Option<&[NameStatus]>,
    diff_scope: &str,
    check_manifest_stale: bool,
    turbovas_added: &BTreeSet<String>,
    runner: &dyn CommandRunner,
) -> Vec<Finding> {
    let Some(rows) = rows else {
        return vec![Finding::new(
            "fail",
            "license.git-history",
            format!("Could not collect modified imported files for diff scope {diff_scope}."),
        )];
    };
    let (missing, review) =
        modified_notice_gaps(repo_root, rows, diff_scope, turbovas_added, runner);
    let mut notice_details = Map::from_iter([
        ("diff_scope".to_string(), json!(diff_scope)),
        ("missing".to_string(), json!(missing)),
    ]);
    if diff_scope == "baseline" {
        notice_details.insert("baseline".to_string(), json!(IMPORT_BASELINE_COMMIT));
    }
    let mut findings = vec![
        Finding::new(
            if missing.is_empty() { "pass" } else { "fail" },
            "license.modified-imported-notices",
            if missing.is_empty() {
                "Modified imported files have TurboVAS modification notices.".to_string()
            } else {
                "Modified imported files are missing TurboVAS modification notices.".to_string()
            },
        )
        .with_details(Value::Object(notice_details)),
    ];
    let (documented, undocumented, stale) = no_comment_manifest_gaps(&review);
    let stale_failures = if check_manifest_stale {
        stale.clone()
    } else {
        Vec::new()
    };
    let clean = undocumented.is_empty() && stale_failures.is_empty();
    findings.push(
        Finding::new(
            if clean { "pass" } else { "fail" },
            "license.modified-imported-no-comment-manifest",
            if clean {
                "Modified imported no-comment files are explicitly recorded in the license manifest."
                    .to_string()
            } else {
                "Modified imported no-comment manifest is incomplete or stale.".to_string()
            },
        )
        .with_details(json!({
            "diff_scope": diff_scope,
            "documented": documented,
            "undocumented": undocumented,
            "stale": if check_manifest_stale { stale } else { Vec::<String>::new() },
            "stale_checked": check_manifest_stale,
            "manifest": no_comment_manifest(),
        })),
    );
    findings
}

fn modified_notice_gaps(
    repo_root: &Path,
    rows: &[NameStatus],
    diff_scope: &str,
    turbovas_added: &BTreeSet<String>,
    runner: &dyn CommandRunner,
) -> (Vec<String>, Vec<String>) {
    let mut missing = Vec::new();
    let mut review = Vec::new();
    for row in rows {
        if !(row.status.starts_with('M')
            || row.status.starts_with('R')
            || row.status.starts_with('C'))
            || turbovas_added.contains(&row.path)
            || row
                .source_path
                .as_ref()
                .is_some_and(|path| turbovas_added.contains(path))
        {
            continue;
        }
        let text = if diff_scope == "staged" {
            staged_file_head(runner, repo_root, &row.path)
        } else {
            let path = repo_root.join(&row.path);
            path.is_file().then(|| file_head(&path, 5_000))
        };
        let Some(text) = text else { continue };
        if text.contains(TURBOVAS_MODIFICATION_NOTICE) {
            continue;
        }
        if comment_notice_supported(&row.path) {
            missing.push(row.path.clone());
        } else {
            review.push(row.path.clone());
        }
    }
    (missing, review)
}

fn staged_file_head(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    relative_path: &str,
) -> Option<String> {
    let spec = format!(":{relative_path}");
    run_git(runner, repo_root, &["show", spec.as_str()])
        .map(|text| text.chars().take(5_000).collect())
}

fn no_comment_manifest_gaps(review: &[String]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let manifest_paths = no_comment_manifest()
        .keys()
        .map(|path| (*path).to_string())
        .collect::<BTreeSet<_>>();
    let review_paths = review.iter().cloned().collect::<BTreeSet<_>>();
    (
        review_paths
            .intersection(&manifest_paths)
            .cloned()
            .collect(),
        review_paths.difference(&manifest_paths).cloned().collect(),
        manifest_paths.difference(&review_paths).cloned().collect(),
    )
}

fn added_turbovas_spdx_gaps(repo_root: &Path, rows: &[NameStatus]) -> Vec<String> {
    rows.iter()
        .filter(|row| row.status.starts_with('A') && !imported_added_path(&row.path))
        .filter(|row| {
            let path = repo_root.join(&row.path);
            path.is_file() && !has_spdx_header(&path)
        })
        .map(|row| row.path.clone())
        .collect()
}

fn has_spdx_header(path: &Path) -> bool {
    let head = file_head(path, 2_000);
    head.contains("SPDX-FileCopyrightText:") && head.contains("SPDX-License-Identifier:")
}

fn file_head(path: &Path, limit: usize) -> String {
    fs::read(path)
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

fn comment_notice_supported(relative_path: &str) -> bool {
    let path = Path::new(relative_path);
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| COMMENT_NOTICE_NAMES.contains(&name))
        || path
            .extension()
            .and_then(|suffix| suffix.to_str())
            .is_some_and(|suffix| COMMENT_NOTICE_SUFFIXES.contains(&suffix))
}

fn enterprise_feed_key_support_finding(repo_root: &Path) -> Finding {
    let mut hits = Vec::new();
    let mut markers = ENTERPRISE_FEED_KEY_UNSUPPORTED_MARKERS.to_vec();
    markers.sort_by_key(|marker| std::cmp::Reverse(marker.len()));
    for relative in ENTERPRISE_FEED_KEY_SUPPORT_SCAN_PATHS {
        let path = repo_root.join(relative);
        if !path.is_file() {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(text) => {
                for (index, line) in text.lines().enumerate() {
                    if let Some(marker) = markers.iter().find(|marker| line.contains(**marker)) {
                        hits.push(json!({
                            "path": relative,
                            "line": index + 1,
                            "marker": marker,
                        }));
                    }
                }
            }
            Err(error) => hits.push(json!({
                "path": relative,
                "line": null,
                "marker": "<read-error>",
                "error": error.to_string(),
            })),
        }
    }
    Finding::new(
        if hits.is_empty() { "pass" } else { "fail" },
        "license.feed-enterprise-key-disabled",
        if hits.is_empty() {
            "Enterprise feed-key support is absent from live TurboVAS feed-sync source and public docs."
                .to_string()
        } else {
            "Enterprise feed-key support markers remain in live TurboVAS feed-sync source or public docs."
                .to_string()
        },
    )
    .with_details(json!({
        "markers": ENTERPRISE_FEED_KEY_UNSUPPORTED_MARKERS,
        "scan_paths": ENTERPRISE_FEED_KEY_SUPPORT_SCAN_PATHS,
        "hits": hits,
    }))
}

fn public_readiness_finding(public_release: bool, mode: &str) -> Finding {
    if !public_release {
        return Finding::new(
            "pass",
            "license.public-readiness",
            "Publication review items are tracked separately; run the source-public gate before changing repository visibility."
                .to_string(),
        )
        .with_details(json!({
            "review_items": PUBLIC_READINESS_LICENSE_ITEMS,
            "release_gate": false,
            "mode": null,
        }));
    }
    if mode == "source-public" {
        return Finding::new(
            "pass",
            "license.public-readiness.source-public",
            "Source-public license/provenance boundary is separated from stricter binary, container, hosted-service, and feed-redistribution modes."
                .to_string(),
        )
        .with_details(json!({
            "mode": mode,
            "release_gate": true,
            "pp_items": ["PP-001", "PP-002", "PP-003", "PP-004", "PP-007"],
            "accepted_scope": "public read access to source code only; no binaries, containers, hosted service, feed bundling, mirroring, or feed redistribution",
            "review_items": PUBLIC_READINESS_LICENSE_ITEMS,
        }));
    }
    Finding::new(
        "fail",
        &format!("license.public-readiness.{mode}"),
        format!(
            "Publication mode '{mode}' remains blocked; source-public readiness does not authorize this stricter mode."
        ),
    )
    .with_details(json!({
        "mode": mode,
        "release_gate": true,
        "pp_items": ["PP-001"],
        "blockers": publication_mode_blockers(mode),
    }))
}

fn publication_mode_blockers(mode: &str) -> &'static [&'static str] {
    match mode {
        "binary" => &[
            "binary/package source-offer procedure",
            "complete bundled dependency/license notices",
            "artifact signing and release provenance",
        ],
        "container" => &[
            "container image source-offer procedure",
            "image SBOM and bundled dependency review",
            "base image license/security review",
        ],
        "hosted" => &[
            "AGPL network-source offer for the deployed service",
            "production authentication, TLS, and first-login posture",
            "hosted-service privacy/security operating model",
        ],
        "feed-redistribution" => &[
            "Greenbone Community Feed terms review for mirroring, bundling, or redistribution",
            "feed-derived data publication decision",
            "separate feed attribution and redistribution procedure",
        ],
        _ => &["unknown publication mode"],
    }
}

fn license_status_only_result(mut result: ResultEnvelope) -> ResultEnvelope {
    let findings = std::mem::take(&mut result.findings);
    let finding_count = findings.len();
    let mut non_pass = findings
        .into_iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_license_finding)
        .collect::<Vec<_>>();
    let non_pass_count = non_pass.len();
    if non_pass.is_empty() {
        non_pass.push(Finding::new(
            "pass",
            "license.status-only",
            "License/provenance checks passed; no non-pass findings.".to_string(),
        ));
    }
    let previous = result.details.as_ref().and_then(Value::as_object);
    let diff_scope = previous
        .and_then(|details| details.get("diff_scope"))
        .cloned()
        .unwrap_or_else(|| json!("baseline"));
    let modified_imported_only = previous
        .and_then(|details| details.get("modified_imported_only"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    result.details = Some(json!({
        "diff_scope": diff_scope,
        "modified_imported_only": modified_imported_only,
        "finding_count": finding_count,
        "non_pass_count": non_pass_count,
    }));
    result.findings = non_pass;
    result
}

fn compact_license_finding(mut finding: Finding) -> Finding {
    if let Some(Value::Object(mut details)) = finding.details.take() {
        if let Some(Value::Object(manifest)) = details.remove("manifest") {
            details.insert("manifest_entry_count".to_string(), json!(manifest.len()));
        }
        finding.details = Some(Value::Object(details));
    }
    finding
}

fn no_comment_manifest() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "components/gsa/index.html",
            "HTML application shell served to browsers; a file-level modification comment would become runtime page content.",
        ),
        (
            "components/gsa/package-lock.json",
            "JSON dependency lockfile; comments would make the file invalid.",
        ),
        (
            "components/gsa/package.json",
            "JSON package manifest; comments would make the file invalid.",
        ),
        (
            "components/notus-scanner/poetry.lock",
            "Python dependency lockfile; comments would make the file invalid.",
        ),
        (
            "components/openvas-scanner/rust/Cargo.lock",
            "Rust dependency lockfile; comments would make the file invalid.",
        ),
        (
            "components/ospd-openvas/poetry.lock",
            "Python dependency lockfile; comments would make the file invalid.",
        ),
        (
            "components/gsa/public/img/enterprise-container.svg",
            "SVG browser asset; adding a text notice would alter the rendered asset payload.",
        ),
        (
            "components/gsa/public/img/favicon.svg",
            "SVG browser asset; adding a text notice would alter the rendered asset payload.",
        ),
        (
            "components/gsa/public/img/login-bottom.svg",
            "SVG browser asset; adding a text notice would alter the rendered asset payload.",
        ),
        (
            "components/gsa/public/img/login-top.svg",
            "SVG browser asset; adding a text notice would alter the rendered asset payload.",
        ),
        (
            "components/gsa/public/locales/gsa-ar.json",
            "JSON locale catalog; comments would make the file invalid.",
        ),
        (
            "components/gsa/public/locales/gsa-de.json",
            "JSON locale catalog; comments would make the file invalid.",
        ),
        (
            "components/gsa/public/locales/gsa-en.json",
            "JSON locale catalog; comments would make the file invalid.",
        ),
        (
            "components/gsa/public/locales/gsa-pt_BR.json",
            "JSON locale catalog; comments would make the file invalid.",
        ),
        (
            "components/gsa/public/locales/gsa-zh_CN.json",
            "JSON locale catalog; comments would make the file invalid.",
        ),
        (
            "components/gsa/public/locales/gsa-zh_TW.json",
            "JSON locale catalog; comments would make the file invalid.",
        ),
        (
            "components/gvm-libs/.docker/prod-oldstable.Dockerfile",
            "Dockerfile syntax/positioning is build-sensitive; a file-level notice could alter build semantics.",
        ),
        (
            "components/gvmd/docs/gvmd.8",
            "Generated manpage output; comments would alter generated artifact semantics.",
        ),
        (
            "components/gvmd/docs/gvmd.html",
            "Generated HTML documentation output; comments would alter generated artifact semantics.",
        ),
        (
            "components/openvas-scanner/rust/src/openvasd/config/snapshots/openvasd__config__tests__defaults.snap",
            "Generated insta snapshot; changing contents would alter test fixture semantics.",
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "turbovasctl-license-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, relative: &str, text: &str) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }

        fn populate_full_report_files(&self) {
            for component in component_specs() {
                for license in component.licenses {
                    self.write(&format!("{}/{}", component.path, license), "license\n");
                }
            }
            for relative in no_comment_manifest().keys() {
                self.write(relative, "{}\n");
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        baseline: String,
        staged: String,
        worktree: String,
        tracked: String,
    }

    impl FakeRunner {
        fn output(stdout: String) -> Option<ProcessOutput> {
            Some(ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Option<ProcessOutput> {
            assert_eq!(program, "git");
            self.calls
                .borrow_mut()
                .push(args.iter().map(|value| (*value).to_string()).collect());
            let tail = &args[2..];
            if tail == ["rev-parse", "--short", "HEAD"] {
                return Self::output("test-head\n".to_string());
            }
            if tail == ["ls-files", "-z"] {
                return Self::output(self.tracked.clone());
            }
            if tail.first() == Some(&"diff") {
                if tail.contains(&"--cached") {
                    return Self::output(self.staged.clone());
                }
                if tail.iter().any(|value| value.ends_with("..HEAD")) {
                    return Self::output(self.baseline.clone());
                }
                return Self::output(self.worktree.clone());
            }
            None
        }
    }

    fn finding<'a>(result: &'a ResultEnvelope, check: &str) -> &'a Finding {
        result
            .findings
            .iter()
            .find(|finding| finding.check == check)
            .unwrap()
    }

    #[test]
    fn comment_capable_paths_match_the_python_policy() {
        assert!(comment_notice_supported("src/main.rs"));
        assert!(comment_notice_supported("Makefile"));
        assert!(!comment_notice_supported("package.json"));
    }

    #[test]
    fn stricter_publication_modes_remain_blocked() {
        let finding = public_readiness_finding(true, "container");
        assert_eq!(finding.status, "fail");
        assert_eq!(finding.check, "license.public-readiness.container");
    }

    #[test]
    fn name_status_uses_the_destination_path_for_renames() {
        let rows = parse_name_status("R100\told.rs\tnew.rs\nM\tother.rs\n");
        assert_eq!(rows[0].status, "R100");
        assert_eq!(rows[0].source_path.as_deref(), Some("old.rs"));
        assert_eq!(rows[0].path, "new.rs");
        assert_eq!(rows[1].source_path, None);
    }

    #[test]
    fn project_created_component_file_stays_notice_exempt_after_rename() {
        let fixture = Fixture::new();
        let source = "components/gsa/src/TurboVASLogo.tsx";
        let destination = "components/gsa/src/YAFVSLogo.tsx";
        fixture.write(
            destination,
            "/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> */\n",
        );
        let rows = parse_name_status(&format!("R100\t{source}\t{destination}\n"));
        let exempt = BTreeSet::from([source.to_string()]);

        let (missing, review) = modified_notice_gaps(
            &fixture.root,
            &rows,
            "worktree",
            &exempt,
            &FakeRunner::default(),
        );

        assert!(missing.is_empty());
        assert!(review.is_empty());
    }

    #[test]
    fn modified_imported_worktree_scope_uses_exact_git_contract() {
        let fixture = Fixture::new();
        let relative = "components/gvmd/src/example.c";
        fixture.write(
            relative,
            "/* TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. */\n",
        );
        let runner = FakeRunner {
            worktree: format!("M\t{relative}\n"),
            ..FakeRunner::default()
        };
        let result = command_license_report_with_runner(
            &fixture.root,
            false,
            "source-public",
            "worktree",
            true,
            false,
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.details,
            Some(json!({
                "diff_scope": "worktree",
                "modified_imported_only": true,
            }))
        );
        let root = fixture.root.display().to_string();
        assert_eq!(
            runner.calls.borrow().as_slice(),
            [
                vec![
                    "-C",
                    &root,
                    "diff",
                    "--find-renames",
                    "--find-copies-harder",
                    "-l0",
                    "--name-status",
                    "--",
                    "components",
                ],
                vec![
                    "-C",
                    &root,
                    "diff",
                    "--find-renames",
                    "--find-copies-harder",
                    "-l0",
                    "--name-status",
                    &format!("{IMPORT_BASELINE_COMMIT}..HEAD"),
                    "--",
                    "components",
                ],
                vec!["-C", &root, "rev-parse", "--short", "HEAD"],
            ]
        );
    }

    #[test]
    fn missing_notice_fails_and_status_only_preserves_relative_evidence() {
        let fixture = Fixture::new();
        let relative = "components/gvmd/src/missing.c";
        fixture.write(relative, "int main(void) { return 0; }\n");
        let runner = FakeRunner {
            worktree: format!("M\t{relative}\n"),
            ..FakeRunner::default()
        };
        let result = command_license_report_with_runner(
            &fixture.root,
            false,
            "source-public",
            "worktree",
            true,
            true,
            &runner,
        );
        assert_eq!(result.status, "fail");
        let notice = finding(&result, "license.modified-imported-notices");
        assert_eq!(notice.status, "fail");
        assert_eq!(
            notice.details.as_ref().unwrap()["missing"],
            json!([relative])
        );
        assert_eq!(result.details.as_ref().unwrap()["non_pass_count"], 1);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn non_baseline_full_report_rejects_before_diff_or_file_inventory() {
        let fixture = Fixture::new();
        let runner = FakeRunner::default();
        let result = command_license_report_with_runner(
            &fixture.root,
            false,
            "source-public",
            "staged",
            false,
            false,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check, "license.diff-scope");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(&calls[0][2..], ["rev-parse", "--short", "HEAD"]);
    }

    #[test]
    fn full_report_covers_license_spdx_feed_marker_and_publication_contracts() {
        let fixture = Fixture::new();
        fixture.populate_full_report_files();
        fixture.write("README.md", "--greenbone-enterprise-feed-key\n");
        let baseline = no_comment_manifest()
            .keys()
            .map(|path| format!("M\t{path}\n"))
            .collect::<String>();
        let source_runner = FakeRunner {
            baseline: baseline.clone(),
            tracked: "feeds/openvas/plugins/tracked.nasl\0".to_string(),
            ..FakeRunner::default()
        };
        let source = command_license_report_with_runner(
            &fixture.root,
            true,
            "source-public",
            "baseline",
            false,
            false,
            &source_runner,
        );
        assert!(
            source
                .findings
                .iter()
                .filter(|item| item.check == "license.file")
                .all(|item| item.status == "pass")
        );
        assert_eq!(finding(&source, "license.new-file-spdx").status, "pass");
        assert_eq!(
            finding(&source, "license.feed-content-tracking").status,
            "fail"
        );
        assert_eq!(
            finding(&source, "license.feed-enterprise-key-disabled").status,
            "fail"
        );
        assert_eq!(
            finding(&source, "license.public-readiness.source-public").status,
            "pass"
        );

        let container_runner = FakeRunner {
            baseline,
            ..FakeRunner::default()
        };
        let container = command_license_report_with_runner(
            &fixture.root,
            true,
            "container",
            "baseline",
            false,
            false,
            &container_runner,
        );
        assert_eq!(
            finding(&container, "license.public-readiness.container").status,
            "fail"
        );
    }
}
