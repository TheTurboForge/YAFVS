// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{iso_system_time, metadata, runtime_dir};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::Path;

const FEED_RELEASE: &str = "22.04";

struct FeedClass {
    key: &'static str,
    label: &'static str,
    relative_path: &'static str,
    markers: &'static [&'static str],
}

pub fn command_runtime_feed_import_init(repo_root: &Path) -> ResultEnvelope {
    make_result(
        metadata(
            repo_root,
            "runtime-feed-import-init",
            &SystemCommandRunner,
        ),
        "Feed import stopped outside the guarded generation-activation boundary.".to_string(),
        vec![Finding::new(
            "fail",
            "feed.import.activation-boundary",
            "Standalone feed import is disabled; use feed-generation-activate or feed-generation-rollback."
                .to_string(),
        )],
    )
    .with_artifacts(vec![
        runtime_dir(repo_root).join("feed-store").display().to_string(),
    ])
}

pub fn command_feed_copy_to_runtime(repo_root: &Path) -> ResultEnvelope {
    make_result(
        metadata(
            repo_root,
            "feed-copy-to-runtime",
            &SystemCommandRunner,
        ),
        "Legacy live feed copying is disabled; stage and activate a verified immutable generation."
            .to_string(),
        vec![Finding::new(
            "fail",
            "feed.copy.activation-boundary",
            "Sequential rsync into live consumer paths is unsafe; use feed-generation-stage followed by feed-generation-activate."
                .to_string(),
        )],
    )
    .with_artifacts(vec![
        runtime_dir(repo_root).join("feed-store").display().to_string(),
    ])
}

const FEED_CLASSES: [FeedClass; 5] = [
    FeedClass {
        key: "nasl",
        label: "NASL vulnerability tests",
        relative_path: "openvas/plugins",
        markers: &["plugin_feed_info.inc", "LICENSE"],
    },
    FeedClass {
        key: "notus",
        label: "Notus advisories",
        relative_path: "notus",
        markers: &[
            "advisories/sha256sums",
            "advisories/sha256sums.asc",
            "products/sha256sums",
            "products/sha256sums.asc",
        ],
    },
    FeedClass {
        key: "scap",
        label: "SCAP data",
        relative_path: "gvm/scap-data",
        markers: &["COPYING", "feed.xml", "timestamp"],
    },
    FeedClass {
        key: "cert",
        label: "CERT data",
        relative_path: "gvm/cert-data",
        markers: &["COPYING.CERT-BUND", "COPYING.DFN-CERT", "feed.xml"],
    },
    FeedClass {
        key: "gvmd",
        label: "GVMD data objects",
        relative_path: "gvm/data-objects/gvmd/22.04",
        markers: &[
            "LICENSE",
            "feed.xml",
            "timestamp",
            "scan-configs",
            "report-formats",
            "port-lists",
        ],
    },
];

#[derive(Debug, Serialize)]
struct MarkerState {
    path: String,
    exists: bool,
}

#[derive(Debug, Serialize)]
struct FeedPathSummary {
    exists: bool,
    file_count: u64,
    byte_count: u64,
    latest_mtime: Option<String>,
    markers: Vec<MarkerState>,
    errors: Vec<String>,
}

pub fn command_feed_state(repo_root: &Path) -> ResultEnvelope {
    command_feed_state_with(repo_root, &SystemCommandRunner)
}

fn command_feed_state_with(repo_root: &Path, runner: &dyn CommandRunner) -> ResultEnvelope {
    let runtime = runtime_dir(repo_root);
    let cache_root = runtime
        .join("feed-cache/community")
        .join(FEED_RELEASE)
        .join("var-lib");
    let active_root = runtime.join("feed-store/current");
    let mut findings = feed_location_findings("cache", &cache_root);
    findings.extend(feed_location_findings("runtime", &active_root));
    make_result(
        metadata(repo_root, "feed-state", runner),
        "Feed cache and runtime copy state collected.".to_string(),
        findings,
    )
    .with_artifacts(vec![
        cache_root.display().to_string(),
        active_root.display().to_string(),
    ])
}

fn feed_location_findings(location: &str, root: &Path) -> Vec<Finding> {
    let mut findings = vec![
        Finding::new(
            if root.is_dir() { "pass" } else { "warn" },
            &format!("feed.{location}.root"),
            format!(
                "{location} feed root {}.",
                if root.is_dir() {
                    "exists"
                } else {
                    "is missing"
                }
            ),
        )
        .with_path(&root.display().to_string()),
    ];
    for feed_class in &FEED_CLASSES {
        let path = root.join(feed_class.relative_path);
        let summary = feed_path_summary(&path, feed_class.markers);
        let missing_markers = summary
            .markers
            .iter()
            .filter(|marker| !marker.exists)
            .map(|marker| marker.path.clone())
            .collect::<Vec<_>>();
        let status = if summary.exists
            && summary.file_count > 0
            && missing_markers.is_empty()
            && summary.errors.is_empty()
        {
            "pass"
        } else {
            "warn"
        };
        let message = if !summary.exists {
            format!("{} directory is missing.", feed_class.label)
        } else if summary.file_count == 0 {
            format!(
                "{} directory exists but contains no files.",
                feed_class.label
            )
        } else if !missing_markers.is_empty() {
            format!(
                "{} has files but expected markers are missing.",
                feed_class.label
            )
        } else if !summary.errors.is_empty() {
            format!(
                "{} state has filesystem inspection errors.",
                feed_class.label
            )
        } else {
            format!("{} is present.", feed_class.label)
        };
        findings.push(
            Finding::new(
                status,
                &format!("feed.{location}.{}", feed_class.key),
                message,
            )
            .with_path(&path.display().to_string())
            .with_details(json!({
                "summary": summary,
                "missing_markers": missing_markers,
            })),
        );
    }
    findings
}

fn feed_path_summary(path: &Path, markers: &[&str]) -> FeedPathSummary {
    let mut file_count = 0;
    let mut byte_count = 0;
    let mut latest_mtime = None;
    let mut errors = Vec::new();
    if path.is_dir() {
        inspect_directory(
            path,
            &mut file_count,
            &mut byte_count,
            &mut latest_mtime,
            &mut errors,
        );
    }
    FeedPathSummary {
        exists: path.is_dir(),
        file_count,
        byte_count,
        latest_mtime: latest_mtime.and_then(iso_system_time),
        markers: markers
            .iter()
            .map(|marker| MarkerState {
                path: (*marker).to_string(),
                exists: path.join(marker).exists(),
            })
            .collect(),
        errors: errors.into_iter().take(20).collect(),
    }
}

fn inspect_directory(
    root: &Path,
    file_count: &mut u64,
    byte_count: &mut u64,
    latest_mtime: &mut Option<std::time::SystemTime>,
    errors: &mut Vec<String>,
) {
    let mut entries = match fs::read_dir(root) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) => {
            errors.push(format!("{}: {error}", root.display()));
            return;
        }
    };
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                errors.push(format!("{}: {error}", path.display()));
                continue;
            }
        };
        if file_type.is_dir() {
            inspect_directory(&path, file_count, byte_count, latest_mtime, errors);
        } else if path.is_file() {
            match fs::metadata(&path) {
                Ok(metadata) => {
                    *file_count += 1;
                    *byte_count += metadata.len();
                    if let Ok(modified) = metadata.modified()
                        && latest_mtime.is_none_or(|latest| modified > latest)
                    {
                        *latest_mtime = Some(modified);
                    }
                }
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn fixture_root() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "yafvsctl-feed-state-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("TurboVAS");
        fs::create_dir_all(&repo).unwrap();
        repo
    }

    #[test]
    fn missing_feed_roots_are_warnings() {
        let repo = fixture_root();
        let result = command_feed_state(&repo);
        assert_eq!(result.status, "warn");
        assert_eq!(result.findings.len(), 12);
        assert_eq!(result.findings[0].check, "feed.cache.root");
        assert_eq!(result.findings[6].check, "feed.runtime.root");
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }

    #[test]
    fn summarizes_files_and_markers() {
        let repo = fixture_root();
        let plugins = repo
            .parent()
            .unwrap()
            .join("TurboVAS-runtime/feed-cache/community/22.04/var-lib/openvas/plugins");
        fs::create_dir_all(&plugins).unwrap();
        fs::write(plugins.join("plugin_feed_info.inc"), b"info").unwrap();
        fs::write(plugins.join("LICENSE"), b"license").unwrap();
        let summary = feed_path_summary(&plugins, FEED_CLASSES[0].markers);
        assert!(summary.exists);
        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.byte_count, 11);
        assert!(summary.markers.iter().all(|marker| marker.exists));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }
}
