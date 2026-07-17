// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::process::CommandRunner;
use crate::result::{Finding, Metadata};
use serde_json::{Value, json};
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(crate) fn run_git(
    runner: &dyn CommandRunner,
    repo_root: &Path,
    args: &[&str],
) -> Option<String> {
    let root = repo_root.to_string_lossy();
    let mut git_args = vec!["-C", root.as_ref()];
    git_args.extend_from_slice(args);
    runner
        .run("git", &git_args)
        .and_then(|output| output.success.then(|| output.stdout.trim().to_string()))
}

pub(crate) fn compact_finding(finding: &Finding) -> Finding {
    let mut compact = Finding::new(&finding.status, &finding.check, finding.message.clone());
    if let Some(path) = &finding.path
        && !path.is_empty()
    {
        compact.path = Some(path.clone());
    }
    if let Some(Value::Object(details)) = &finding.details {
        let compact_details = details
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    Value::Array(items) => json!({ "type": "list", "count": items.len() }),
                    Value::Object(items) => {
                        json!({ "type": "object", "key_count": items.len() })
                    }
                    scalar => scalar.clone(),
                };
                (key.clone(), value)
            })
            .collect();
        compact.details = Some(Value::Object(compact_details));
    }
    compact
}

pub(crate) fn git_tracked_files(
    runner: &dyn CommandRunner,
    repo_root: &Path,
) -> Option<Vec<String>> {
    run_git(runner, repo_root, &["ls-files", "-z"]).map(|output| {
        let mut paths = output
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        paths.sort();
        paths
    })
}

pub(crate) fn metadata(repo_root: &Path, command: &str, runner: &dyn CommandRunner) -> Metadata {
    Metadata {
        command: command.to_string(),
        generated_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        repo_root: repo_root.display().to_string(),
        head: run_git(runner, repo_root, &["rev-parse", "--short", "HEAD"]),
    }
}
