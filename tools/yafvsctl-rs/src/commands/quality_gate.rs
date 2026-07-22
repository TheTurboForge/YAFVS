// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{iso_system_time, metadata, runtime_dir};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Map, Value, json};
use std::fs;
use std::path::Path;

const QUALITY_GATE_ARTIFACT: &str = "quality-gate.json";
const QUALITY_GATE_HISTORY_PREFIX: &str = "quality-gate-";

pub fn command_quality_gate_state(repo_root: &Path, status_only: bool) -> ResultEnvelope {
    command_quality_gate_state_with(repo_root, status_only, &SystemCommandRunner)
}

fn command_quality_gate_state_with(
    repo_root: &Path,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let artifact_dir = runtime_dir(repo_root).join("artifacts/quality-gate");
    let latest_path = artifact_dir.join(QUALITY_GATE_ARTIFACT);
    let latest = read_json_object(&latest_path);
    let history = if artifact_dir.exists() {
        json_artifact_history(&artifact_dir)
    } else {
        Vec::new()
    };
    let recent_failures = history
        .iter()
        .filter(|entry| entry.get("status") == Some(&Value::String("fail".to_string())))
        .take(5)
        .cloned()
        .collect::<Vec<_>>();

    let mut details = Map::new();
    details.insert("artifact_dir".to_string(), json!(artifact_dir));
    details.insert("latest_artifact_path".to_string(), json!(latest_path));
    details.insert("history_count".to_string(), json!(history.len()));
    details.insert(
        "history".to_string(),
        Value::Array(history.iter().take(10).cloned().collect()),
    );
    details.insert(
        "recent_failures".to_string(),
        Value::Array(recent_failures.clone()),
    );

    let mut findings = Vec::new();
    let summary = if let Some(latest) = latest {
        let latest_status = latest
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let latest_details = json!({
            "status": latest_status,
            "summary": latest.get("summary").and_then(Value::as_str).unwrap_or(""),
            "generated_at": latest
                .get("metadata")
                .and_then(Value::as_object)
                .and_then(|metadata| metadata.get("generated_at"))
                .cloned()
                .unwrap_or(Value::Null),
            "artifact_path": latest_path,
        });
        details.insert("latest".to_string(), latest_details.clone());
        findings.push(
            Finding::new(
                if matches!(latest_status, "pass" | "warn" | "fail") {
                    latest_status
                } else {
                    "warn"
                },
                "quality-gate-state.latest",
                format!("Latest quality gate status is {latest_status}."),
            )
            .with_path(&latest_path.display().to_string())
            .with_details(json!({ "latest": latest_details })),
        );
        format!("Latest quality gate status is {latest_status}.")
    } else {
        findings.push(
            Finding::new(
                "warn",
                "quality-gate-state.latest",
                "No quality gate artifact has been written yet.".to_string(),
            )
            .with_path(&latest_path.display().to_string()),
        );
        "No quality gate history found.".to_string()
    };
    findings.push(
        Finding::new(
            "pass",
            "quality-gate-state.history",
            format!(
                "Quality gate history contains {} retained timestamped artifacts.",
                history.len()
            ),
        )
        .with_details(json!({
            "history_count": history.len(),
            "recent_failure_count": recent_failures.len(),
        })),
    );

    let artifacts = if latest_path.exists() {
        vec![latest_path.display().to_string()]
    } else {
        Vec::new()
    };
    let mut result = make_result(
        metadata(repo_root, "quality-gate-state", runner),
        summary,
        findings,
    )
    .with_artifacts(artifacts)
    .with_details(Value::Object(details));
    if status_only {
        compact_status_only(&mut result);
    }
    result
}

fn read_json_object(path: &Path) -> Option<Map<String, Value>> {
    let value = serde_json::from_slice::<Value>(&fs::read(path).ok()?).ok()?;
    value.as_object().cloned()
}

fn json_artifact_history(artifact_dir: &Path) -> Vec<Value> {
    let mut paths = fs::read_dir(artifact_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with(QUALITY_GATE_HISTORY_PREFIX) && name.ends_with(".json")
                })
        })
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    paths.into_iter().map(|path| history_entry(&path)).collect()
}

fn history_entry(path: &Path) -> Value {
    let payload = read_json_object(path).unwrap_or_default();
    json!({
        "path": path,
        "name": path.file_name().and_then(|name| name.to_str()).unwrap_or(""),
        "mtime": artifact_mtime(path).map(Value::String).unwrap_or(Value::Null),
        "generated_at": payload
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("generated_at"))
            .cloned()
            .unwrap_or(Value::Null),
        "status": payload.get("status").cloned().unwrap_or_else(|| json!("unknown")),
        "summary": payload.get("summary").cloned().unwrap_or_else(|| json!("")),
    })
}

fn artifact_mtime(path: &Path) -> Option<String> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    iso_system_time(modified)
}

fn compact_status_only(result: &mut ResultEnvelope) {
    let details = result.details.as_ref().and_then(Value::as_object);
    let latest = details
        .and_then(|details| details.get("latest"))
        .cloned()
        .unwrap_or(Value::Null);
    let history_count = details
        .and_then(|details| details.get("history_count"))
        .cloned()
        .unwrap_or_else(|| json!(0));
    let recent_failure_count = details
        .and_then(|details| details.get("recent_failures"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    result.details = Some(json!({
        "latest": latest,
        "history_count": history_count,
        "recent_failure_count": recent_failure_count,
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            "quality-gate-state.status-only",
            "Quality gate state passed; no non-pass findings.".to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn fixture_root() -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "yafvsctl-quality-state-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = base.join("YAFVS");
        let artifacts = base.join("YAFVS-runtime/artifacts/quality-gate");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&artifacts).unwrap();
        (repo, artifacts)
    }

    #[test]
    fn reports_missing_history_as_warning() {
        let (repo, artifacts) = fixture_root();
        let result = command_quality_gate_state(&repo, false);
        assert_eq!(result.status, "warn");
        assert_eq!(result.summary, "No quality gate history found.");
        assert_eq!(result.artifacts, Vec::<String>::new());
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
        assert!(!artifacts.exists());
    }

    #[test]
    fn compacts_passing_history() {
        let (repo, artifacts) = fixture_root();
        let payload = json!({
            "status": "pass",
            "summary": "gate passed",
            "metadata": {"generated_at": "2026-07-17T00:00:00+00:00"},
        });
        fs::write(
            artifacts.join(QUALITY_GATE_ARTIFACT),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        fs::write(
            artifacts.join("quality-gate-20260717T000000Z.json"),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();

        let result = command_quality_gate_state(&repo, true);
        assert_eq!(result.status, "pass");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check, "quality-gate-state.status-only");
        assert_eq!(result.details.as_ref().unwrap()["history_count"], json!(1));
        fs::remove_dir_all(repo.parent().unwrap()).unwrap();
    }
}
