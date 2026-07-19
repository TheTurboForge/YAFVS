// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

const COMMAND: &str = "native-empty-trash";
const PREVIEW_PATH: &str = "/api/v1/trashcan/empty-preview";
const EMPTY_PATH: &str = "/api/v1/trashcan/empty";
const SCOPE: &str = "operator";
const RESOURCE_TYPES: [&str; 12] = [
    "alerts",
    "configs",
    "credentials",
    "filters",
    "overrides",
    "port_lists",
    "report_formats",
    "scanners",
    "schedules",
    "tags",
    "targets",
    "tasks",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreviewItem {
    resource_type: String,
    count: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    scope: String,
    items: Vec<PreviewItem>,
    total: u64,
    snapshot_digest: String,
}

#[derive(Debug, Serialize)]
struct EmptyRequest<'a> {
    acknowledge_permanent_deletion: bool,
    expected_total: u64,
    expected_snapshot_digest: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyResponse {
    scope: String,
    deleted_total: u64,
}

pub fn command_native_empty_trash(
    root: &Path,
    allow_write_control: bool,
    acknowledge_permanent_deletion: bool,
    expected_total: Option<u64>,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        root,
        allow_write_control,
        acknowledge_permanent_deletion,
        expected_total,
        status_only,
        &SystemCommandRunner,
    )
}

fn command_with_runner(
    root: &Path,
    allow_write_control: bool,
    acknowledge_permanent_deletion: bool,
    expected_total: Option<u64>,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let mutation_intent =
        allow_write_control || acknowledge_permanent_deletion || expected_total.is_some();
    if mutation_intent
        && !(allow_write_control && acknowledge_permanent_deletion && expected_total.is_some())
    {
        let mut details = default_details(expected_total);
        details["outcome"] = json!("rejected");
        return result(
            root,
            runner,
            "Native Trashcan empty request was rejected before runtime access.",
            vec![Finding::new(
                "fail",
                "native-empty-trash.arguments",
                "permanent Trashcan deletion requires --allow-write-control, --acknowledge-permanent-deletion, and --expected-total N".into(),
            )],
            details,
            status_only,
        );
    }

    let mut call = |path: &str, method: &str, body: Option<&str>| {
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            body,
            "native-empty-trash.direct-config-shape",
            "native-empty-trash.direct-token-strength",
            runner,
        )
    };
    execute(
        root,
        mutation_intent,
        expected_total,
        status_only,
        runner,
        &mut call,
    )
}

fn execute<F>(
    root: &Path,
    mutation_intent: bool,
    expected_total: Option<u64>,
    status_only: bool,
    runner: &dyn CommandRunner,
    call: &mut F,
) -> ResultEnvelope
where
    F: FnMut(&str, &str, Option<&str>) -> Result<GuardedDirectApiCall, Vec<Finding>>,
{
    let mut findings = Vec::new();
    let mut details = default_details(expected_total);
    let preview_call = match call(PREVIEW_PATH, "GET", None) {
        Ok(call) => call,
        Err(findings) => {
            details["outcome"] = json!("rejected");
            return result(
                root,
                runner,
                "Native Trashcan empty request was rejected before runtime access.",
                findings,
                details,
                status_only,
            );
        }
    };
    let preview = trusted_preview(&preview_call);
    details["http_status"] = json!(preview_call.http_status);
    findings.push(preview_call.config);
    let preview = match preview {
        Some(preview) => preview,
        None => {
            details["outcome"] = json!("rejected");
            findings.push(
                Finding::new(
                    "fail",
                    "native-empty-trash.preview",
                    "Native API Trashcan preview failed or returned an unsafe payload; no deletion was attempted.".into(),
                )
                .with_details(json!({
                    "http_status": preview_call.http_status,
                    "oversized": preview_call.oversized,
                })),
            );
            return result(
                root,
                runner,
                "Native Trashcan empty request stopped because the fresh preview was not trustworthy.",
                findings,
                details,
                status_only,
            );
        }
    };

    details["scope"] = json!(preview.scope);
    details["preview_total"] = json!(preview.total);
    details["preview_item_count"] = json!(preview.items.len());
    details["preview_items"] = json!(preview.items);
    findings.push(
        Finding::new(
            "pass",
            "native-empty-trash.preview",
            format!(
                "Native API preview confirmed {} operator-owned Trashcan item(s).",
                preview.total
            ),
        )
        .with_details(json!({
            "scope": SCOPE,
            "items": preview.items,
            "total": preview.total,
        })),
    );

    if !mutation_intent {
        return result(
            root,
            runner,
            "Native Trashcan preview completed; no deletion was requested.",
            findings,
            details,
            status_only,
        );
    }

    let expected_total = expected_total.expect("mutation intent requires expected total");
    if expected_total != preview.total {
        details["outcome"] = json!("mismatch");
        findings.push(
            Finding::new(
                "fail",
                "native-empty-trash.expected-total-mismatch",
                "Expected Trashcan total does not match the fresh operator preview; no deletion was attempted.".into(),
            )
            .with_details(json!({
                "expected_total": expected_total,
                "preview_total": preview.total,
            })),
        );
        return result(
            root,
            runner,
            "Native Trashcan empty request rejected because the preview total changed.",
            findings,
            details,
            status_only,
        );
    }

    let request_body = serde_json::to_string(&EmptyRequest {
        acknowledge_permanent_deletion: true,
        expected_total,
        expected_snapshot_digest: &preview.snapshot_digest,
    })
    .expect("serializing a fixed Trashcan request cannot fail");
    let deletion = match call(EMPTY_PATH, "POST", Some(&request_body)) {
        Ok(call) => call,
        Err(mut rejected) => {
            details["outcome"] = json!("rejected");
            details["http_status"] = Value::Null;
            findings.append(&mut rejected);
            findings.push(Finding::new(
                "fail",
                "native-empty-trash.delete-rejected",
                "Native API Trashcan deletion was rejected before request execution; it was not retried.".into(),
            ));
            return result(
                root,
                runner,
                "Native Trashcan empty request was rejected before API execution.",
                findings,
                details,
                status_only,
            );
        }
    };
    details["http_status"] = json!(deletion.http_status);

    if let Some(deleted_total) = confirmed_deletion(&deletion, expected_total) {
        details["outcome"] = json!("confirmed");
        details["deleted_total"] = json!(deleted_total);
        findings.push(
            Finding::new(
                "pass",
                "native-empty-trash.delete-confirmed",
                format!(
                    "Native API permanently deleted the confirmed {deleted_total} operator-owned Trashcan item(s)."
                ),
            )
            .with_details(json!({
                "scope": SCOPE,
                "deleted_total": deleted_total,
            })),
        );
        return result(
            root,
            runner,
            "Native Trashcan empty request was confirmed.",
            findings,
            details,
            status_only,
        );
    }

    if confirmed_rejection(&deletion) {
        details["outcome"] = json!("rejected");
        findings.push(
            Finding::new(
                "fail",
                "native-empty-trash.delete-rejected",
                "Native API rejected the permanent Trashcan deletion; it was not retried.".into(),
            )
            .with_details(json!({"http_status": deletion.http_status})),
        );
        result(
            root,
            runner,
            "Native Trashcan empty request was rejected by the API.",
            findings,
            details,
            status_only,
        )
    } else {
        details["outcome"] = json!("indeterminate");
        findings.push(
            Finding::new(
                "fail",
                "native-empty-trash.delete-indeterminate",
                "Native Trashcan deletion outcome is indeterminate; the mutation was not retried."
                    .into(),
            )
            .with_details(json!({
                "http_status": deletion.http_status,
                "exit_code": deletion.output.exit_code,
                "oversized": deletion.oversized,
            })),
        );
        result(
            root,
            runner,
            "Native Trashcan empty request has an indeterminate outcome.",
            findings,
            details,
            status_only,
        )
    }
}

fn trusted_preview(call: &GuardedDirectApiCall) -> Option<Preview> {
    if call.oversized || !call.output.success || call.http_status != Some(200) {
        return None;
    }
    let preview = serde_json::from_value::<Preview>(call.parsed.clone()?).ok()?;
    if preview.scope != SCOPE
        || !is_snapshot_digest(&preview.snapshot_digest)
        || preview.items.len() != RESOURCE_TYPES.len()
    {
        return None;
    }
    let expected = RESOURCE_TYPES.into_iter().collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    let mut total = 0_u64;
    for item in &preview.items {
        if item.resource_type.is_empty() || !observed.insert(item.resource_type.as_str()) {
            return None;
        }
        total = total.checked_add(item.count)?;
    }
    (observed == expected && total == preview.total).then_some(preview)
}

fn is_snapshot_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn confirmed_deletion(call: &GuardedDirectApiCall, expected_total: u64) -> Option<u64> {
    if call.oversized
        || !call.output.success
        || !call
            .http_status
            .is_some_and(|status| (200..300).contains(&status))
    {
        return None;
    }
    let response = serde_json::from_value::<EmptyResponse>(call.parsed.clone()?).ok()?;
    (response.scope == SCOPE && response.deleted_total == expected_total)
        .then_some(response.deleted_total)
}

fn confirmed_rejection(call: &GuardedDirectApiCall) -> bool {
    !call.oversized
        && call.output.success
        && call
            .http_status
            .is_some_and(|status| (400..500).contains(&status))
        && call
            .parsed
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|value| value.get("error"))
            .is_some_and(Value::is_object)
}

fn default_details(expected_total: Option<u64>) -> Value {
    json!({
        "outcome": "preview",
        "scope": SCOPE,
        "preview_total": null,
        "preview_item_count": 0,
        "expected_total": expected_total,
        "deleted_total": null,
        "http_status": null,
    })
}

fn result(
    root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
    status_only: bool,
) -> ResultEnvelope {
    let mut result = make_result(metadata(root, COMMAND, runner), summary.into(), findings)
        .with_details(details);
    if status_only {
        compact_status_only(&mut result);
    }
    result
}

fn compact_status_only(result: &mut ResultEnvelope) {
    let details = result.details.as_ref().expect("details");
    result.details = Some(json!({
        "outcome": details["outcome"],
        "scope": details["scope"],
        "preview_total": details["preview_total"],
        "preview_item_count": details["preview_item_count"],
        "expected_total": details["expected_total"],
        "deleted_total": details["deleted_total"],
        "http_status": details["http_status"],
    }));
    result.findings = result
        .findings
        .iter()
        .filter(|finding| finding.status != "pass")
        .map(compact_finding)
        .collect();
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            "native-empty-trash.status-only",
            "Native Trashcan empty outcome summarized.".into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Runner(Mutex<Vec<String>>);

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _: &[&str]) -> Option<ProcessOutput> {
            self.0.lock().unwrap().push(program.into());
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }
    }

    fn api_call(body: Value, status: i64) -> GuardedDirectApiCall {
        GuardedDirectApiCall {
            output: ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            },
            parsed: Some(body),
            http_status: Some(status),
            oversized: false,
            config: Finding::new(
                "pass",
                "native-empty-trash.direct-config-shape",
                "ok".into(),
            ),
        }
    }

    fn preview(total: u64, digest: &str) -> Value {
        let mut items = RESOURCE_TYPES
            .into_iter()
            .map(|resource_type| json!({"resource_type": resource_type, "count": 0}))
            .collect::<Vec<_>>();
        items[0]["count"] = json!(total);
        json!({
            "scope": SCOPE,
            "items": items,
            "total": total,
            "snapshot_digest": digest,
        })
    }

    #[test]
    fn incomplete_mutation_intent_stops_before_runtime() {
        let runner = Runner::default();
        for (allow, acknowledge, expected) in [
            (true, false, Some(0)),
            (false, true, Some(0)),
            (true, true, None),
        ] {
            let result = command_with_runner(
                Path::new("/tmp"),
                allow,
                acknowledge,
                expected,
                false,
                &runner,
            );
            assert_eq!(result.status, "fail");
            assert_eq!(result.details.as_ref().unwrap()["outcome"], "rejected");
        }
        assert!(
            runner
                .0
                .lock()
                .unwrap()
                .iter()
                .all(|program| program == "git")
        );
    }

    #[test]
    fn preview_contract_requires_exact_counts_only_shape() {
        let valid = api_call(preview(3, &"a".repeat(64)), 200);
        assert_eq!(trusted_preview(&valid).unwrap().total, 3);

        let mut incomplete = preview(0, &"a".repeat(64));
        incomplete["items"].as_array_mut().unwrap().pop();
        assert!(trusted_preview(&api_call(incomplete, 200)).is_none());

        let mut duplicate = preview(0, &"a".repeat(64));
        duplicate["items"][1]["resource_type"] = json!("alerts");
        assert!(trusted_preview(&api_call(duplicate, 200)).is_none());

        let mut named = preview(0, &"a".repeat(64));
        named["items"][0]["name"] = json!("must-not-be-accepted");
        assert!(trusted_preview(&api_call(named, 200)).is_none());
        assert!(trusted_preview(&api_call(preview(0, &"A".repeat(64)), 200)).is_none());
    }

    #[test]
    fn preview_only_is_one_get_and_status_only_is_counts_only() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let result = execute(
            Path::new("/tmp"),
            false,
            None,
            true,
            &runner,
            &mut |path, method, body| {
                calls.lock().unwrap().push((
                    path.to_string(),
                    method.to_string(),
                    body.map(str::to_string),
                ));
                Ok(api_call(preview(2, &"a".repeat(64)), 200))
            },
        );
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(PREVIEW_PATH.into(), "GET".into(), None)]
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["outcome"], "preview");
        assert_eq!(result.details.as_ref().unwrap()["preview_total"], 2);
        assert_eq!(
            result.details.as_ref().unwrap()["preview_item_count"],
            RESOURCE_TYPES.len()
        );
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(!rendered.contains("snapshot_digest"));
        assert!(!rendered.contains("resource_type"));
    }

    #[test]
    fn expected_total_mismatch_never_posts() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let result = execute(
            Path::new("/tmp"),
            true,
            Some(1),
            false,
            &runner,
            &mut |path, method, _body| {
                calls.lock().unwrap().push(format!("{method} {path}"));
                Ok(api_call(preview(2, &"a".repeat(64)), 200))
            },
        );
        assert_eq!(*calls.lock().unwrap(), vec![format!("GET {PREVIEW_PATH}")]);
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["outcome"], "mismatch");
    }

    #[test]
    fn confirmed_delete_uses_fresh_digest_once_and_requires_exact_acknowledgement() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let mut responses = vec![
            api_call(preview(2, &"b".repeat(64)), 200),
            api_call(json!({"scope": SCOPE, "deleted_total": 2}), 200),
        ]
        .into_iter();
        let result = execute(
            Path::new("/tmp"),
            true,
            Some(2),
            false,
            &runner,
            &mut |path, method, body| {
                calls.lock().unwrap().push((
                    path.to_string(),
                    method.to_string(),
                    body.map(str::to_string),
                ));
                Ok(responses.next().unwrap())
            },
        );
        let calls = calls.into_inner().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            (&calls[0].0, &calls[0].1),
            (&PREVIEW_PATH.to_string(), &"GET".to_string())
        );
        assert_eq!(
            (&calls[1].0, &calls[1].1),
            (&EMPTY_PATH.to_string(), &"POST".to_string())
        );
        assert_eq!(
            serde_json::from_str::<Value>(calls[1].2.as_ref().unwrap()).unwrap(),
            json!({
                "acknowledge_permanent_deletion": true,
                "expected_total": 2,
                "expected_snapshot_digest": "b".repeat(64),
            })
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["outcome"], "confirmed");
        assert_eq!(result.details.as_ref().unwrap()["deleted_total"], 2);
    }

    #[test]
    fn successful_http_response_requires_exact_scope_total_and_shape() {
        for payload in [
            json!({"scope": "global", "deleted_total": 2}),
            json!({"scope": SCOPE, "deleted_total": 1}),
            json!({"scope": SCOPE, "deleted_total": 2, "extra": true}),
            json!({"scope": SCOPE}),
        ] {
            assert!(confirmed_deletion(&api_call(payload, 200), 2).is_none());
        }
        assert!(
            confirmed_deletion(
                &api_call(json!({"scope": SCOPE, "deleted_total": 2}), 201),
                2,
            )
            .is_some()
        );
    }

    #[test]
    fn delete_rejection_and_indeterminate_outcome_are_never_retried() {
        for (status, payload, expected_outcome, expected_check) in [
            (
                409,
                json!({"error":{"code":"conflict"}}),
                "rejected",
                "native-empty-trash.delete-rejected",
            ),
            (
                502,
                json!({"error":{"code":"mutation_outcome_indeterminate"}}),
                "indeterminate",
                "native-empty-trash.delete-indeterminate",
            ),
        ] {
            let runner = Runner::default();
            let calls = Mutex::new(Vec::new());
            let mut responses = vec![
                api_call(preview(0, &"c".repeat(64)), 200),
                api_call(payload, status),
            ]
            .into_iter();
            let result = execute(
                Path::new("/tmp"),
                true,
                Some(0),
                false,
                &runner,
                &mut |path, method, _body| {
                    calls.lock().unwrap().push(format!("{method} {path}"));
                    Ok(responses.next().unwrap())
                },
            );
            assert_eq!(calls.lock().unwrap().len(), 2);
            assert_eq!(result.status, "fail");
            assert_eq!(
                result.details.as_ref().unwrap()["outcome"],
                expected_outcome
            );
            assert_eq!(result.findings.last().unwrap().check, expected_check);
        }
    }

    #[test]
    fn unsafe_preview_stops_before_post() {
        let runner = Runner::default();
        let calls = Mutex::new(Vec::new());
        let result = execute(
            Path::new("/tmp"),
            true,
            Some(0),
            true,
            &runner,
            &mut |path, method, _body| {
                calls.lock().unwrap().push(format!("{method} {path}"));
                Ok(api_call(json!({"scope": SCOPE}), 200))
            },
        );
        assert_eq!(*calls.lock().unwrap(), vec![format!("GET {PREVIEW_PATH}")]);
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["outcome"], "rejected");
        assert_eq!(
            result.findings.last().unwrap().check,
            "native-empty-trash.preview"
        );
    }
}
