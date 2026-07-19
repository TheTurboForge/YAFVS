// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::common::{compact_finding, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

const COMMAND: &str = "native-delete-overrides-by-filter";
#[cfg(test)]
const DEFAULT_MAX: usize = 100;
const MAX_LIMIT: usize = 500;
const PAGE_SIZE: usize = 500;
const MAX_PAGES: usize = 1_000;

#[allow(clippy::too_many_arguments)]
pub fn command_native_delete_overrides_by_filter(
    root: &Path,
    filter: &str,
    max_overrides: usize,
    dry_run: bool,
    allow_write_control: bool,
    confirm_snapshot: Option<&str>,
    delay_seconds: f64,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        root,
        filter,
        max_overrides,
        dry_run,
        allow_write_control,
        confirm_snapshot,
        delay_seconds,
        status_only,
        &SystemCommandRunner,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_with_runner(
    root: &Path,
    filter: &str,
    max_overrides: usize,
    dry_run: bool,
    allow_write_control: bool,
    confirm_snapshot: Option<&str>,
    delay_seconds: f64,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let filter = match validate_arguments(
        filter,
        max_overrides,
        dry_run,
        allow_write_control,
        confirm_snapshot,
        delay_seconds,
    ) {
        Ok(filter) => filter,
        Err(message) => {
            return result(
                root,
                runner,
                "Native filtered override deletion rejected before runtime access.",
                vec![Finding::new(
                    "fail",
                    "native-delete-overrides-by-filter.arguments",
                    message,
                )],
                default_details(max_overrides, dry_run, delay_seconds),
                status_only,
            );
        }
    };
    let mut call = |path: &str, method: &str| {
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            None,
            "native-delete-overrides-by-filter.direct-config-shape",
            "native-delete-overrides-by-filter.direct-token-strength",
            runner,
        )
    };
    let mut sleep = |seconds: f64| std::thread::sleep(Duration::from_secs_f64(seconds));
    execute(
        root,
        &filter,
        max_overrides,
        dry_run,
        confirm_snapshot,
        delay_seconds,
        status_only,
        runner,
        &mut call,
        &mut sleep,
    )
}

fn validate_arguments(
    filter: &str,
    max_overrides: usize,
    dry_run: bool,
    allow_write_control: bool,
    confirm_snapshot: Option<&str>,
    delay_seconds: f64,
) -> Result<String, String> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Err("--filter must be non-empty; broad unfiltered deletion is refused".into());
    }
    if filter.len() > 1_024 || filter.chars().any(char::is_control) {
        return Err("--filter must be one printable line up to 1024 bytes".into());
    }
    if !(1..=MAX_LIMIT).contains(&max_overrides) {
        return Err(format!("--max-overrides must be between 1 and {MAX_LIMIT}"));
    }
    if !delay_seconds.is_finite() || !(0.0..=60.0).contains(&delay_seconds) {
        return Err("--delay-seconds must be between 0 and 60".into());
    }
    if !dry_run && !allow_write_control {
        return Err("deleting overrides requires --allow-write-control".into());
    }
    if !dry_run && !confirm_snapshot.is_some_and(is_sha256) {
        return Err(
            "deleting overrides requires --confirm-snapshot with the SHA-256 from a fresh --dry-run"
                .into(),
        );
    }
    Ok(filter.to_string())
}

#[allow(clippy::too_many_arguments)]
fn execute<F, S>(
    root: &Path,
    filter: &str,
    max_overrides: usize,
    dry_run: bool,
    confirm_snapshot: Option<&str>,
    delay_seconds: f64,
    status_only: bool,
    runner: &dyn CommandRunner,
    call: &mut F,
    sleep: &mut S,
) -> ResultEnvelope
where
    F: FnMut(&str, &str) -> Result<GuardedDirectApiCall, Vec<Finding>>,
    S: FnMut(f64),
{
    let mut details = default_details(max_overrides, dry_run, delay_seconds);
    let (override_ids, config) = match fetch_snapshot(filter, max_overrides, call) {
        Ok(snapshot) => snapshot,
        Err((findings, reason)) => {
            return result(
                root,
                runner,
                "Native filtered override deletion stopped during snapshot collection.",
                findings
                    .into_iter()
                    .chain([Finding::new(
                        "fail",
                        "native-delete-overrides-by-filter.snapshot",
                        "Native override snapshot failed; no deletes were attempted.".into(),
                    )
                    .with_details(reason)])
                    .collect(),
                details,
                status_only,
            );
        }
    };
    let (filter_sha256, snapshot_sha256) = snapshot_hashes(filter, &override_ids);
    details["filter"] = json!(filter);
    details["filter_sha256"] = json!(filter_sha256);
    details["snapshot_sha256"] = json!(snapshot_sha256);
    details["matched_count"] = json!(override_ids.len());
    details["override_ids"] = json!(override_ids);
    let mut findings = vec![
        config,
        Finding::new(
            "pass",
            "native-delete-overrides-by-filter.snapshot",
            format!(
                "Snapshotted {} override UUID(s) deterministically.",
                override_ids.len()
            ),
        )
        .with_details(json!({
            "matched_count": override_ids.len(),
            "filter_sha256": filter_sha256,
            "snapshot_sha256": snapshot_sha256,
        })),
    ];
    if dry_run {
        return result(
            root,
            runner,
            "Native filtered override deletion dry run completed; no writes were attempted.",
            findings,
            details,
            status_only,
        );
    }
    if !confirm_snapshot.is_some_and(|value| value.eq_ignore_ascii_case(&snapshot_sha256)) {
        findings.push(
            Finding::new(
                "fail",
                "native-delete-overrides-by-filter.snapshot-confirmation",
                "Confirmed snapshot does not match the fresh native override snapshot; no deletes were attempted.".into(),
            )
            .with_details(json!({"expected_snapshot_sha256": snapshot_sha256})),
        );
        return result(
            root,
            runner,
            "Native filtered override deletion rejected because the snapshot changed.",
            findings,
            details,
            status_only,
        );
    }
    findings.push(Finding::new(
        "pass",
        "native-delete-overrides-by-filter.snapshot-confirmation",
        "Confirmed snapshot matches the fresh native override snapshot.".into(),
    ));

    for (index, override_id) in override_ids.iter().enumerate() {
        let path = format!("/api/v1/overrides/{override_id}");
        let (status, http_status, exit_code, oversized) = match call(&path, "DELETE") {
            Ok(delete) if confirmed_delete(&delete) => {
                details["deleted_count"] = json!(count(&details, "deleted_count") + 1);
                (
                    "deleted",
                    delete.http_status,
                    delete.output.exit_code,
                    delete.oversized,
                )
            }
            Ok(delete) if confirmed_rejection(&delete) => {
                details["failure_count"] = json!(count(&details, "failure_count") + 1);
                (
                    "rejected",
                    delete.http_status,
                    delete.output.exit_code,
                    delete.oversized,
                )
            }
            Ok(delete) => {
                details["failure_count"] = json!(count(&details, "failure_count") + 1);
                details["indeterminate_count"] = json!(count(&details, "indeterminate_count") + 1);
                (
                    "indeterminate",
                    delete.http_status,
                    delete.output.exit_code,
                    delete.oversized,
                )
            }
            Err(_) => {
                details["failure_count"] = json!(count(&details, "failure_count") + 1);
                ("rejected-before-execution", None, None, false)
            }
        };
        details["rows"]
            .as_array_mut()
            .expect("rows are an array")
            .push(json!({
                "override_id": override_id,
                "status": status,
                "http_status": http_status,
            }));
        let accepted = status == "deleted";
        findings.push(
            Finding::new(
                if accepted { "pass" } else { "fail" },
                &format!("native-delete-overrides-by-filter.override.{override_id}"),
                if accepted {
                    "Native API moved the override to trash.".into()
                } else if status == "indeterminate" {
                    "Native override trash move outcome is indeterminate; the mutation was not retried and remaining exact snapshot rows continue.".into()
                } else {
                    "Native API rejected the override trash move; it was not retried and remaining exact snapshot rows continue.".into()
                },
            )
            .with_details(json!({
                "override_id": override_id,
                "outcome": status,
                "http_status": http_status,
                "exit_code": exit_code,
                "oversized": oversized,
            })),
        );
        if delay_seconds > 0.0 && index + 1 < override_ids.len() {
            sleep(delay_seconds);
        }
    }

    let failures = count(&details, "failure_count");
    let deleted = count(&details, "deleted_count");
    let summary = if failures == 0 {
        format!("Native filtered override deletion moved all {deleted} override(s) to trash.")
    } else {
        format!(
            "Native filtered override deletion completed with {failures} failure(s); {deleted} override(s) moved to trash."
        )
    };
    result(root, runner, &summary, findings, details, status_only)
}

fn fetch_snapshot<F>(
    filter: &str,
    max_overrides: usize,
    call: &mut F,
) -> Result<(Vec<String>, Finding), (Vec<Finding>, Value)>
where
    F: FnMut(&str, &str) -> Result<GuardedDirectApiCall, Vec<Finding>>,
{
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    let mut expected_total = None;
    let mut config = None;
    for page in 1..=MAX_PAGES {
        let path = format!(
            "/api/v1/overrides?filter={}&page={page}&page_size={PAGE_SIZE}&sort=id",
            percent_encode(filter)
        );
        let response = match call(&path, "GET") {
            Ok(response) => response,
            Err(findings) => {
                return Err((
                    findings,
                    json!({"reason": "direct API guard rejected snapshot request", "page": page}),
                ));
            }
        };
        if config.is_none() {
            config = Some(response.config);
        }
        let parsed = response.parsed.as_ref().and_then(Value::as_object);
        let items = parsed
            .and_then(|value| value.get("items"))
            .and_then(Value::as_array);
        let page_info = parsed
            .and_then(|value| value.get("page"))
            .and_then(Value::as_object);
        let total = page_info
            .and_then(|value| value.get("total"))
            .and_then(Value::as_u64);
        let actual_page = page_info
            .and_then(|value| value.get("page"))
            .and_then(Value::as_u64);
        let page_ids = items.and_then(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_object()
                        .and_then(|value| value.get("id"))
                        .and_then(Value::as_str)
                        .filter(|id| validate_operator_uuid(id, "override id").is_ok())
                        .map(str::to_string)
                })
                .collect::<Option<Vec<_>>>()
        });
        let page_ok = response.output.success
            && !response.oversized
            && response.http_status == Some(200)
            && total.is_some()
            && actual_page == Some(page as u64)
            && page_ids.is_some()
            && expected_total.is_none_or(|expected| total == Some(expected));
        if !page_ok {
            return Err((
                config.into_iter().collect(),
                json!({
                    "reason": "override snapshot page was invalid, duplicated, or changed during pagination",
                    "page": page,
                    "http_status": response.http_status,
                    "expected_total": expected_total,
                    "observed_total": total,
                    "oversized": response.oversized,
                }),
            ));
        }
        let total = total.expect("validated total");
        let page_ids = page_ids.expect("validated ids");
        if expected_total.is_none() {
            if total > max_overrides as u64 {
                return Err((
                    config.into_iter().collect(),
                    json!({
                        "reason": "matched override count exceeds safety cap",
                        "total": total,
                        "max_overrides": max_overrides,
                    }),
                ));
            }
            expected_total = Some(total);
        }
        if page_ids.len() != page_ids.iter().collect::<BTreeSet<_>>().len()
            || page_ids.iter().any(|id| seen.contains(id))
        {
            return Err((
                config.into_iter().collect(),
                json!({
                    "reason": "override snapshot page was invalid, duplicated, or changed during pagination",
                    "page": page,
                    "expected_total": expected_total,
                    "observed_total": total,
                }),
            ));
        }
        if page_ids.is_empty() && ids.len() as u64 != total {
            return Err((
                config.into_iter().collect(),
                json!({
                    "reason": "override snapshot ended before declared total",
                    "page": page,
                    "total": total,
                }),
            ));
        }
        seen.extend(page_ids.iter().cloned());
        ids.extend(page_ids);
        if ids.len() as u64 == total {
            ids.sort();
            return Ok((
                ids,
                config.expect("successful API call provides config finding"),
            ));
        }
        if ids.len() as u64 > total {
            return Err((
                config.into_iter().collect(),
                json!({
                    "reason": "override snapshot exceeded declared total",
                    "page": page,
                    "total": total,
                }),
            ));
        }
    }
    Err((
        config.into_iter().collect(),
        json!({
            "reason": "override snapshot pagination exceeded safety limit",
            "total": expected_total,
        }),
    ))
}

fn snapshot_hashes(filter: &str, ids: &[String]) -> (String, String) {
    let filter_sha256 = hex_sha256(filter.as_bytes());
    let mut sorted_ids = ids.to_vec();
    sorted_ids.sort();
    let payload = serde_json::to_string(&json!({
        "filter_sha256": filter_sha256,
        "override_ids": sorted_ids,
    }))
    .expect("fixed snapshot payload is serializable");
    let snapshot_sha256 = hex_sha256(payload.as_bytes());
    (filter_sha256, snapshot_sha256)
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn percent_encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
                (*byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn confirmed_delete(call: &GuardedDirectApiCall) -> bool {
    !call.oversized && call.output.success && call.http_status == Some(204)
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

fn count(details: &Value, key: &str) -> u64 {
    details[key].as_u64().unwrap_or(0)
}

fn default_details(max_overrides: usize, dry_run: bool, delay_seconds: f64) -> Value {
    json!({
        "filter_sha256": null,
        "snapshot_sha256": null,
        "matched_count": 0,
        "max_overrides": max_overrides,
        "dry_run": dry_run,
        "delay_seconds": delay_seconds,
        "deleted_count": 0,
        "failure_count": 0,
        "indeterminate_count": 0,
        "rows": [],
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
    let failures = details["failure_count"].as_u64().unwrap_or(0);
    let compact_details = json!({
        "filter_sha256": details["filter_sha256"],
        "snapshot_sha256": details["snapshot_sha256"],
        "matched_count": details["matched_count"],
        "max_overrides": details["max_overrides"],
        "dry_run": details["dry_run"],
        "delay_seconds": details["delay_seconds"],
        "deleted_count": details["deleted_count"],
        "failure_count": details["failure_count"],
        "indeterminate_count": details["indeterminate_count"],
    });
    result.details = Some(compact_details);
    result.findings = result
        .findings
        .iter()
        .filter(|finding| {
            finding.status != "pass"
                && !finding
                    .check
                    .starts_with("native-delete-overrides-by-filter.override.")
        })
        .map(compact_finding)
        .collect();
    if failures > 0 {
        result.findings.push(Finding::new(
            "fail",
            "native-delete-overrides-by-filter.partial-failures",
            format!(
                "{failures} override trash move(s) failed; inspect the full local artifact for row details."
            ),
        ));
    }
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            "native-delete-overrides-by-filter.status-only",
            "Native override delete snapshot/result summarized.".into(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
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
                "native-delete-overrides-by-filter.direct-config-shape",
                "ok".into(),
            ),
        }
    }

    fn page(ids: &[&str], total: u64) -> Value {
        json!({
            "items": ids.iter().map(|id| json!({"id": id, "text": "ignored"})).collect::<Vec<_>>(),
            "page": {"page": 1, "page_size": 500, "total": total, "sort": "id", "filter": "CVE"},
        })
    }

    const ID1: &str = "11111111-1111-4111-8111-111111111111";
    const ID2: &str = "22222222-2222-4222-8222-222222222222";
    const ID3: &str = "33333333-3333-4333-8333-333333333333";

    #[test]
    fn arguments_and_write_intent_fail_before_runtime_access() {
        let runner = Runner::default();
        for (filter, max, dry_run, allow, confirm, delay) in [
            (" ", DEFAULT_MAX, true, false, None, 1.0),
            ("CVE", 0, true, false, None, 1.0),
            ("CVE", DEFAULT_MAX, false, false, Some("0"), 1.0),
            ("CVE", DEFAULT_MAX, false, true, None, 1.0),
            ("CVE", DEFAULT_MAX, true, false, None, 61.0),
        ] {
            let result = command_with_runner(
                Path::new("/tmp"),
                filter,
                max,
                dry_run,
                allow,
                confirm,
                delay,
                false,
                &runner,
            );
            assert_eq!(result.status, "fail");
            assert_eq!(
                result.findings[0].check,
                "native-delete-overrides-by-filter.arguments"
            );
        }
        assert!(!runner.0.lock().unwrap().iter().any(|call| call == "curl"));
    }

    #[test]
    fn snapshot_hash_matches_python_contract_and_is_order_stable() {
        let (filter_hash, snapshot_hash) = snapshot_hashes("CVE 2026", &[ID1.into(), ID2.into()]);
        assert_eq!(
            filter_hash,
            "4ff37bf07ea7d1724b3b16d82d982d6f3fa2143718d20d37eb325ca9a0a431bb"
        );
        assert_eq!(
            snapshot_hash,
            "ad121a448d44811dbfce78c0dd7ba7d65ab9aecb8986c19512643fa1d17f879e"
        );
        let (_, reverse_hash) = snapshot_hashes("CVE 2026", &[ID2.into(), ID1.into()]);
        assert_eq!(snapshot_hash, reverse_hash);
        assert_eq!(percent_encode("CVE 2026/ä"), "CVE%202026%2F%C3%A4");
    }

    #[test]
    fn dry_run_returns_stable_snapshot_without_delete() {
        let runner = Runner::default();
        let mut calls = Vec::new();
        let mut call = |path: &str, method: &str| {
            calls.push((method.to_string(), path.to_string()));
            Ok(api_call(page(&[ID2, ID1], 2), 200))
        };
        let mut sleep = |_| panic!("dry run must not sleep");
        let result = execute(
            Path::new("/tmp"),
            "CVE 2026",
            DEFAULT_MAX,
            true,
            None,
            1.0,
            false,
            &runner,
            &mut call,
            &mut sleep,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            result.details.as_ref().unwrap()["override_ids"],
            json!([ID1, ID2])
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "GET");
        assert!(calls[0].1.contains("filter=CVE%202026"));
    }

    #[test]
    fn cap_and_snapshot_change_refuse_all_deletes() {
        let runner = Runner::default();
        let mut capped = |_: &str, _: &str| Ok(api_call(page(&[ID1, ID2], 2), 200));
        let mut sleep = |_| {};
        let result = execute(
            Path::new("/tmp"),
            "CVE",
            1,
            true,
            None,
            0.0,
            false,
            &runner,
            &mut capped,
            &mut sleep,
        );
        assert_eq!(result.status, "fail");

        let mut methods = Vec::new();
        let mut changed = |_: &str, method: &str| {
            methods.push(method.to_string());
            Ok(api_call(page(&[ID1], 1), 200))
        };
        let result = execute(
            Path::new("/tmp"),
            "CVE",
            DEFAULT_MAX,
            false,
            Some(&"0".repeat(64)),
            0.0,
            false,
            &runner,
            &mut changed,
            &mut sleep,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(methods, ["GET"]);
        assert_eq!(
            result.findings.last().unwrap().check,
            "native-delete-overrides-by-filter.snapshot-confirmation"
        );
    }

    #[test]
    fn confirmed_batch_distinguishes_rejection_and_indeterminate_without_retry() {
        let runner = Runner::default();
        let (_, snapshot) = snapshot_hashes("CVE", &[ID1.into(), ID2.into(), ID3.into()]);
        let mut responses = VecDeque::from([
            api_call(page(&[ID1, ID2, ID3], 3), 200),
            api_call(Value::Null, 204),
            api_call(json!({"error": {"code": "forbidden"}}), 403),
            GuardedDirectApiCall {
                output: ProcessOutput {
                    success: false,
                    exit_code: Some(28),
                    stdout: String::new(),
                    stderr: "timeout".into(),
                },
                parsed: None,
                http_status: None,
                oversized: false,
                config: Finding::new("pass", "config", "ok".into()),
            },
        ]);
        let mut methods = Vec::new();
        let mut call = |_: &str, method: &str| {
            methods.push(method.to_string());
            Ok(responses.pop_front().unwrap())
        };
        let mut sleeps = Vec::new();
        let mut sleep = |seconds| sleeps.push(seconds);
        let result = execute(
            Path::new("/tmp"),
            "CVE",
            DEFAULT_MAX,
            false,
            Some(&snapshot),
            0.25,
            false,
            &runner,
            &mut call,
            &mut sleep,
        );
        assert_eq!(result.status, "fail");
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["deleted_count"], 1);
        assert_eq!(details["failure_count"], 2);
        assert_eq!(details["indeterminate_count"], 1);
        assert_eq!(methods, ["GET", "DELETE", "DELETE", "DELETE"]);
        assert_eq!(sleeps, [0.25, 0.25]);

        let rendered = serde_json::to_string(&result).unwrap();
        assert!(rendered.contains(ID1));
        let mut compact = result;
        compact_status_only(&mut compact);
        let rendered = serde_json::to_string(&compact).unwrap();
        assert!(!rendered.contains(ID1));
        assert!(rendered.contains("partial-failures"));
    }

    #[test]
    fn duplicate_snapshot_ids_are_rejected() {
        let mut call = |_: &str, _: &str| Ok(api_call(page(&[ID1, ID1], 2), 200));
        let error = fetch_snapshot("CVE", DEFAULT_MAX, &mut call).unwrap_err();
        assert_eq!(
            error.1["reason"],
            "override snapshot page was invalid, duplicated, or changed during pagination"
        );
    }
}
