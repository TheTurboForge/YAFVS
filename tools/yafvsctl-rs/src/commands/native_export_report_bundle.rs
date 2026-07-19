// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::artifact::{ArtifactCommit, begin_secure_artifact_transaction};
use super::common::{compact_finding, expand_home, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{GuardedDirectApiCall, guarded_direct_api_call};
use super::native_export_report_csv::report_csv_bytes_for_bundle;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::{Terminator, WriterBuilder};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const COMMAND: &str = "native-export-report-bundle";
const PAGE_SIZE: usize = 500;
const MAX_PAGES: usize = 10_000;
pub(crate) const DEFAULT_MAX_ITEMS: usize = 100_000;
const MAX_ITEMS_LIMIT: usize = 1_000_000;
pub(crate) const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_BYTES_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const ERROR_FIELDS: [&str; 7] = [
    "id",
    "source_report_id",
    "host",
    "port",
    "nvt_oid",
    "created_at",
    "description",
];

#[derive(Clone, Copy)]
struct CollectionSpec {
    name: &'static str,
    sort: &'static str,
    role: &'static str,
}

const COLLECTIONS: [CollectionSpec; 9] = [
    CollectionSpec {
        name: "raw-results",
        sort: "id",
        role: "canonical_raw_evidence",
    },
    CollectionSpec {
        name: "results",
        sort: "id",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "errors",
        sort: "id",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "hosts",
        sort: "host",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "ports",
        sort: "port",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "applications",
        sort: "name",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "operating-systems",
        sort: "name",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "cves",
        sort: "id",
        role: "analytical_projection",
    },
    CollectionSpec {
        name: "tls-certificates",
        sort: "id",
        role: "analytical_projection",
    },
];

struct DirectJson {
    value: Value,
    config: Finding,
}

struct Collection {
    items: Vec<Value>,
    total: usize,
}

#[derive(serde::Serialize)]
struct Member {
    path: String,
    media_type: String,
    bytes: usize,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

pub fn command_native_export_report_bundle(
    repo_root: &Path,
    report_id: &str,
    output: Option<&Path>,
    max_items: usize,
    max_bytes: u64,
    overwrite: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_with_runner(
        repo_root,
        report_id,
        output,
        max_items,
        max_bytes,
        overwrite,
        status_only,
        &SystemCommandRunner,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_with_runner(
    repo_root: &Path,
    report_id: &str,
    output: Option<&Path>,
    max_items: usize,
    max_bytes: u64,
    overwrite: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
) -> ResultEnvelope {
    let report_id = match validate_operator_uuid(report_id, "--report-id") {
        Ok(value) => value,
        Err(message) => {
            return argument_failure(
                repo_root,
                runner,
                report_id,
                max_items,
                max_bytes,
                message,
                status_only,
            );
        }
    };
    if !(1..=MAX_ITEMS_LIMIT).contains(&max_items) {
        return argument_failure(
            repo_root,
            runner,
            &report_id,
            max_items,
            max_bytes,
            format!("--max-items must be between 1 and {MAX_ITEMS_LIMIT}"),
            status_only,
        );
    }
    if !(1..=MAX_BYTES_LIMIT).contains(&max_bytes) {
        return argument_failure(
            repo_root,
            runner,
            &report_id,
            max_items,
            max_bytes,
            format!("--max-bytes must be between 1 and {MAX_BYTES_LIMIT}"),
            status_only,
        );
    }
    let output = expand_home(
        output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(format!("{report_id}.yafvs-report.zip"))),
    );
    let output_text = output.display().to_string();
    let mut details = initial_details(&report_id, max_items, max_bytes);
    details["output"] = Value::String(output_text.clone());
    let mut transaction = match begin_secure_artifact_transaction(&output, overwrite) {
        Ok(transaction) => transaction,
        Err(message) => {
            return finish(
                repo_root,
                runner,
                "Native report bundle rejected before runtime access.",
                vec![
                    Finding::new("fail", "native-export-report-bundle.arguments", message)
                        .with_details(json!({"output": output_text, "overwrite": overwrite})),
                ],
                details,
                None,
                status_only,
            );
        }
    };

    let report_path = format!("/api/v1/reports/{report_id}");
    let report_call = match direct_json(repo_root, &report_path, runner) {
        Ok(call) => call,
        Err(findings) => {
            return finish(
                repo_root,
                runner,
                "Native report bundle stopped at report preflight.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let report_ok = report_call
        .value
        .as_object()
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        == Some(report_id.as_str());
    let mut findings = vec![report_call.config];
    findings.push(
        Finding::new(
            if report_ok { "pass" } else { "fail" },
            "native-export-report-bundle.report-preflight",
            if report_ok {
                "Direct native API returned the exact report metadata.".into()
            } else {
                "Direct native API report preflight failed or returned the wrong report.".into()
            },
        )
        .with_details(json!({"http_status": 200, "report_id": report_id})),
    );
    if !report_ok {
        return finish(
            repo_root,
            runner,
            "Native report bundle stopped at report preflight.",
            findings,
            details,
            None,
            status_only,
        );
    }

    let metrics_path = format!("/api/v1/reports/{report_id}/metrics");
    let metrics_call = match direct_json(repo_root, &metrics_path, runner) {
        Ok(call) => call,
        Err(mut request_findings) => {
            findings.append(&mut request_findings);
            return finish(
                repo_root,
                runner,
                "Native report bundle stopped at report metrics.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let metrics_ok = metrics_call
        .value
        .as_object()
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)
        == Some(report_id.as_str());
    findings.push(
        Finding::new(
            if metrics_ok { "pass" } else { "fail" },
            "native-export-report-bundle.metrics",
            if metrics_ok {
                "Direct native API returned metrics for the exact report.".into()
            } else {
                "Direct native API returned invalid or mismatched report metrics.".into()
            },
        )
        .with_details(json!({"http_status": 200, "report_id": report_id})),
    );
    if !metrics_ok {
        return finish(
            repo_root,
            runner,
            "Native report bundle stopped at report metrics.",
            findings,
            details,
            None,
            status_only,
        );
    }

    let report = report_call.value;
    let metrics = metrics_call.value;
    let mut collections = BTreeMap::<&'static str, Collection>::new();
    for spec in COLLECTIONS {
        match fetch_collection(repo_root, &report_id, spec, max_items, runner) {
            Ok(collection) => {
                details["collection_counts"][spec.name] = Value::from(collection.total);
                collections.insert(spec.name, collection);
            }
            Err((mut request_findings, error)) => {
                findings.append(&mut request_findings);
                findings.push(
                    Finding::new(
                        "fail",
                        &format!("native-export-report-bundle.{}", spec.name),
                        "Native report collection was incomplete or invalid; no output was replaced."
                            .into(),
                    )
                    .with_details(error),
                );
                return finish(
                    repo_root,
                    runner,
                    &format!("Native report bundle failed while reading {}.", spec.name),
                    findings,
                    details,
                    None,
                    status_only,
                );
            }
        }
    }

    let result_total = collections["results"].items.len();
    if let Some(expected) = exact_integer(report.get("result_count"))
        && expected != result_total as i128
    {
        findings.push(
            Finding::new(
                "fail",
                "native-export-report-bundle.result-count",
                "Report metadata and analytical result totals disagree; no output was replaced."
                    .into(),
            )
            .with_details(json!({
                "report_result_count": expected,
                "collection_total": result_total,
            })),
        );
        return finish(
            repo_root,
            runner,
            "Native report bundle stopped at result-count consistency validation.",
            findings,
            details,
            None,
            status_only,
        );
    }

    let archive_result = write_archive(
        transaction.file_mut(),
        &report_id,
        &report,
        &metrics,
        &collections,
        max_bytes,
    );
    let members = match archive_result {
        Ok(members) => members,
        Err(message) => {
            findings.push(
                Finding::new(
                    "fail",
                    "native-export-report-bundle.output",
                    format!("Atomic report bundle output failed: {message}"),
                )
                .with_details(json!({"output": output_text})),
            );
            return finish(
                repo_root,
                runner,
                "Native report bundle could not write the output; any existing file was preserved.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let (byte_count, sha256) = match file_identity(transaction.file_mut()) {
        Ok(identity) => identity,
        Err(error) => {
            findings.push(Finding::new(
                "fail",
                "native-export-report-bundle.output",
                format!("Private report bundle could not be inspected: {error}"),
            ));
            return finish(
                repo_root,
                runner,
                "Native report bundle could not validate its private output.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    let commit = match transaction.commit() {
        Ok(commit) => commit,
        Err(error) => {
            findings.push(
                Finding::new(
                    "fail",
                    "native-export-report-bundle.output",
                    format!("Atomic report bundle output installation failed: {error}"),
                )
                .with_details(json!({"output": output_text})),
            );
            return finish(
                repo_root,
                runner,
                "Native report bundle could not complete atomic output installation.",
                findings,
                details,
                None,
                status_only,
            );
        }
    };
    details["member_count"] = Value::from(members);
    details["byte_count"] = Value::from(byte_count);
    details["sha256"] = Value::String(sha256.clone());
    let (status, summary, message) = match commit {
        ArtifactCommit::Durable => (
            "pass",
            "Complete native report bundle export completed.",
            "Complete native report bundle was written atomically.".to_string(),
        ),
        ArtifactCommit::InstalledDurabilityUnknown(error) => (
            "warn",
            "Native report bundle completed with an output-durability warning.",
            error,
        ),
    };
    findings.push(
        Finding::new(status, "native-export-report-bundle.output", message).with_details(json!({
            "output": output_text,
            "member_count": members,
            "byte_count": byte_count,
            "sha256": sha256,
        })),
    );
    finish(
        repo_root,
        runner,
        summary,
        findings,
        details,
        Some(output),
        status_only,
    )
}

fn initial_details(report_id: &str, max_items: usize, max_bytes: u64) -> Value {
    json!({
        "report_id": report_id,
        "output": Value::Null,
        "max_items": max_items,
        "max_bytes": max_bytes,
        "collection_counts": {},
        "member_count": 0,
        "byte_count": Value::Null,
        "sha256": Value::Null,
    })
}

#[allow(clippy::too_many_arguments)]
fn argument_failure(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    report_id: &str,
    max_items: usize,
    max_bytes: u64,
    message: String,
    status_only: bool,
) -> ResultEnvelope {
    finish(
        repo_root,
        runner,
        "Native report bundle rejected before runtime access.",
        vec![
            Finding::new("fail", "native-export-report-bundle.arguments", message).with_details(
                json!({
                    "report_id": report_id,
                    "max_items": max_items,
                    "max_bytes": max_bytes,
                }),
            ),
        ],
        initial_details(report_id, max_items, max_bytes),
        None,
        status_only,
    )
}

fn direct_json(
    repo_root: &Path,
    path: &str,
    runner: &dyn CommandRunner,
) -> Result<DirectJson, Vec<Finding>> {
    let call = guarded_direct_api_call(
        repo_root,
        path,
        "GET",
        None,
        None,
        "native-export-report-bundle.direct-config-shape",
        "native-export-report-bundle.direct-token-strength",
        runner,
    )?;
    validate_direct_json(call, path)
}

fn validate_direct_json(
    call: GuardedDirectApiCall,
    path: &str,
) -> Result<DirectJson, Vec<Finding>> {
    let ok = call.output.success
        && call.output.exit_code == Some(0)
        && !call.oversized
        && call.http_status == Some(200)
        && call.parsed.as_ref().is_some_and(Value::is_object);
    if !ok {
        return Err(vec![
            call.config,
            Finding::new(
                "fail",
                "native-export-report-bundle.direct-response",
                "Direct native API request failed, exceeded its bound, returned non-200, or returned an invalid JSON object."
                    .into(),
            )
            .with_details(json!({
                "path": path,
                "exit_code": call.output.exit_code,
                "http_status": call.http_status,
                "oversized": call.oversized,
            })),
        ]);
    }
    Ok(DirectJson {
        value: call.parsed.expect("validated direct JSON object"),
        config: call.config,
    })
}

fn fetch_collection(
    repo_root: &Path,
    report_id: &str,
    spec: CollectionSpec,
    max_items: usize,
    runner: &dyn CommandRunner,
) -> Result<Collection, (Vec<Finding>, Value)> {
    let mut items = Vec::<Value>::new();
    let mut seen = BTreeSet::<String>::new();
    let mut expected_total = None::<usize>;
    for page in 1..=MAX_PAGES {
        let path = format!(
            "/api/v1/reports/{report_id}/{}?page={page}&page_size={PAGE_SIZE}&sort={}",
            spec.name, spec.sort
        );
        let call = match direct_json(repo_root, &path, runner) {
            Ok(call) => call,
            Err(findings) => {
                return Err((
                    findings,
                    json!({
                        "reason": "collection request failed",
                        "collection": spec.name,
                        "page": page,
                    }),
                ));
            }
        };
        let page_value = match validate_page(
            &call.value,
            report_id,
            spec.name,
            page,
            expected_total,
            &seen,
        ) {
            Ok(value) => value,
            Err(reason) => {
                return Err((
                    Vec::new(),
                    json!({
                        "reason": reason,
                        "collection": spec.name,
                        "page": page,
                        "expected_total": expected_total,
                    }),
                ));
            }
        };
        if expected_total.is_none() {
            expected_total = Some(page_value.total);
            if page_value.total > max_items {
                return Err((
                    Vec::new(),
                    json!({
                        "reason": "collection exceeds safety cap",
                        "collection": spec.name,
                        "total": page_value.total,
                        "max_items": max_items,
                    }),
                ));
            }
        }
        if page_value.items.is_empty() && items.len() != page_value.total {
            return Err((
                Vec::new(),
                json!({
                    "reason": "collection ended before declared total",
                    "collection": spec.name,
                    "page": page,
                    "total": page_value.total,
                }),
            ));
        }
        for item in page_value.items {
            let key = item_key(spec.name, item).expect("page item key was validated");
            seen.insert(key);
            items.push(item.clone());
        }
        if items.len() == page_value.total {
            return Ok(Collection {
                items,
                total: page_value.total,
            });
        }
        if items.len() > page_value.total {
            return Err((
                Vec::new(),
                json!({
                    "reason": "collection exceeded declared total",
                    "collection": spec.name,
                    "page": page,
                    "total": page_value.total,
                }),
            ));
        }
    }
    Err((
        Vec::new(),
        json!({
            "reason": "collection pagination exceeded safety limit",
            "collection": spec.name,
            "total": expected_total,
        }),
    ))
}

struct Page<'a> {
    total: usize,
    items: &'a [Value],
}

fn validate_page<'a>(
    value: &'a Value,
    report_id: &str,
    collection: &str,
    requested_page: usize,
    expected_total: Option<usize>,
    seen: &BTreeSet<String>,
) -> Result<Page<'a>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "collection page was not an object".to_string())?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "collection page items were not an array".to_string())?;
    let page = object
        .get("page")
        .and_then(Value::as_object)
        .ok_or_else(|| "collection page metadata was not an object".to_string())?;
    let total = exact_usize(page.get("total"))
        .ok_or_else(|| "collection total was not a non-negative integer".to_string())?;
    let actual_page = exact_usize(page.get("page"))
        .ok_or_else(|| "collection page number was not a non-negative integer".to_string())?;
    if actual_page != requested_page {
        return Err("collection page number did not match the request".into());
    }
    if expected_total.is_some_and(|expected| expected != total) {
        return Err("collection total changed during pagination".into());
    }
    let mut page_keys = BTreeSet::<String>::new();
    for item in items {
        if !item_is_scoped(collection, item, report_id) {
            return Err("collection item was invalid or outside the requested report".into());
        }
        let key = item_key(collection, item).expect("scoped item has key");
        if !page_keys.insert(key.clone()) || seen.contains(&key) {
            return Err("collection page repeated an item key".into());
        }
    }
    Ok(Page { total, items })
}

fn item_key(collection: &str, item: &Value) -> Option<String> {
    let object = item.as_object()?;
    match collection {
        "raw-results" | "results" | "errors" | "cves" | "tls-certificates" => object
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        "hosts" => object
            .get("host")
            .and_then(Value::as_str)
            .map(str::to_string),
        "ports" => object
            .get("port")
            .and_then(Value::as_str)
            .map(str::to_string),
        "applications" => tuple_key(object, &["name", "version", "cpe"]),
        "operating-systems" => tuple_key(object, &["name", "cpe"]),
        _ => None,
    }
}

fn tuple_key(object: &Map<String, Value>, fields: &[&str]) -> Option<String> {
    let values = fields
        .iter()
        .map(|field| object.get(*field).filter(|value| !value.is_null()).cloned())
        .collect::<Option<Vec<_>>>()?;
    serde_json::to_string(&values).ok()
}

fn item_is_scoped(collection: &str, item: &Value, report_id: &str) -> bool {
    let Some(object) = item.as_object() else {
        return false;
    };
    if item_key(collection, item).is_none() {
        return false;
    }
    if matches!(collection, "raw-results" | "results" | "errors" | "hosts") {
        return object.get("source_report_id").and_then(Value::as_str) == Some(report_id);
    }
    object
        .get("source_report_ids")
        .and_then(Value::as_array)
        .is_some_and(|ids| {
            ids.iter().all(Value::is_string) && ids.iter().any(|id| id.as_str() == Some(report_id))
        })
}

fn exact_usize(value: Option<&Value>) -> Option<usize> {
    value?
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
}

fn exact_integer(value: Option<&Value>) -> Option<i128> {
    value.and_then(|value| {
        value
            .as_i64()
            .map(i128::from)
            .or_else(|| value.as_u64().map(i128::from))
    })
}

fn write_archive(
    file: &mut File,
    report_id: &str,
    report: &Value,
    metrics: &Value,
    collections: &BTreeMap<&'static str, Collection>,
    max_bytes: u64,
) -> Result<usize, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("private archive could not be positioned: {error}"))?;
    file.set_len(0)
        .map_err(|error| format!("private archive could not be reset: {error}"))?;
    let mut archive = ZipWriter::new(file);
    let mut members = Vec::<Member>::new();
    let mut uncompressed = 0_u64;
    add_member(
        &mut archive,
        &mut members,
        &mut uncompressed,
        max_bytes,
        "report.json",
        "application/json",
        json_bytes(report)?,
        None,
        None,
    )?;
    add_member(
        &mut archive,
        &mut members,
        &mut uncompressed,
        max_bytes,
        "metrics.json",
        "application/json",
        json_bytes(metrics)?,
        None,
        None,
    )?;
    for spec in COLLECTIONS {
        let collection = &collections[spec.name];
        let payload = json!({
            "schema_version": 1,
            "source_endpoint": format!("/api/v1/reports/{report_id}/{}", spec.name),
            "total": collection.total,
            "items": collection.items,
        });
        add_member(
            &mut archive,
            &mut members,
            &mut uncompressed,
            max_bytes,
            &format!("collections/{}.json", spec.name),
            "application/json",
            json_bytes(&payload)?,
            Some(collection.items.len()),
            Some(spec.role),
        )?;
    }
    let results = report_csv_bytes_for_bundle(&collections["results"].items)?;
    add_member(
        &mut archive,
        &mut members,
        &mut uncompressed,
        max_bytes,
        "views/results.csv",
        "text/csv; charset=utf-8",
        results,
        Some(collections["results"].items.len()),
        Some("human_spreadsheet_view"),
    )?;
    let errors = error_csv_bytes(&collections["errors"].items)?;
    add_member(
        &mut archive,
        &mut members,
        &mut uncompressed,
        max_bytes,
        "views/errors.csv",
        "text/csv; charset=utf-8",
        errors,
        Some(collections["errors"].items.len()),
        Some("human_spreadsheet_view"),
    )?;
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| format!("bundle timestamp could not be formatted: {error}"))?;
    let manifest = json!({
        "format": "yafvs-native-report-bundle",
        "schema_version": 1,
        "generated_at": generated_at,
        "report_id": report_id,
        "source": {
            "contract": "YAFVS native API v1",
            "base_path": "/api/v1",
        },
        "evidence_contract": {
            "canonical": "collections/raw-results.json",
            "complete": true,
            "meaning": "Every retained gvmd result row for the exact report, including scanner error and hostless rows, with nullable source values preserved.",
            "legacy_xml_byte_or_schema_parity": false,
            "projections": "Other collections and CSV files are typed analytical or human views derived from native API contracts.",
        },
        "members": members,
    });
    add_member(
        &mut archive,
        &mut members,
        &mut uncompressed,
        max_bytes,
        "manifest.json",
        "application/json",
        json_bytes(&manifest)?,
        None,
        None,
    )?;
    archive
        .finish()
        .map_err(|error| format!("ZIP archive could not be completed: {error}"))?;
    Ok(members.len())
}

#[allow(clippy::too_many_arguments)]
fn add_member(
    archive: &mut ZipWriter<&mut File>,
    members: &mut Vec<Member>,
    uncompressed: &mut u64,
    max_bytes: u64,
    path: &str,
    media_type: &str,
    content: Vec<u8>,
    item_count: Option<usize>,
    role: Option<&str>,
) -> Result<(), String> {
    let bytes = u64::try_from(content.len())
        .map_err(|_| "bundle member size could not be represented".to_string())?;
    *uncompressed = uncompressed
        .checked_add(bytes)
        .ok_or_else(|| "bundle uncompressed byte count overflowed".to_string())?;
    if *uncompressed > max_bytes {
        return Err(format!("bundle content exceeds --max-bytes {max_bytes}"));
    }
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600)
        .large_file(bytes > u64::from(u32::MAX));
    archive
        .start_file(path, options)
        .and_then(|_| archive.write_all(&content).map_err(Into::into))
        .map_err(|error| format!("ZIP member {path} could not be written: {error}"))?;
    members.push(Member {
        path: path.to_string(),
        media_type: media_type.to_string(),
        bytes: content.len(),
        sha256: format!("{:x}", Sha256::digest(&content)),
        item_count,
        role: role.map(str::to_string),
    });
    Ok(())
}

fn json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(&canonical_json(value))
        .map_err(|error| format!("bundle JSON could not be encoded: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        value => value.clone(),
    }
}

fn error_csv_bytes(rows: &[Value]) -> Result<Vec<u8>, String> {
    let mut writer = WriterBuilder::new()
        .terminator(Terminator::Any(b'\n'))
        .from_writer(Vec::new());
    writer
        .write_record(ERROR_FIELDS)
        .map_err(|error| format!("error CSV header could not be encoded: {error}"))?;
    for row in rows {
        let object = row.as_object();
        writer
            .write_record(
                ERROR_FIELDS
                    .map(|field| spreadsheet_safe_cell(object.and_then(|value| value.get(field)))),
            )
            .map_err(|error| format!("error CSV row could not be encoded: {error}"))?;
    }
    writer
        .into_inner()
        .map_err(|error| format!("error CSV could not be completed: {}", error.error()))
}

fn spreadsheet_safe_cell(value: Option<&Value>) -> String {
    let text = match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Array(_) | Value::Object(_)) => {
            serde_json::to_string(value.expect("matched JSON collection")).unwrap_or_default()
        }
        Some(value) => value.to_string(),
    };
    if text.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{text}")
    } else {
        text
    }
}

fn file_identity(file: &mut File) -> std::io::Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_count = byte_count
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("bundle byte count overflow"))?;
        digest.update(&buffer[..read]);
    }
    Ok((byte_count, format!("{:x}", digest.finalize())))
}

fn finish(
    repo_root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    mut details: Value,
    artifact: Option<PathBuf>,
    status_only: bool,
) -> ResultEnvelope {
    if status_only {
        let source = details.as_object().cloned().unwrap_or_default();
        details = Value::Object(
            [
                "report_id",
                "output",
                "collection_counts",
                "member_count",
                "byte_count",
                "sha256",
            ]
            .into_iter()
            .map(|key| {
                (
                    key.to_string(),
                    source.get(key).cloned().unwrap_or(Value::Null),
                )
            })
            .collect(),
        );
    }
    let mut outcome = make_result(
        metadata(repo_root, COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_details(details);
    if let Some(artifact) = artifact {
        outcome = outcome.with_artifacts(vec![artifact.display().to_string()]);
    }
    if status_only {
        outcome.findings = outcome
            .findings
            .iter()
            .filter(|finding| finding.status != "pass")
            .map(compact_finding)
            .collect();
        if outcome.findings.is_empty() {
            outcome.findings.push(Finding::new(
                "pass",
                "native-export-report-bundle.status-only",
                "Native report bundle completed; evidence content omitted.".into(),
            ));
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::os::fd::RawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use zip::ZipArchive;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    type CurlCall = (Vec<String>, BTreeMap<OsString, OsString>);

    struct Runner {
        responses: Mutex<VecDeque<ProcessOutput>>,
        calls: Mutex<Vec<CurlCall>>,
        private_header_seen: Mutex<bool>,
    }

    impl Runner {
        fn new(responses: Vec<ProcessOutput>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
                private_header_seen: Mutex::new(false),
            }
        }
    }

    impl CommandRunner for Runner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbee\n".into(),
                stderr: String::new(),
            })
        }

        #[allow(clippy::too_many_arguments)]
        fn run_with_input_and_fd(
            &self,
            program: &str,
            args: &[&str],
            _cwd: Option<&Path>,
            env: Option<&BTreeMap<OsString, OsString>>,
            _timeout: Option<Duration>,
            _input: Option<&[u8]>,
            inherited_fd: RawFd,
        ) -> Option<ProcessOutput> {
            if program != "curl" {
                return None;
            }
            let header = std::fs::read_to_string(format!("/proc/self/fd/{inherited_fd}")).ok()?;
            *self.private_header_seen.lock().unwrap() = header
                .strip_prefix("Authorization: Bearer ")
                .and_then(|value| value.strip_suffix('\n'))
                .is_some_and(|token| token.len() >= 32);
            self.calls.lock().unwrap().push((
                args.iter().map(|value| (*value).to_string()).collect(),
                env.cloned().unwrap_or_default(),
            ));
            self.responses.lock().unwrap().pop_front()
        }
    }

    fn response(value: Value, status: u16) -> ProcessOutput {
        ProcessOutput {
            success: true,
            exit_code: Some(0),
            stdout: format!("{value}\n{status}"),
            stderr: String::new(),
        }
    }

    fn fixture(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "yafvsctl-native-bundle-{label}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let repo = root.join("YAFVS");
        std::fs::create_dir_all(&repo).unwrap();
        (root, repo)
    }

    fn result_row(report_id: &str, id: &str) -> Value {
        json!({
            "id": id,
            "source_report_id": report_id,
            "report": {"id": report_id, "name": "private report"},
            "task": {"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "name": "Daily scan"},
            "host": "192.0.2.10",
            "port": "443/tcp",
            "severity": 7.5,
            "qod": 95,
            "nvt_oid": "1.3.6.1.4.1.25623.1.0.100001",
            "name": "=formula",
            "cves": ["CVE-2026-0001"],
            "cert_refs": [],
            "xrefs": {"z": 1, "a": 2},
            "user_tags": [],
            "overrides": [],
            "description": "private evidence body",
        })
    }

    fn collection_rows(report_id: &str) -> BTreeMap<&'static str, Vec<Value>> {
        let result_id = "22222222-2222-4222-8222-222222222222";
        BTreeMap::from([
            (
                "raw-results",
                vec![json!({
                    "id": result_id,
                    "source_report_id": report_id,
                    "host": "192.0.2.10",
                    "description": "private evidence body",
                    "path": null,
                })],
            ),
            ("results", vec![result_row(report_id, result_id)]),
            (
                "errors",
                vec![json!({
                    "id": "33333333-3333-4333-8333-333333333333",
                    "source_report_id": report_id,
                    "host": "",
                    "port": "",
                    "nvt_oid": "",
                    "created_at": "2026-07-10T12:01:00Z",
                    "description": "=hostless scanner error",
                })],
            ),
            (
                "hosts",
                vec![json!({"host": "192.0.2.10", "source_report_id": report_id})],
            ),
            (
                "ports",
                vec![json!({"port": "443/tcp", "source_report_ids": [report_id]})],
            ),
            (
                "applications",
                vec![json!({
                    "name": "Service",
                    "version": "1",
                    "cpe": "cpe:/a:test",
                    "source_report_ids": [report_id],
                })],
            ),
            (
                "operating-systems",
                vec![json!({
                    "name": "Linux",
                    "cpe": "cpe:/o:linux",
                    "source_report_ids": [report_id],
                })],
            ),
            (
                "cves",
                vec![json!({"id": "CVE-2026-0001", "source_report_ids": [report_id]})],
            ),
            (
                "tls-certificates",
                vec![json!({
                    "id": "44444444-4444-4444-8444-444444444444",
                    "source_report_ids": [report_id],
                })],
            ),
        ])
    }

    fn successful_responses(report_id: &str) -> Vec<ProcessOutput> {
        let rows = collection_rows(report_id);
        let mut responses = vec![
            response(
                json!({"id": report_id, "name": "private report", "result_count": 1}),
                200,
            ),
            response(json!({"id": report_id, "summary": {}}), 200),
        ];
        for spec in COLLECTIONS {
            let items = rows.get(spec.name).unwrap();
            responses.push(response(
                json!({
                    "items": items,
                    "page": {"page": 1, "page_size": PAGE_SIZE, "total": items.len()},
                }),
                200,
            ));
        }
        responses
    }

    fn temporary_files(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".tmp-"))
            })
            .collect()
    }

    #[test]
    fn invalid_arguments_make_no_runtime_request() {
        let (root, repo) = fixture("arguments");
        let runner = Runner::new(Vec::new());
        for result in [
            command_with_runner(
                &repo,
                "not-a-uuid",
                None,
                DEFAULT_MAX_ITEMS,
                DEFAULT_MAX_BYTES,
                false,
                false,
                &runner,
            ),
            command_with_runner(
                &repo,
                "11111111-1111-4111-8111-111111111111",
                None,
                0,
                DEFAULT_MAX_BYTES,
                false,
                false,
                &runner,
            ),
            command_with_runner(
                &repo,
                "11111111-1111-4111-8111-111111111111",
                None,
                DEFAULT_MAX_ITEMS,
                0,
                false,
                false,
                &runner,
            ),
        ] {
            assert_eq!(result.status, "fail");
            assert_eq!(
                result.findings[0].check,
                "native-export-report-bundle.arguments"
            );
        }
        assert!(runner.calls.lock().unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_complete_private_bundle_and_redacts_status() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let runner = Runner::new(successful_responses(report_id));
        let (root, repo) = fixture("success");
        let output = root.join("report.yafvs-report.zip");
        let result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            DEFAULT_MAX_ITEMS,
            DEFAULT_MAX_BYTES,
            false,
            true,
            &runner,
        );
        assert_eq!(result.status, "pass");
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(
            result.details.as_ref().unwrap()["sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert_eq!(result.details.as_ref().unwrap()["byte_count"], bytes.len());
        assert_eq!(result.details.as_ref().unwrap()["member_count"], 14);
        assert_eq!(
            result.details.as_ref().unwrap()["collection_counts"]["raw-results"],
            1
        );
        let mut archive = ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("collections/raw-results.json"));
        assert!(names.contains("collections/errors.json"));
        assert!(names.contains("views/results.csv"));
        assert!(names.contains("views/errors.csv"));
        assert!(names.contains("manifest.json"));
        let manifest: Value = {
            let mut text = String::new();
            archive
                .by_name("manifest.json")
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            serde_json::from_str(&text).unwrap()
        };
        assert_eq!(manifest["format"], "yafvs-native-report-bundle");
        assert_eq!(
            manifest["evidence_contract"]["canonical"],
            "collections/raw-results.json"
        );
        assert_eq!(
            manifest["evidence_contract"]["legacy_xml_byte_or_schema_parity"],
            false
        );
        assert_eq!(manifest["members"].as_array().unwrap().len(), 13);
        let raw: Value = {
            let mut text = String::new();
            archive
                .by_name("collections/raw-results.json")
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            serde_json::from_str(&text).unwrap()
        };
        assert_eq!(raw["total"], 1);
        assert_eq!(raw["items"][0]["path"], Value::Null);
        let errors = {
            let mut text = String::new();
            archive
                .by_name("views/errors.csv")
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            text
        };
        assert!(errors.contains("'=hostless scanner error"));
        assert!(*runner.private_header_seen.lock().unwrap());
        assert_eq!(runner.calls.lock().unwrap().len(), 11);
        for (args, env) in runner.calls.lock().unwrap().iter() {
            assert!(!args.join(" ").contains("Bearer "));
            assert!(
                !env.keys()
                    .any(|name| name.to_string_lossy().contains("TOKEN"))
            );
        }
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("private evidence body"));
        assert!(!encoded.contains("private report"));
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collection_cap_and_byte_cap_preserve_existing_output() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let (root, repo) = fixture("caps");
        let output = root.join("report.zip");
        std::fs::write(&output, b"preserve").unwrap();
        let item_runner = Runner::new(vec![
            response(json!({"id": report_id, "result_count": 2}), 200),
            response(json!({"id": report_id}), 200),
            response(
                json!({"items": [], "page": {"page": 1, "page_size": 500, "total": 2}}),
                200,
            ),
        ]);
        let item_result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            1,
            DEFAULT_MAX_BYTES,
            true,
            false,
            &item_runner,
        );
        assert_eq!(item_result.status, "fail");
        assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
        let byte_runner = Runner::new(successful_responses(report_id));
        let byte_result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            DEFAULT_MAX_ITEMS,
            1,
            true,
            false,
            &byte_runner,
        );
        assert_eq!(byte_result.status, "fail");
        assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_collection_key_during_pagination_is_rejected() {
        let report_id = "11111111-1111-4111-8111-111111111111";
        let duplicate = json!({
            "id": "22222222-2222-4222-8222-222222222222",
            "source_report_id": report_id,
        });
        let runner = Runner::new(vec![
            response(json!({"id": report_id}), 200),
            response(json!({"id": report_id}), 200),
            response(
                json!({"items": [duplicate.clone()], "page": {"page": 1, "total": 2}}),
                200,
            ),
            response(
                json!({"items": [duplicate], "page": {"page": 2, "total": 2}}),
                200,
            ),
        ]);
        let (root, repo) = fixture("duplicate");
        let output = root.join("report.zip");
        let result = command_with_runner(
            &repo,
            report_id,
            Some(&output),
            DEFAULT_MAX_ITEMS,
            DEFAULT_MAX_BYTES,
            false,
            false,
            &runner,
        );
        assert_eq!(result.status, "fail");
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.check == "native-export-report-bundle.raw-results")
        );
        assert!(!output.exists());
        assert!(temporary_files(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_json_is_recursively_sorted_and_tuple_keys_reject_null() {
        let encoded = String::from_utf8(
            json_bytes(&json!({"z": {"b": 1, "a": 2}, "a": [{"d": 3, "c": 4}]})).unwrap(),
        )
        .unwrap();
        assert!(encoded.find("\"a\"").unwrap() < encoded.find("\"z\"").unwrap());
        assert!(encoded.find("\"c\"").unwrap() < encoded.find("\"d\"").unwrap());
        let application = json!({"name": "Service", "version": null, "cpe": "cpe:/a:test"});
        assert!(item_key("applications", &application).is_none());
    }
}
