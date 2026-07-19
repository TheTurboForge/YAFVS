// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded resource-import commands sharing one guarded native-API boundary.
//!
//! Format-specific importers live beside this module as their contracts grow.

mod schedule_import;
mod tag_csv;
mod task_csv;
mod target_csv;

pub use schedule_import::{command_native_schedules_from_csv, command_native_schedules_from_xml};
pub use tag_csv::command_native_tags_from_csv;
pub use task_csv::command_native_tasks_from_csv;
pub use target_csv::command_native_targets_from_csv;

use super::common::{iso_system_time, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{
    GuardedDirectApiCall, MAX_REQUEST_BODY_BYTES, guarded_direct_api_call,
};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::OnceLock;
use std::time::SystemTime;

const COMMAND: &str = "native-targets-from-host-list";
const XML_COMMAND: &str = "native-targets-from-xml";
const DEFAULT_PORT_LIST_ID: &str = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5";
const DEFAULT_ALIVE_TEST: &str = "Scan Config Default";
const MAX_HOST_FILE_BYTES: usize = 1024 * 1024;
const MAX_HOSTS: usize = 4095;
const MAX_HOST_BYTES: usize = 4096;
const MAX_PORT_RANGES: usize = 4095;
const MAX_XML_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_XML_ROWS: usize = 4095;
const MAX_XML_LIST_ITEMS: usize = 4095;
const MAX_XML_TEXT_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PortRange {
    protocol: &'static str,
    start: u16,
    end: u16,
    comment: &'static str,
}

struct ApiReply {
    output: ProcessOutput,
    parsed: Option<Value>,
    http_status: Option<i64>,
    oversized: bool,
    config: Finding,
}

trait TargetApi {
    #[allow(clippy::too_many_arguments)]
    fn call(
        &self,
        root: &Path,
        path: &str,
        method: &str,
        body: Option<&Value>,
        request_check: &str,
        config_check: &str,
        token_check: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>>;
}

struct GuardedApi;

impl TargetApi for GuardedApi {
    fn call(
        &self,
        root: &Path,
        path: &str,
        method: &str,
        body: Option<&Value>,
        request_check: &str,
        config_check: &str,
        token_check: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>> {
        let body = body
            .map(serialize_request_body)
            .transpose()
            .map_err(|error| vec![Finding::new("fail", request_check, error)])?;
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            body.as_deref(),
            config_check,
            token_check,
            runner,
        )
        .map(reply_from_guarded)
    }
}

fn reply_from_guarded(call: GuardedDirectApiCall) -> ApiReply {
    ApiReply {
        output: call.output,
        parsed: call.parsed,
        http_status: call.http_status,
        oversized: call.oversized,
        config: call.config,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn command_native_targets_from_host_list(
    root: &Path,
    hosts_file: &Path,
    port_list_id: Option<&str>,
    port_range: Option<&str>,
    port_list_name: Option<&str>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    let hosts = match load_hosts(hosts_file) {
        Ok(hosts) => hosts,
        Err(error) => {
            return finish_status(
                envelope(
                    root,
                    &SystemCommandRunner,
                    "Native host-list target creation rejected before runtime access.",
                    vec![
                        Finding::new("fail", &format!("{COMMAND}.hosts"), error)
                            .with_details(json!({"hosts_file":hosts_file})),
                    ],
                    base_details(hosts_file, dry_run),
                ),
                status_only,
            );
        }
    };
    command_with(
        root,
        hosts_file,
        hosts,
        port_list_id,
        port_range,
        port_list_name,
        allow_write_control,
        dry_run,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
        iso_system_time(SystemTime::now()).unwrap_or_else(|| "unknown".into()),
    )
}

fn envelope(
    root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
) -> ResultEnvelope {
    make_result(metadata(root, COMMAND, runner), summary.into(), findings).with_details(details)
}

fn base_details(hosts_file: &Path, dry_run: bool) -> Value {
    json!({
        "hosts_file": hosts_file,
        "host_count": 0,
        "dry_run": dry_run,
        "port_list_id": null,
        "port_list_created": false,
        "created_target_count": 0,
        "created_target_ids": [],
    })
}

fn load_hosts(path: &Path) -> Result<Vec<String>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read host file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read host file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("failed to read host file: path is not a regular file".into());
    }
    if metadata.len() > MAX_HOST_FILE_BYTES as u64 {
        return Err(format!(
            "failed to read host file: file exceeds the {MAX_HOST_FILE_BYTES} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((MAX_HOST_FILE_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read host file: {error}"))?;
    if input.len() > MAX_HOST_FILE_BYTES {
        return Err(format!(
            "failed to read host file: file exceeds the {MAX_HOST_FILE_BYTES} byte limit"
        ));
    }
    let text =
        String::from_utf8(input).map_err(|_| "failed to read host file: input is not UTF-8")?;
    let mut hosts = Vec::new();
    for line in text.lines() {
        let host = line.trim();
        if host.is_empty() {
            continue;
        }
        if host.len() > MAX_HOST_BYTES {
            return Err(format!(
                "host file entries must be at most {MAX_HOST_BYTES} bytes"
            ));
        }
        hosts.push(host.to_string());
        if hosts.len() > MAX_HOSTS {
            return Err(format!(
                "host file must contain at most {MAX_HOSTS} non-empty entries"
            ));
        }
    }
    if hosts.is_empty() {
        return Err("host file is empty".into());
    }
    Ok(hosts)
}

fn port_range_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)^(T|TCP|U|UDP):([0-9]+)(?:-([0-9]+))?$").expect("static port-range regex")
    })
}

fn serialize_request_body(body: &Value) -> Result<String, String> {
    let body = body.to_string();
    if body.len() > MAX_REQUEST_BODY_BYTES {
        Err(format!(
            "request body JSON exceeds the {MAX_REQUEST_BODY_BYTES} byte limit"
        ))
    } else {
        Ok(body)
    }
}

fn parse_port_ranges(value: &str) -> Result<Vec<PortRange>, String> {
    let mut ranges = Vec::new();
    for raw in value.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let Some(captures) = port_range_regex().captures(token) else {
            return Err(
                "port ranges must use comma-separated T:start-end or U:start-end tokens".into(),
            );
        };
        let start = captures[2].parse::<u32>().ok();
        let end = captures
            .get(3)
            .and_then(|value| value.as_str().parse::<u32>().ok())
            .or(start);
        let (Some(start), Some(end)) = (start, end) else {
            return Err("port range start/end must be decimal integers".into());
        };
        if !(1..=65_535).contains(&start) || !(1..=65_535).contains(&end) || start > end {
            return Err(
                "port range start/end must be within 1..65535 and start must not exceed end".into(),
            );
        }
        ranges.push(PortRange {
            protocol: if captures[1].to_ascii_lowercase().starts_with('t') {
                "tcp"
            } else {
                "udp"
            },
            start: start as u16,
            end: end as u16,
            comment: "YAFVS native host-list target import",
        });
        if ranges.len() > MAX_PORT_RANGES {
            return Err(format!(
                "port range must contain at most {MAX_PORT_RANGES} ranges"
            ));
        }
    }
    if ranges.is_empty() {
        return Err("port range must include at least one T:/U: range".into());
    }
    Ok(ranges)
}

pub(crate) fn target_body(host: &str, port_list_id: &str, timestamp: &str) -> Value {
    json!({
        "name": format!("Target for {host}"),
        "comment": format!("Created: {timestamp}"),
        "port_list_id": port_list_id,
        "hosts": [host],
        "exclude_hosts": [],
        "alive_tests": [DEFAULT_ALIVE_TEST],
        "allow_simultaneous_ips": false,
        "reverse_lookup_only": false,
        "reverse_lookup_unify": false,
    })
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    hosts_file: &Path,
    hosts: Vec<String>,
    port_list_id: Option<&str>,
    port_range: Option<&str>,
    port_list_name: Option<&str>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    timestamp: String,
) -> ResultEnvelope {
    let mut details = base_details(hosts_file, dry_run);
    details["host_count"] = json!(hosts.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{COMMAND}.hosts"),
        format!(
            "Loaded {} non-empty host(s) from the host file.",
            hosts.len()
        ),
    )];

    let ranges = match port_range {
        Some(value) => match parse_port_ranges(value) {
            Ok(ranges) => {
                details["port_range_count"] = json!(ranges.len());
                Some(ranges)
            }
            Err(error) => {
                findings.push(Finding::new(
                    "fail",
                    &format!("{COMMAND}.port-range"),
                    error,
                ));
                return finish_status(
                    envelope(
                        root,
                        runner,
                        "Native host-list target creation rejected before runtime access.",
                        findings,
                        details,
                    ),
                    status_only,
                );
            }
        },
        None => None,
    };

    let mut selected_port_list = match ranges {
        Some(_) => None,
        None => {
            let value = port_list_id.unwrap_or(DEFAULT_PORT_LIST_ID);
            match validate_operator_uuid(value, "--port-list-id") {
                Ok(value) => {
                    details["port_list_id"] = json!(value);
                    Some(value)
                }
                Err(_) => {
                    findings.push(
                        Finding::new(
                            "fail",
                            &format!("{COMMAND}.port-list-id"),
                            "--port-list-id must be a UUID.".into(),
                        )
                        .with_details(json!({"port_list_id":value})),
                    );
                    return finish_status(
                        envelope(
                            root,
                            runner,
                            "Native host-list target creation rejected before runtime access.",
                            findings,
                            details,
                        ),
                        status_only,
                    );
                }
            }
        }
    };

    let placeholder = selected_port_list
        .as_deref()
        .unwrap_or("<created-port-list-id>");
    let planned_targets = hosts
        .iter()
        .map(|host| target_body(host, placeholder, &timestamp))
        .collect::<Vec<_>>();
    if dry_run {
        details["planned_targets"] = json!(planned_targets);
        if let Some(ranges) = &ranges {
            let name = port_list_name
                .map(str::to_string)
                .unwrap_or_else(|| default_port_list_name(hosts_file));
            details["planned_port_list"] = json!({
                "name": name,
                "comment": "Created by YAFVS native-targets-from-host-list",
                "port_ranges": ranges,
            });
        }
        findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.dry-run"),
            "Dry run planned native port-list/target writes without runtime access.".into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native host-list target creation dry run completed.",
                findings,
                details,
            ),
            status_only,
        );
    }

    if !allow_write_control {
        findings.push(Finding::new(
            "fail",
            &format!("{COMMAND}.write-control-intent"),
            "Creating targets requires --allow-write-control.".into(),
        ));
        return finish_status(
            envelope(
                root,
                runner,
                "Native host-list target creation rejected before runtime access.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut config_recorded = false;
    if let Some(ranges) = &ranges {
        let body = json!({
            "name": port_list_name
                .map(str::to_string)
                .unwrap_or_else(|| default_port_list_name(hosts_file)),
            "comment": "Created by YAFVS native-targets-from-host-list",
            "port_ranges": ranges,
        });
        let reply = match api.call(
            root,
            "/api/v1/port-lists",
            "POST",
            Some(&body),
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        ) {
            Ok(reply) => reply,
            Err(mut rejected) => {
                findings.append(&mut rejected);
                return finish_status(
                    envelope(
                        root,
                        runner,
                        "Direct native API target creation rejected before runtime access.",
                        findings,
                        details,
                    ),
                    status_only,
                );
            }
        };
        let id = acknowledged_id(&reply, 201);
        findings.push(reply.config);
        config_recorded = true;
        let ok = id.is_some();
        findings.push(
            Finding::new(
                if ok { "pass" } else { "fail" },
                &format!("{COMMAND}.port-list-create"),
                if ok {
                    "Created a native port list for host-list target creation.".into()
                } else {
                    "Failed to create the native port list for host-list target creation.".into()
                },
            )
            .with_details(json!({"http_status":reply.http_status,"port_list_id":id})),
        );
        let Some(id) = id else {
            return finish_status(
                envelope(
                    root,
                    runner,
                    "Native host-list target creation failed before target creation.",
                    findings,
                    details,
                ),
                status_only,
            );
        };
        details["port_list_id"] = json!(id);
        details["port_list_created"] = json!(true);
        selected_port_list = Some(id);
    }

    let port_list_id = selected_port_list.expect("existing or newly created port list");
    let mut created_ids = Vec::new();
    for (index, host) in hosts.iter().enumerate() {
        let body = target_body(host, &port_list_id, &timestamp);
        let reply = match api.call(
            root,
            "/api/v1/targets",
            "POST",
            Some(&body),
            &format!("{COMMAND}.request-body"),
            &format!("{COMMAND}.direct-config-shape"),
            &format!("{COMMAND}.direct-token-strength"),
            runner,
        ) {
            Ok(reply) => reply,
            Err(mut rejected) => {
                if config_recorded {
                    rejected.retain(|finding| {
                        finding.check != format!("{COMMAND}.direct-config-shape")
                    });
                }
                findings.append(&mut rejected);
                findings.push(
                    Finding::new(
                        "fail",
                        &format!("{COMMAND}.target-create"),
                        format!(
                            "Failed to create target {} of {} through the native API.",
                            index + 1,
                            hosts.len()
                        ),
                    )
                    .with_details(json!({"target_index":index + 1})),
                );
                break;
            }
        };
        let id = acknowledged_id(&reply, 201);
        if !config_recorded {
            findings.push(reply.config);
            config_recorded = true;
        }
        if let Some(id) = &id {
            created_ids.push(id.clone());
        }
        let ok = id.is_some();
        findings.push(
            Finding::new(
                if ok { "pass" } else { "fail" },
                &format!("{COMMAND}.target-create"),
                if ok {
                    format!(
                        "Created target {} of {} through the native API.",
                        index + 1,
                        hosts.len()
                    )
                } else {
                    format!(
                        "Failed to create target {} of {} through the native API.",
                        index + 1,
                        hosts.len()
                    )
                },
            )
            .with_details(json!({
                "http_status":reply.http_status,
                "target_id":id,
                "target_index":index + 1,
            })),
        );
        details["created_target_count"] = json!(created_ids.len());
        details["created_target_ids"] = json!(created_ids);
        if !ok {
            break;
        }
    }

    let failed = findings.iter().any(|finding| finding.status == "fail");
    finish_status(
        envelope(
            root,
            runner,
            if failed {
                "Native host-list target creation failed."
            } else {
                "Native host-list target creation completed."
            },
            findings,
            details,
        ),
        status_only,
    )
}

fn default_port_list_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("hosts");
    format!("Port list for target {stem}")
}

fn acknowledged_id(reply: &ApiReply, expected_status: i64) -> Option<String> {
    if reply.oversized || !reply.output.success || reply.http_status != Some(expected_status) {
        return None;
    }
    let id = reply
        .parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("id"))
        .and_then(Value::as_str)?;
    validate_operator_uuid(id, "response id").ok()
}

fn finish_status(mut result: ResultEnvelope, status_only: bool) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    let details = result
        .details
        .as_ref()
        .cloned()
        .unwrap_or_else(|| json!({}));
    result.details = Some(json!({
        "hosts_file": details.get("hosts_file"),
        "host_count": details.get("host_count").and_then(Value::as_u64).unwrap_or(0),
        "dry_run": details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        "port_list_id": details.get("port_list_id"),
        "port_list_created": details.get("port_list_created").and_then(Value::as_bool).unwrap_or(false),
        "created_target_count": details.get("created_target_count").and_then(Value::as_u64).unwrap_or(0),
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{COMMAND}.status-only"),
            "Native host-list target creation passed; details summarized.".into(),
        ));
    }
    result
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct XmlTargetBuilder {
    name: Option<String>,
    hosts: Option<String>,
    exclude_hosts: Option<String>,
    comment: Option<String>,
    alive_tests: Option<String>,
    reverse_lookup_only: Option<String>,
    reverse_lookup_unify: Option<String>,
    port_list_id: Option<String>,
    port_range: Option<String>,
    credentials: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct XmlTargetRow {
    row_number: usize,
    name: String,
    body: Value,
}

pub fn command_native_targets_from_xml(
    root: &Path,
    xml_file: &Path,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    let rows = match load_xml_rows(xml_file) {
        Ok(rows) => rows,
        Err(error) => {
            return finish_xml_status(
                xml_envelope(
                    root,
                    &SystemCommandRunner,
                    "Native XML target import rejected before runtime access.",
                    vec![
                        Finding::new("fail", &format!("{XML_COMMAND}.rows"), error)
                            .with_details(json!({"xml_file":xml_file})),
                    ],
                    xml_base_details(xml_file, dry_run),
                ),
                status_only,
            );
        }
    };
    command_xml_with(
        root,
        xml_file,
        rows,
        allow_write_control,
        dry_run,
        status_only,
        &SystemCommandRunner,
        &GuardedApi,
    )
}

fn xml_envelope(
    root: &Path,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
) -> ResultEnvelope {
    make_result(
        metadata(root, XML_COMMAND, runner),
        summary.into(),
        findings,
    )
    .with_details(details)
}

fn xml_base_details(xml_file: &Path, dry_run: bool) -> Value {
    json!({
        "xml_file": xml_file,
        "row_count": 0,
        "dry_run": dry_run,
        "created_target_count": 0,
        "created_target_ids": [],
    })
}

fn read_bounded_xml_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read target XML file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read target XML file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("failed to read target XML file: path is not a regular file".into());
    }
    if metadata.len() > MAX_XML_FILE_BYTES as u64 {
        return Err(format!(
            "failed to read target XML file: file exceeds the {MAX_XML_FILE_BYTES} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_XML_FILE_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read target XML file: {error}"))?;
    if input.len() > MAX_XML_FILE_BYTES {
        return Err(format!(
            "failed to read target XML file: file exceeds the {MAX_XML_FILE_BYTES} byte limit"
        ));
    }
    Ok(input)
}

fn load_xml_rows(path: &Path) -> Result<Vec<XmlTargetRow>, String> {
    parse_xml_rows(&read_bounded_xml_file(path)?)
}

fn parse_xml_rows(input: &[u8]) -> Result<Vec<XmlTargetRow>, String> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().check_end_names = true;
    let mut rows = Vec::new();
    let mut root_seen = false;
    let mut root_complete = false;
    loop {
        match reader.read_event() {
            Ok(Event::Decl(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(Event::DocType(_)) => {
                return Err("failed to parse target XML file: DTDs are not supported".into());
            }
            Ok(Event::Text(text)) => {
                let value = decode_xml_text(&text)?;
                if !value.trim().is_empty() {
                    return Err(
                        "failed to parse target XML file: text outside the root element".into(),
                    );
                }
            }
            Ok(Event::Start(start)) if !root_seen => {
                root_seen = true;
                let end = start.name();
                parse_xml_root(&mut reader, end, &mut rows)?;
                root_complete = true;
            }
            Ok(Event::Empty(_)) if !root_seen => {
                root_seen = true;
                root_complete = true;
            }
            Ok(Event::Start(_)) | Ok(Event::Empty(_)) => {
                return Err(
                    "failed to parse target XML file: multiple root elements are not supported"
                        .into(),
                );
            }
            Ok(Event::End(_)) => {
                return Err("failed to parse target XML file: unexpected closing element".into());
            }
            Ok(Event::CData(data)) => {
                let value = data
                    .decode()
                    .map_err(|error| format!("failed to parse target XML file: {error}"))?;
                if !value.trim().is_empty() {
                    return Err(
                        "failed to parse target XML file: text outside the root element".into(),
                    );
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(format!("failed to parse target XML file: {error}"));
            }
        }
    }
    if !root_seen || !root_complete {
        return Err("failed to parse target XML file: missing complete root element".into());
    }
    if rows.is_empty() {
        return Err("target XML file does not contain any <target> rows".into());
    }
    Ok(rows)
}

fn parse_xml_root(
    reader: &mut Reader<&[u8]>,
    root_end: QName<'_>,
    rows: &mut Vec<XmlTargetRow>,
) -> Result<(), String> {
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) if start.name().as_ref() == b"target" => {
                if rows.len() >= MAX_XML_ROWS {
                    return Err(format!(
                        "target XML file must contain at most {MAX_XML_ROWS} target rows"
                    ));
                }
                let row_number = rows.len() + 1;
                rows.push(parse_xml_target(reader, start.name(), row_number)?);
            }
            Ok(Event::Empty(start)) if start.name().as_ref() == b"target" => {
                return Err("target row is missing required <name> text".into());
            }
            Ok(Event::Start(start)) => {
                reader
                    .read_to_end(start.name())
                    .map_err(|error| format!("failed to parse target XML file: {error}"))?;
            }
            Ok(Event::Empty(_)) | Ok(Event::Text(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {
            }
            Ok(Event::DocType(_)) => {
                return Err("failed to parse target XML file: DTDs are not supported".into());
            }
            Ok(Event::End(end)) if end.name() == root_end => return Ok(()),
            Ok(Event::End(_)) => {
                return Err("failed to parse target XML file: unexpected closing element".into());
            }
            Ok(Event::Eof) => {
                return Err("failed to parse target XML file: incomplete root element".into());
            }
            Ok(_) => {}
            Err(error) => return Err(format!("failed to parse target XML file: {error}")),
        }
    }
}

fn parse_xml_target(
    reader: &mut Reader<&[u8]>,
    target_end: QName<'_>,
    row_number: usize,
) -> Result<XmlTargetRow, String> {
    let mut builder = XmlTargetBuilder::default();
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = start.name();
                match name.as_ref() {
                    b"name"
                    | b"hosts"
                    | b"exclude_hosts"
                    | b"comment"
                    | b"alive_tests"
                    | b"reverse_lookup_only"
                    | b"reverse_lookup_unify"
                    | b"port_range" => {
                        let value = read_xml_element_text(reader, name)?;
                        set_xml_scalar(&mut builder, name.as_ref(), value);
                    }
                    b"port_list" => {
                        if builder.port_list_id.is_none() {
                            builder.port_list_id = xml_attribute(&start, b"id", reader.decoder())?;
                        }
                        reader
                            .read_to_end(name)
                            .map_err(|error| format!("failed to parse target XML file: {error}"))?;
                    }
                    b"ssh_credential" | b"smb_credential" | b"esxi_credential"
                    | b"snmp_credential" => {
                        let native_name = xml_credential_name(name.as_ref());
                        if !builder.credentials.contains_key(native_name) {
                            if let Some(link) =
                                parse_xml_credential(reader, &start, row_number, native_name)?
                            {
                                builder.credentials.insert(native_name.into(), link);
                            }
                        } else {
                            reader.read_to_end(name).map_err(|error| {
                                format!("failed to parse target XML file: {error}")
                            })?;
                        }
                    }
                    _ => {
                        reader
                            .read_to_end(name)
                            .map_err(|error| format!("failed to parse target XML file: {error}"))?;
                    }
                }
            }
            Ok(Event::Empty(start)) => match start.name().as_ref() {
                b"name"
                | b"hosts"
                | b"exclude_hosts"
                | b"comment"
                | b"alive_tests"
                | b"reverse_lookup_only"
                | b"reverse_lookup_unify"
                | b"port_range" => {
                    set_xml_scalar(&mut builder, start.name().as_ref(), String::new());
                }
                b"port_list" => {
                    if builder.port_list_id.is_none() {
                        builder.port_list_id = xml_attribute(&start, b"id", reader.decoder())?;
                    }
                }
                b"ssh_credential" | b"smb_credential" | b"esxi_credential" | b"snmp_credential" => {
                    let native_name = xml_credential_name(start.name().as_ref());
                    if !builder.credentials.contains_key(native_name)
                        && let Some(link) =
                            parse_empty_xml_credential(&start, row_number, native_name, reader)?
                    {
                        builder.credentials.insert(native_name.into(), link);
                    }
                }
                _ => {}
            },
            Ok(Event::DocType(_)) => {
                return Err("failed to parse target XML file: DTDs are not supported".into());
            }
            Ok(Event::End(end)) if end.name() == target_end => {
                return finish_xml_target(builder, row_number);
            }
            Ok(Event::End(_)) => {
                return Err("failed to parse target XML file: unexpected closing element".into());
            }
            Ok(Event::Eof) => {
                return Err("failed to parse target XML file: incomplete <target> row".into());
            }
            Ok(_) => {}
            Err(error) => return Err(format!("failed to parse target XML file: {error}")),
        }
    }
}

fn set_xml_scalar(builder: &mut XmlTargetBuilder, name: &[u8], value: String) {
    let slot = match name {
        b"name" => &mut builder.name,
        b"hosts" => &mut builder.hosts,
        b"exclude_hosts" => &mut builder.exclude_hosts,
        b"comment" => &mut builder.comment,
        b"alive_tests" => &mut builder.alive_tests,
        b"reverse_lookup_only" => &mut builder.reverse_lookup_only,
        b"reverse_lookup_unify" => &mut builder.reverse_lookup_unify,
        b"port_range" => &mut builder.port_range,
        _ => return,
    };
    if slot.is_none() {
        *slot = Some(value);
    }
}

fn decode_xml_text(text: &quick_xml::events::BytesText<'_>) -> Result<String, String> {
    text.xml10_content()
        .map(|value| value.into_owned())
        .map_err(|error| format!("failed to parse target XML file: {error}"))
}

fn decode_xml_reference(reference: &quick_xml::events::BytesRef<'_>) -> Result<char, String> {
    if let Some(value) = reference
        .resolve_char_ref()
        .map_err(|error| format!("failed to parse target XML file: {error}"))?
    {
        return Ok(value);
    }
    match reference
        .decode()
        .map_err(|error| format!("failed to parse target XML file: {error}"))?
        .as_ref()
    {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        other => Err(format!(
            "failed to parse target XML file: unsupported entity reference &{other};"
        )),
    }
}

fn read_xml_element_text(reader: &mut Reader<&[u8]>, end: QName<'_>) -> Result<String, String> {
    let mut value = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Text(text)) => value.push_str(&decode_xml_text(&text)?),
            Ok(Event::GeneralRef(reference)) => {
                value.push(decode_xml_reference(&reference)?);
            }
            Ok(Event::CData(data)) => value.push_str(
                data.decode()
                    .map_err(|error| format!("failed to parse target XML file: {error}"))?
                    .as_ref(),
            ),
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(Event::End(found)) if found.name() == end => break,
            Ok(Event::Start(_)) | Ok(Event::Empty(_)) => {
                return Err(
                    "failed to parse target XML file: nested scalar content is not supported"
                        .into(),
                );
            }
            Ok(Event::DocType(_)) => {
                return Err("failed to parse target XML file: DTDs are not supported".into());
            }
            Ok(Event::Eof) => {
                return Err("failed to parse target XML file: incomplete scalar element".into());
            }
            Ok(_) => {}
            Err(error) => return Err(format!("failed to parse target XML file: {error}")),
        }
        if value.len() > MAX_XML_TEXT_BYTES {
            return Err(format!(
                "target XML scalar text exceeds the {MAX_XML_TEXT_BYTES} byte limit"
            ));
        }
    }
    Ok(value.trim().to_string())
}

fn xml_attribute(
    start: &BytesStart<'_>,
    name: &[u8],
    decoder: quick_xml::encoding::Decoder,
) -> Result<Option<String>, String> {
    for attribute in start.attributes() {
        let attribute =
            attribute.map_err(|error| format!("failed to parse target XML file: {error}"))?;
        if attribute.key.as_ref() != name {
            continue;
        }
        let value = attribute
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
            .map_err(|error| format!("failed to parse target XML file: {error}"))?;
        return Ok(Some(value.trim().to_string()));
    }
    Ok(None)
}

fn xml_credential_name(name: &[u8]) -> &'static str {
    match name {
        b"ssh_credential" => "ssh",
        b"smb_credential" => "smb",
        b"esxi_credential" => "esxi",
        b"snmp_credential" => "snmp",
        _ => unreachable!("caller restricts XML credential names"),
    }
}

fn parse_empty_xml_credential(
    start: &BytesStart<'_>,
    row_number: usize,
    native_name: &str,
    reader: &Reader<&[u8]>,
) -> Result<Option<Value>, String> {
    let Some(id) = xml_attribute(start, b"id", reader.decoder())? else {
        return Ok(None);
    };
    xml_credential_value(id, None, row_number, native_name)
}

fn parse_xml_credential(
    reader: &mut Reader<&[u8]>,
    start: &BytesStart<'_>,
    row_number: usize,
    native_name: &str,
) -> Result<Option<Value>, String> {
    let id = xml_attribute(start, b"id", reader.decoder())?.unwrap_or_default();
    if id.is_empty() {
        reader
            .read_to_end(start.name())
            .map_err(|error| format!("failed to parse target XML file: {error}"))?;
        return Ok(None);
    }
    let mut port = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(child)) if child.name().as_ref() == b"port" => {
                let value = read_xml_element_text(reader, child.name())?;
                if port.is_none() {
                    port = Some(value);
                }
            }
            Ok(Event::Empty(child)) if child.name().as_ref() == b"port" => {
                if port.is_none() {
                    port = Some(String::new());
                }
            }
            Ok(Event::Start(child)) => {
                reader
                    .read_to_end(child.name())
                    .map_err(|error| format!("failed to parse target XML file: {error}"))?;
            }
            Ok(Event::Empty(_)) | Ok(Event::Text(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {
            }
            Ok(Event::DocType(_)) => {
                return Err("failed to parse target XML file: DTDs are not supported".into());
            }
            Ok(Event::End(end)) if end.name() == start.name() => break,
            Ok(Event::End(_)) => {
                return Err("failed to parse target XML file: unexpected closing element".into());
            }
            Ok(Event::Eof) => {
                return Err(
                    "failed to parse target XML file: incomplete credential element".into(),
                );
            }
            Ok(_) => {}
            Err(error) => return Err(format!("failed to parse target XML file: {error}")),
        }
    }
    xml_credential_value(id, port, row_number, native_name)
}

fn xml_credential_value(
    id: String,
    port: Option<String>,
    row_number: usize,
    native_name: &str,
) -> Result<Option<Value>, String> {
    if id.is_empty() {
        return Ok(None);
    }
    if validate_operator_uuid(&id, "credential id").is_err() {
        return Err(format!(
            "target row {row_number} {native_name}_credential id must be a UUID"
        ));
    }
    let mut link = Map::new();
    link.insert("id".into(), json!(id));
    if let Some(port) = port.filter(|value| !value.is_empty()) {
        if native_name != "ssh" {
            return Err(format!(
                "target row {row_number} {native_name}_credential ports are not native-safe yet"
            ));
        }
        let port = port.parse::<u32>().map_err(|_| {
            format!("target row {row_number} ssh_credential port must be an integer")
        })?;
        if !(1..=65_535).contains(&port) {
            return Err(format!(
                "target row {row_number} ssh_credential port must be within 1..65535"
            ));
        }
        link.insert("port".into(), json!(port));
    }
    Ok(Some(Value::Object(link)))
}

fn finish_xml_target(builder: XmlTargetBuilder, row_number: usize) -> Result<XmlTargetRow, String> {
    let name = builder
        .name
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "target row is missing required <name> text".to_string())?;
    let hosts_text = builder
        .hosts
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "target row is missing required <hosts> text".to_string())?;
    let hosts = split_xml_list(&hosts_text)?;
    if hosts.is_empty() {
        return Err(format!(
            "target row {row_number} must include at least one host"
        ));
    }
    let exclude_hosts = split_xml_list(builder.exclude_hosts.as_deref().unwrap_or(""))?;
    let port_list_id = builder.port_list_id.unwrap_or_default();
    if validate_operator_uuid(&port_list_id, "port_list id").is_err() {
        return Err(format!(
            "target row {row_number} must include a port_list id UUID"
        ));
    }
    if builder
        .port_range
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(format!(
            "target row {row_number} port_range is not native-safe; use a port_list id"
        ));
    }
    let alive_test = builder
        .alive_tests
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_ALIVE_TEST.into());
    let reverse_lookup_only = parse_xml_flag(
        builder.reverse_lookup_only.as_deref(),
        "reverse_lookup_only",
    )?;
    let reverse_lookup_unify = parse_xml_flag(
        builder.reverse_lookup_unify.as_deref(),
        "reverse_lookup_unify",
    )?;
    let mut body = json!({
        "name": name,
        "comment": builder.comment.filter(|value| !value.is_empty()),
        "port_list_id": port_list_id,
        "hosts": hosts,
        "exclude_hosts": exclude_hosts,
        "alive_tests": [alive_test],
        "allow_simultaneous_ips": false,
        "reverse_lookup_only": reverse_lookup_only,
        "reverse_lookup_unify": reverse_lookup_unify,
    });
    if !builder.credentials.is_empty() {
        body["credentials"] = Value::Object(builder.credentials);
    }
    Ok(XmlTargetRow {
        row_number,
        name: body["name"].as_str().unwrap_or_default().to_string(),
        body,
    })
}

fn split_xml_list(value: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.len() > MAX_HOST_BYTES {
            return Err(format!(
                "target XML list entries must be at most {MAX_HOST_BYTES} bytes"
            ));
        }
        values.push(item.to_string());
        if values.len() > MAX_XML_LIST_ITEMS {
            return Err(format!(
                "target XML lists must contain at most {MAX_XML_LIST_ITEMS} entries"
            ));
        }
    }
    Ok(values)
}

fn parse_xml_flag(value: Option<&str>, name: &str) -> Result<bool, String> {
    match value.unwrap_or("").trim() {
        "" | "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("<{name}> must be empty, 0, or 1")),
    }
}

#[allow(clippy::too_many_arguments)]
fn command_xml_with(
    root: &Path,
    xml_file: &Path,
    rows: Vec<XmlTargetRow>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
) -> ResultEnvelope {
    let mut details = xml_base_details(xml_file, dry_run);
    details["row_count"] = json!(rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{XML_COMMAND}.rows"),
        format!("Loaded {} target XML row(s).", rows.len()),
    )];
    if dry_run {
        details["planned_targets"] =
            Value::Array(rows.iter().map(|row| row.body.clone()).collect());
        findings.push(Finding::new(
            "pass",
            &format!("{XML_COMMAND}.dry-run"),
            "Dry run planned native target writes without runtime access.".into(),
        ));
        return finish_xml_status(
            xml_envelope(
                root,
                runner,
                "Native XML target import dry run completed.",
                findings,
                details,
            ),
            status_only,
        );
    }
    if !allow_write_control {
        findings.push(Finding::new(
            "fail",
            &format!("{XML_COMMAND}.write-control-intent"),
            "Creating targets requires --allow-write-control.".into(),
        ));
        return finish_xml_status(
            xml_envelope(
                root,
                runner,
                "Native XML target import rejected before runtime access.",
                findings,
                details,
            ),
            status_only,
        );
    }

    let mut created_ids = Vec::new();
    let mut failures = Vec::new();
    let mut config_recorded = false;
    for row in &rows {
        let reply = match api.call(
            root,
            "/api/v1/targets",
            "POST",
            Some(&row.body),
            &format!("{XML_COMMAND}.request-body"),
            &format!("{XML_COMMAND}.direct-config-shape"),
            &format!("{XML_COMMAND}.direct-token-strength"),
            runner,
        ) {
            Ok(reply) => reply,
            Err(mut rejected) => {
                if config_recorded {
                    rejected.retain(|finding| {
                        finding.check != format!("{XML_COMMAND}.direct-config-shape")
                    });
                }
                findings.append(&mut rejected);
                failures.push(json!({
                    "row": row.row_number,
                    "name": row.name,
                    "http_status": null,
                }));
                break;
            }
        };
        let id = acknowledged_id(&reply, 201);
        if !config_recorded {
            findings.push(reply.config);
            config_recorded = true;
        }
        if let Some(id) = id {
            created_ids.push(id);
            continue;
        }
        failures.push(json!({
            "row": row.row_number,
            "name": row.name,
            "http_status": reply.http_status,
        }));
        break;
    }
    details["created_target_ids"] = json!(created_ids);
    details["created_target_count"] = json!(created_ids.len());
    if failures.is_empty() {
        findings.push(Finding::new(
            "pass",
            &format!("{XML_COMMAND}.target-create"),
            format!(
                "Created {} target(s) through the native API.",
                created_ids.len()
            ),
        ));
    } else {
        details["create_failures"] = json!(failures);
        findings.push(
            Finding::new(
                "fail",
                &format!("{XML_COMMAND}.target-create"),
                "One or more native target create requests failed.".into(),
            )
            .with_details(json!({"failure_count":failures.len(),"failures":failures})),
        );
    }
    let failed = findings.iter().any(|finding| finding.status == "fail");
    finish_xml_status(
        xml_envelope(
            root,
            runner,
            if failed {
                "Native XML target import failed."
            } else {
                "Native XML target import completed."
            },
            findings,
            details,
        ),
        status_only,
    )
}

fn finish_xml_status(mut result: ResultEnvelope, status_only: bool) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    let details = result
        .details
        .as_ref()
        .cloned()
        .unwrap_or_else(|| json!({}));
    result.details = Some(json!({
        "xml_file": details.get("xml_file"),
        "row_count": details.get("row_count").and_then(Value::as_u64).unwrap_or(0),
        "dry_run": details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        "created_target_count": details.get("created_target_count").and_then(Value::as_u64).unwrap_or(0),
    }));
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{XML_COMMAND}.status-only"),
            "Native XML target import passed; details summarized.".into(),
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessOutput;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::Mutex;

    struct Runner;
    impl CommandRunner for Runner {
        fn run(&self, program: &str, _args: &[&str]) -> Option<ProcessOutput> {
            (program == "git").then(|| ProcessOutput {
                success: true,
                exit_code: Some(0),
                stdout: "deadbeef\n".into(),
                stderr: String::new(),
            })
        }
    }

    struct FakeApi {
        replies: Mutex<VecDeque<Result<ApiReply, Vec<Finding>>>>,
        calls: Mutex<Vec<(String, String, Value)>>,
    }

    impl FakeApi {
        fn new(replies: Vec<Result<ApiReply, Vec<Finding>>>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl TargetApi for FakeApi {
        fn call(
            &self,
            _root: &Path,
            path: &str,
            method: &str,
            body: Option<&Value>,
            _request_check: &str,
            _config_check: &str,
            _token_check: &str,
            _runner: &dyn CommandRunner,
        ) -> Result<ApiReply, Vec<Finding>> {
            self.calls.lock().unwrap().push((
                path.into(),
                method.into(),
                body.cloned().unwrap_or(Value::Null),
            ));
            self.replies.lock().unwrap().pop_front().unwrap()
        }
    }

    fn reply(status: i64, body: Value) -> Result<ApiReply, Vec<Finding>> {
        Ok(ApiReply {
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
                &format!("{COMMAND}.direct-config-shape"),
                "valid".into(),
            ),
        })
    }

    #[test]
    fn securely_loads_bounded_nonempty_host_lines() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "yafvsctl-target-host-list-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("hosts.txt");
        fs::write(&path, "192.0.2.10\n\n example.invalid \n").unwrap();
        assert_eq!(
            load_hosts(&path).unwrap(),
            ["192.0.2.10", "example.invalid"]
        );
        let link = directory.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_hosts(&link).unwrap_err().contains("failed to read"));
        assert!(
            load_hosts(&directory)
                .unwrap_err()
                .contains("not a regular file")
        );

        let oversized = directory.join("oversized.txt");
        fs::write(&oversized, vec![b'x'; MAX_HOST_FILE_BYTES + 1]).unwrap();
        assert!(load_hosts(&oversized).unwrap_err().contains("byte limit"));

        let long_entry = directory.join("long-entry.txt");
        fs::write(&long_entry, "x".repeat(MAX_HOST_BYTES + 1)).unwrap();
        assert!(
            load_hosts(&long_entry)
                .unwrap_err()
                .contains("at most 4096 bytes")
        );

        let too_many = directory.join("too-many.txt");
        fs::write(&too_many, "x\n".repeat(MAX_HOSTS + 1)).unwrap();
        assert!(load_hosts(&too_many).unwrap_err().contains("at most 4095"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn parses_and_rejects_port_ranges_exactly() {
        assert_eq!(
            serde_json::to_value(parse_port_ranges("T:1-443,U:53").unwrap()).unwrap(),
            json!([
                {"protocol":"tcp","start":1,"end":443,"comment":"YAFVS native host-list target import"},
                {"protocol":"udp","start":53,"end":53,"comment":"YAFVS native host-list target import"}
            ])
        );
        for invalid in ["1-443", "T:0-1", "U:10-9", ","] {
            assert!(parse_port_ranges(invalid).is_err(), "{invalid}");
        }
        assert!(
            parse_port_ranges(&"T:1,".repeat(MAX_PORT_RANGES + 1))
                .unwrap_err()
                .contains("at most 4095")
        );
        assert!(
            serialize_request_body(&json!({"name":"x".repeat(MAX_REQUEST_BODY_BYTES)}))
                .unwrap_err()
                .contains("byte limit")
        );
    }

    #[test]
    fn dry_run_is_secret_free_and_never_calls_api() {
        let api = FakeApi::new(Vec::new());
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("hosts.txt"),
            vec!["192.0.2.10".into(), "192.0.2.11".into()],
            None,
            Some("T:1-443,U:53"),
            Some("Web and DNS"),
            false,
            true,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "pass");
        let details = result.details.unwrap();
        assert_eq!(details["planned_port_list"]["name"], "Web and DNS");
        assert_eq!(
            details["planned_targets"][0]["hosts"],
            json!(["192.0.2.10"])
        );
        assert_eq!(
            details["planned_targets"][0]["alive_tests"],
            json!(["Scan Config Default"])
        );
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn write_intent_is_required_before_runtime_access() {
        let api = FakeApi::new(Vec::new());
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("hosts.txt"),
            vec!["192.0.2.10".into()],
            None,
            None,
            None,
            false,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.findings.last().unwrap().check,
            "native-targets-from-host-list.write-control-intent"
        );
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn creates_port_list_then_targets_sequentially() {
        let api = FakeApi::new(vec![
            reply(201, json!({"id":"11111111-1111-4111-8111-111111111111"})),
            reply(201, json!({"id":"22222222-2222-4222-8222-222222222221"})),
            reply(201, json!({"id":"22222222-2222-4222-8222-222222222222"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("hosts.txt"),
            vec!["192.0.2.10".into(), "192.0.2.11".into()],
            None,
            Some("T:1-443"),
            Some("Web"),
            true,
            false,
            true,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "pass");
        assert_eq!(result.details.as_ref().unwrap()["created_target_count"], 2);
        assert_eq!(result.details.as_ref().unwrap()["port_list_created"], true);
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "/api/v1/port-lists");
        assert_eq!(calls[1].0, "/api/v1/targets");
        assert_eq!(calls[2].0, "/api/v1/targets");
        assert_eq!(
            calls[1].2["port_list_id"],
            "11111111-1111-4111-8111-111111111111"
        );
    }

    #[test]
    fn stops_after_first_target_failure_and_retains_prior_count() {
        let api = FakeApi::new(vec![
            reply(201, json!({"id":"22222222-2222-4222-8222-222222222221"})),
            reply(500, json!({"error":{"code":"failed"}})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("hosts.txt"),
            vec![
                "192.0.2.10".into(),
                "192.0.2.11".into(),
                "192.0.2.12".into(),
            ],
            Some(DEFAULT_PORT_LIST_ID),
            None,
            None,
            true,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["created_target_count"], 1);
        assert_eq!(api.calls.lock().unwrap().len(), 2);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("\"error\"")
        );
    }

    #[test]
    fn wrong_or_missing_acknowledgement_id_fails_without_retaining_body() {
        let api = FakeApi::new(vec![reply(
            201,
            json!({"id":"not-a-uuid","secret":"do-not-retain"}),
        )]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("hosts.txt"),
            vec!["192.0.2.10".into()],
            Some(DEFAULT_PORT_LIST_ID),
            None,
            None,
            true,
            false,
            false,
            &Runner,
            &api,
            "2026-07-19T12:00:00+00:00".into(),
        );
        assert_eq!(result.status, "fail");
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-retain")
        );
    }

    fn xml_fixture() -> &'static str {
        r#"<targets>
  <target>
    <name>XML target</name>
    <hosts>192.0.2.10, 192.0.2.11</hosts>
    <exclude_hosts>192.0.2.99</exclude_hosts>
    <comment>Imported &amp; reviewed</comment>
    <alive_tests>ICMP Ping</alive_tests>
    <reverse_lookup_only>1</reverse_lookup_only>
    <reverse_lookup_unify>0</reverse_lookup_unify>
    <ssh_credential id="55555555-5555-4555-8555-555555555555"><port>2222</port></ssh_credential>
    <smb_credential id="44444444-4444-4444-8444-444444444444" />
    <port_list id="11111111-1111-4111-8111-111111111111" />
  </target>
</targets>"#
    }

    #[test]
    fn parses_retained_xml_subset_into_secret_free_body() {
        let rows = parse_xml_rows(xml_fixture().as_bytes()).unwrap();
        assert_eq!(rows.len(), 1);
        let body = &rows[0].body;
        assert_eq!(body["name"], "XML target");
        assert_eq!(body["hosts"], json!(["192.0.2.10", "192.0.2.11"]));
        assert_eq!(body["exclude_hosts"], json!(["192.0.2.99"]));
        assert_eq!(body["comment"], "Imported & reviewed");
        assert_eq!(body["alive_tests"], json!(["ICMP Ping"]));
        assert_eq!(body["reverse_lookup_only"], true);
        assert_eq!(body["reverse_lookup_unify"], false);
        assert_eq!(body["credentials"]["ssh"]["port"], 2222);
        assert_eq!(
            body["credentials"]["smb"]["id"],
            "44444444-4444-4444-8444-444444444444"
        );
        assert!(!serde_json::to_string(body).unwrap().contains("password"));
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_xml_before_runtime() {
        let legacy_range = xml_fixture().replace(
            "<port_list id=\"11111111-1111-4111-8111-111111111111\" />",
            "<port_range>T:1-443</port_range><port_list id=\"11111111-1111-4111-8111-111111111111\" />",
        );
        assert!(
            parse_xml_rows(legacy_range.as_bytes())
                .unwrap_err()
                .contains("port_range is not native-safe")
        );
        let smb_port = xml_fixture().replace(
            "<smb_credential id=\"44444444-4444-4444-8444-444444444444\" />",
            "<smb_credential id=\"44444444-4444-4444-8444-444444444444\"><port>445</port></smb_credential>",
        );
        assert!(
            parse_xml_rows(smb_port.as_bytes())
                .unwrap_err()
                .contains("ports are not native-safe")
        );
        assert!(
            parse_xml_rows(b"<!DOCTYPE targets><targets/>")
                .unwrap_err()
                .contains("DTDs are not supported")
        );
        assert!(
            parse_xml_rows(
                b"<targets><target><name><nested/></name><hosts>x</hosts><port_list id=\"11111111-1111-4111-8111-111111111111\"/></target></targets>"
            )
            .unwrap_err()
            .contains("nested scalar content")
        );
        let bad_flag = xml_fixture().replace(
            "<reverse_lookup_only>1</reverse_lookup_only>",
            "<reverse_lookup_only>true</reverse_lookup_only>",
        );
        assert!(
            parse_xml_rows(bad_flag.as_bytes())
                .unwrap_err()
                .contains("must be empty, 0, or 1")
        );
    }

    #[test]
    fn securely_loads_bounded_xml_file() {
        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "yafvsctl-target-xml-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("targets.xml");
        fs::write(&path, xml_fixture()).unwrap();
        assert_eq!(load_xml_rows(&path).unwrap().len(), 1);
        let link = directory.join("targets-link.xml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_xml_rows(&link).unwrap_err().contains("failed to read"));
        assert!(
            load_xml_rows(&directory)
                .unwrap_err()
                .contains("not a regular file")
        );
        let oversized = directory.join("oversized.xml");
        fs::write(&oversized, vec![b'x'; MAX_XML_FILE_BYTES + 1]).unwrap();
        assert!(
            load_xml_rows(&oversized)
                .unwrap_err()
                .contains("byte limit")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn xml_dry_run_and_write_refusal_never_call_api() {
        let rows = parse_xml_rows(xml_fixture().as_bytes()).unwrap();
        let api = FakeApi::new(Vec::new());
        let dry_run = command_xml_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.xml"),
            rows.clone(),
            false,
            true,
            true,
            &Runner,
            &api,
        );
        assert_eq!(dry_run.status, "pass");
        assert_eq!(dry_run.details.as_ref().unwrap()["row_count"], 1);
        assert!(api.calls.lock().unwrap().is_empty());
        let refused = command_xml_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.xml"),
            rows,
            false,
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(refused.status, "fail");
        assert_eq!(
            refused.findings.last().unwrap().check,
            "native-targets-from-xml.write-control-intent"
        );
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn xml_creation_stops_at_first_failure_and_keeps_prior_success() {
        let first = parse_xml_rows(xml_fixture().as_bytes()).unwrap().remove(0);
        let mut second = first.clone();
        second.row_number = 2;
        second.name = "Second target".into();
        second.body["name"] = json!("Second target");
        let mut third = first.clone();
        third.row_number = 3;
        third.name = "Third target".into();
        third.body["name"] = json!("Third target");
        let api = FakeApi::new(vec![
            reply(201, json!({"id":"66666666-6666-4666-8666-666666666661"})),
            reply(500, json!({"secret":"do-not-retain"})),
        ]);
        let result = command_xml_with(
            Path::new("/srv/YAFVS"),
            Path::new("targets.xml"),
            vec![first, second, third],
            true,
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(result.details.as_ref().unwrap()["created_target_count"], 1);
        assert_eq!(api.calls.lock().unwrap().len(), 2);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-retain")
        );
    }
}
