// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded target import commands sharing one guarded native-API boundary.

use super::common::{iso_system_time, metadata};
use super::direct_api::validate_operator_uuid;
use super::native_api_request::{
    GuardedDirectApiCall, MAX_REQUEST_BODY_BYTES, guarded_direct_api_call,
};
use crate::process::{CommandRunner, ProcessOutput, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::OnceLock;
use std::time::SystemTime;

const COMMAND: &str = "native-targets-from-host-list";
const DEFAULT_PORT_LIST_ID: &str = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5";
const DEFAULT_ALIVE_TEST: &str = "Scan Config Default";
const MAX_HOST_FILE_BYTES: usize = 1024 * 1024;
const MAX_HOSTS: usize = 4095;
const MAX_HOST_BYTES: usize = 4096;
const MAX_PORT_RANGES: usize = 4095;

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
        body: &Value,
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
        body: &Value,
        config_check: &str,
        token_check: &str,
        runner: &dyn CommandRunner,
    ) -> Result<ApiReply, Vec<Finding>> {
        let body = serialize_request_body(body).map_err(|error| {
            vec![Finding::new(
                "fail",
                &format!("{COMMAND}.request-body"),
                error,
            )]
        })?;
        guarded_direct_api_call(
            root,
            path,
            method,
            None,
            Some(&body),
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
            &body,
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
            &body,
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
            body: &Value,
            _config_check: &str,
            _token_check: &str,
            _runner: &dyn CommandRunner,
        ) -> Result<ApiReply, Vec<Finding>> {
            self.calls
                .lock()
                .unwrap()
                .push((path.into(), method.into(), body.clone()));
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
}
