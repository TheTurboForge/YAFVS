// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Retained CSV/XML schedule import with bounded, fail-closed preflight.

use super::{ApiReply, GuardedApi, TargetApi, acknowledged_id};
use crate::commands::common::metadata;
use crate::commands::native_runtime::percent_encode_component;
use crate::process::{CommandRunner, SystemCommandRunner};
use crate::result::{Finding, ResultEnvelope, make_result};
use csv::ReaderBuilder;
use quick_xml::Reader;
use quick_xml::events::Event;
use quick_xml::name::QName;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Take};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const CSV_COMMAND: &str = "native-schedules-from-csv";
const XML_COMMAND: &str = "native-schedules-from-xml";
const CSV_COMMENT: &str = "Created by YAFVS native-schedules-from-csv";
const MAX_CSV_BYTES: usize = 1024 * 1024;
const MAX_XML_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 4095;
const MAX_REPORTED: usize = 10;
const MAX_NAME_BYTES: usize = 4096;
const MAX_COMMENT_BYTES: usize = 4096;
const MAX_TIMEZONE_BYTES: usize = 256;
const MAX_ICALENDAR_BYTES: usize = 32_768;
const PAGE_SIZE: usize = 100;
const MAX_LOOKUP_PAGES: usize = 1000;
const MAX_LOOKUP_ITEMS: usize = PAGE_SIZE * MAX_LOOKUP_PAGES;
const MAX_LOOKUP_REQUESTS: usize = 4095;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    Csv,
    Xml,
}

impl SourceKind {
    fn command(self) -> &'static str {
        match self {
            Self::Csv => CSV_COMMAND,
            Self::Xml => XML_COMMAND,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Csv => "CSV",
            Self::Xml => "XML",
        }
    }

    fn file_key(self) -> &'static str {
        match self {
            Self::Csv => "csv_file",
            Self::Xml => "xml_file",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScheduleRow {
    row_number: usize,
    name: String,
    comment: String,
    timezone: String,
    icalendar: String,
}

pub fn command_native_schedules_from_csv(
    root: &Path,
    csv_file: &Path,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_loaded(
        root,
        csv_file,
        SourceKind::Csv,
        load_csv_rows(csv_file),
        allow_write_control,
        dry_run,
        status_only,
    )
}

pub fn command_native_schedules_from_xml(
    root: &Path,
    xml_file: &Path,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    command_loaded(
        root,
        xml_file,
        SourceKind::Xml,
        load_xml_rows(xml_file),
        allow_write_control,
        dry_run,
        status_only,
    )
}

fn command_loaded(
    root: &Path,
    source_file: &Path,
    kind: SourceKind,
    rows: Result<Vec<ScheduleRow>, String>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
) -> ResultEnvelope {
    match rows {
        Ok(rows) => command_with(
            root,
            source_file,
            kind,
            rows,
            allow_write_control,
            dry_run,
            status_only,
            &SystemCommandRunner,
            &GuardedApi,
        ),
        Err(error) => {
            let result = envelope(
                root,
                kind,
                &SystemCommandRunner,
                &format!(
                    "Native {} schedule creation rejected before runtime access.",
                    kind.label()
                ),
                vec![
                    Finding::new("fail", &format!("{}.rows", kind.command()), error)
                        .with_details(source_file_detail(source_file, kind)),
                ],
                base_details(source_file, kind, dry_run),
            );
            finish_status(result, kind, status_only)
        }
    }
}

fn envelope(
    root: &Path,
    kind: SourceKind,
    runner: &dyn CommandRunner,
    summary: &str,
    findings: Vec<Finding>,
    details: Value,
) -> ResultEnvelope {
    make_result(
        metadata(root, kind.command(), runner),
        summary.into(),
        findings,
    )
    .with_details(details)
}

fn base_details(path: &Path, kind: SourceKind, dry_run: bool) -> Value {
    let mut details = json!({
        "row_count": 0,
        "dry_run": dry_run,
        "duplicate_source_name_count": 0,
        "skipped_existing_schedule_count": 0,
        "preflight_failure_count": 0,
        "created_schedule_count": 0,
        "create_failure_count": 0,
        "created_schedule_ids": [],
    });
    details[kind.file_key()] = json!(path);
    if kind == SourceKind::Csv {
        details["duplicate_csv_name_count"] = json!(0);
    }
    details
}

fn source_file_detail(path: &Path, kind: SourceKind) -> Value {
    let mut details = json!({});
    details[kind.file_key()] = json!(path);
    details
}

fn read_bounded_file(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("failed to read schedule {label} file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read schedule {label} file: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "failed to read schedule {label} file: path is not a regular file"
        ));
    }
    if metadata.len() > maximum as u64 {
        return Err(format!(
            "failed to read schedule {label} file: file exceeds the {maximum} byte limit"
        ));
    }
    let mut input = Vec::with_capacity(metadata.len() as usize);
    let mut bounded: Take<_> = file.take((maximum + 1) as u64);
    bounded
        .read_to_end(&mut input)
        .map_err(|error| format!("failed to read schedule {label} file: {error}"))?;
    if input.len() > maximum {
        return Err(format!(
            "failed to read schedule {label} file: file exceeds the {maximum} byte limit"
        ));
    }
    Ok(input)
}

fn load_csv_rows(path: &Path) -> Result<Vec<ScheduleRow>, String> {
    let input = read_bounded_file(path, MAX_CSV_BYTES, "CSV")?;
    std::str::from_utf8(&input)
        .map_err(|_| "failed to read schedule CSV file: input is not UTF-8")?;
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(input.as_slice());
    let mut rows = Vec::new();
    for (index, record) in reader.records().enumerate() {
        let row_number = index + 1;
        let record =
            record.map_err(|error| format!("failed to read schedule CSV file: {error}"))?;
        if record.is_empty() {
            continue;
        }
        if record.len() != 3 {
            return Err(format!(
                "row {row_number} must have exactly 3 columns: name, timezone, icalendar"
            ));
        }
        rows.push(validate_row(
            row_number,
            &record[0],
            CSV_COMMENT,
            &record[1],
            &record[2],
            false,
        )?);
        if rows.len() > MAX_ROWS {
            return Err(format!(
                "schedule CSV file must contain at most {MAX_ROWS} non-empty rows"
            ));
        }
    }
    if rows.is_empty() {
        Err("schedule CSV file is empty".into())
    } else {
        Ok(rows)
    }
}

fn load_xml_rows(path: &Path) -> Result<Vec<ScheduleRow>, String> {
    parse_xml_rows(&read_bounded_file(path, MAX_XML_BYTES, "XML")?)
}

fn parse_xml_rows(input: &[u8]) -> Result<Vec<ScheduleRow>, String> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().check_end_names = true;
    let mut rows = Vec::new();
    let mut root_seen = false;
    loop {
        match reader.read_event() {
            Ok(Event::Decl(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(Event::DocType(_)) => {
                return Err("failed to parse schedule XML file: DTDs are not supported".into());
            }
            Ok(Event::Text(text)) => {
                let value = super::decode_xml_text(&text)?;
                if !value.trim().is_empty() {
                    return Err(
                        "failed to parse schedule XML file: text outside the root element".into(),
                    );
                }
            }
            Ok(Event::CData(data)) => {
                let value = data
                    .decode()
                    .map_err(|error| format!("failed to parse schedule XML file: {error}"))?;
                if !value.trim().is_empty() {
                    return Err(
                        "failed to parse schedule XML file: text outside the root element".into(),
                    );
                }
            }
            Ok(Event::GeneralRef(_)) => {
                return Err(
                    "failed to parse schedule XML file: text outside the root element".into(),
                );
            }
            Ok(Event::Start(start)) if !root_seen => {
                root_seen = true;
                parse_xml_root(&mut reader, start.name(), &mut rows)?;
            }
            Ok(Event::Empty(_)) if !root_seen => {
                root_seen = true;
            }
            Ok(Event::Start(_)) | Ok(Event::Empty(_)) => {
                return Err(
                    "failed to parse schedule XML file: multiple root elements are not supported"
                        .into(),
                );
            }
            Ok(Event::End(_)) => {
                return Err("failed to parse schedule XML file: unexpected closing element".into());
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(format!("failed to parse schedule XML file: {error}"));
            }
        }
    }
    if !root_seen {
        return Err("failed to parse schedule XML file: missing root element".into());
    }
    if rows.is_empty() {
        Err("schedule XML document must contain direct schedule children".into())
    } else {
        Ok(rows)
    }
}

fn parse_xml_root(
    reader: &mut Reader<&[u8]>,
    root_end: QName<'_>,
    rows: &mut Vec<ScheduleRow>,
) -> Result<(), String> {
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) if start.name().as_ref() == b"schedule" => {
                if rows.len() >= MAX_ROWS {
                    return Err(format!(
                        "schedule XML file must contain at most {MAX_ROWS} direct schedule rows"
                    ));
                }
                rows.push(parse_xml_schedule(reader, start.name(), rows.len() + 1)?);
            }
            Ok(Event::Empty(start)) if start.name().as_ref() == b"schedule" => {
                return Err("row 1 must include a schedule name".into());
            }
            Ok(Event::Start(_)) | Ok(Event::Empty(_)) => {
                return Err("schedule XML document accepts only direct <schedule> children".into());
            }
            Ok(Event::Text(text)) => {
                let value = super::decode_xml_text(&text)?;
                if !value.trim().is_empty() {
                    return Err(
                        "schedule XML document accepts only direct <schedule> children".into(),
                    );
                }
            }
            Ok(Event::CData(data)) => {
                let value = data
                    .decode()
                    .map_err(|error| format!("failed to parse schedule XML file: {error}"))?;
                if !value.trim().is_empty() {
                    return Err(
                        "schedule XML document accepts only direct <schedule> children".into(),
                    );
                }
            }
            Ok(Event::GeneralRef(_)) => {
                return Err("schedule XML document accepts only direct <schedule> children".into());
            }
            Ok(Event::DocType(_)) => {
                return Err("failed to parse schedule XML file: DTDs are not supported".into());
            }
            Ok(Event::End(end)) if end.name() == root_end => return Ok(()),
            Ok(Event::End(_)) => {
                return Err("failed to parse schedule XML file: unexpected closing element".into());
            }
            Ok(Event::Eof) => {
                return Err("failed to parse schedule XML file: incomplete root element".into());
            }
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(_) => {}
            Err(error) => {
                return Err(format!("failed to parse schedule XML file: {error}"));
            }
        }
    }
}

fn parse_xml_schedule(
    reader: &mut Reader<&[u8]>,
    schedule_end: QName<'_>,
    row_number: usize,
) -> Result<ScheduleRow, String> {
    let mut name = None;
    let mut comment = None;
    let mut timezone = None;
    let mut icalendar = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let field = start.name().as_ref().to_vec();
                let slot = match field.as_slice() {
                    b"name" => &mut name,
                    b"comment" => &mut comment,
                    b"timezone" => &mut timezone,
                    b"icalendar" => &mut icalendar,
                    _ => {
                        return Err(format!(
                            "row {row_number} contains unsupported schedule XML field"
                        ));
                    }
                };
                if slot.is_some() {
                    return Err(format!(
                        "row {row_number} contains duplicate schedule XML fields"
                    ));
                }
                *slot = Some(read_xml_scalar(reader, start.name())?);
            }
            Ok(Event::Empty(start)) => {
                let slot = match start.name().as_ref() {
                    b"name" => &mut name,
                    b"comment" => &mut comment,
                    b"timezone" => &mut timezone,
                    b"icalendar" => &mut icalendar,
                    _ => {
                        return Err(format!(
                            "row {row_number} contains unsupported schedule XML field"
                        ));
                    }
                };
                if slot.replace(String::new()).is_some() {
                    return Err(format!(
                        "row {row_number} contains duplicate schedule XML fields"
                    ));
                }
            }
            Ok(Event::CData(data)) => {
                let value = data
                    .decode()
                    .map_err(|error| format!("failed to parse schedule XML file: {error}"))?;
                if !value.trim().is_empty() {
                    return Err(format!(
                        "row {row_number} contains text outside schedule fields"
                    ));
                }
            }
            Ok(Event::GeneralRef(_)) => {
                return Err(format!(
                    "row {row_number} contains text outside schedule fields"
                ));
            }
            Ok(Event::Text(text)) => {
                let value = super::decode_xml_text(&text)?;
                if !value.trim().is_empty() {
                    return Err(format!(
                        "row {row_number} contains text outside schedule fields"
                    ));
                }
            }
            Ok(Event::DocType(_)) => {
                return Err("failed to parse schedule XML file: DTDs are not supported".into());
            }
            Ok(Event::End(end)) if end.name() == schedule_end => {
                return validate_row(
                    row_number,
                    name.as_deref().unwrap_or(""),
                    comment.as_deref().unwrap_or(""),
                    timezone.as_deref().unwrap_or(""),
                    icalendar.as_deref().unwrap_or(""),
                    true,
                );
            }
            Ok(Event::End(_)) => {
                return Err(format!(
                    "row {row_number} has an unexpected closing schedule XML field"
                ));
            }
            Ok(Event::Eof) => {
                return Err(format!("row {row_number} contains an incomplete schedule"));
            }
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(_) => {}
            Err(error) => {
                return Err(format!("failed to parse schedule XML file: {error}"));
            }
        }
    }
}

fn read_xml_scalar(reader: &mut Reader<&[u8]>, end: QName<'_>) -> Result<String, String> {
    let mut value = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Text(text)) => value.push_str(&super::decode_xml_text(&text)?),
            Ok(Event::GeneralRef(reference)) => {
                value.push(super::decode_xml_reference(&reference)?);
            }
            Ok(Event::CData(data)) => value.push_str(
                data.decode()
                    .map_err(|error| format!("failed to parse schedule XML file: {error}"))?
                    .as_ref(),
            ),
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {}
            Ok(Event::End(found)) if found.name() == end => return Ok(value),
            Ok(Event::Start(_)) | Ok(Event::Empty(_)) => {
                return Err(
                    "failed to parse schedule XML file: nested scalar content is not supported"
                        .into(),
                );
            }
            Ok(Event::DocType(_)) => {
                return Err("failed to parse schedule XML file: DTDs are not supported".into());
            }
            Ok(Event::Eof) => {
                return Err("failed to parse schedule XML file: incomplete scalar element".into());
            }
            Ok(_) => {}
            Err(error) => {
                return Err(format!("failed to parse schedule XML file: {error}"));
            }
        }
        if value.len() > MAX_ICALENDAR_BYTES {
            return Err(format!(
                "schedule XML scalar text exceeds the {MAX_ICALENDAR_BYTES} byte limit"
            ));
        }
    }
}

fn validate_row(
    row_number: usize,
    name: &str,
    comment: &str,
    timezone: &str,
    icalendar: &str,
    require_timezone: bool,
) -> Result<ScheduleRow, String> {
    let name = name.trim();
    let comment = comment.trim();
    let timezone = timezone.trim();
    if name.is_empty() {
        return Err(format!("row {row_number} must include a schedule name"));
    }
    if require_timezone && timezone.is_empty() {
        return Err(format!("row {row_number} must include a timezone"));
    }
    if icalendar.trim().is_empty() {
        return Err(format!("row {row_number} must include an iCalendar value"));
    }
    for (label, value, maximum) in [
        ("schedule name", name, MAX_NAME_BYTES),
        ("schedule comment", comment, MAX_COMMENT_BYTES),
        ("timezone", timezone, MAX_TIMEZONE_BYTES),
    ] {
        if value.chars().any(is_c0_or_c1) {
            return Err(format!("row {row_number} {label} must be printable text"));
        }
        if value.len() > maximum {
            return Err(format!("row {row_number} {label} exceeds {maximum} bytes"));
        }
    }
    if icalendar
        .chars()
        .any(|character| is_c0_or_c1(character) && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(format!(
            "row {row_number} iCalendar contains unsupported control characters"
        ));
    }
    if icalendar.len() > MAX_ICALENDAR_BYTES {
        return Err(format!(
            "row {row_number} iCalendar value exceeds {MAX_ICALENDAR_BYTES} bytes"
        ));
    }
    Ok(ScheduleRow {
        row_number,
        name: name.into(),
        comment: comment.into(),
        timezone: timezone.into(),
        icalendar: icalendar.into(),
    })
}

fn is_c0_or_c1(character: char) -> bool {
    matches!(character as u32, 0..=31 | 127..=159)
}

#[allow(clippy::too_many_arguments)]
fn command_with(
    root: &Path,
    source_file: &Path,
    kind: SourceKind,
    rows: Vec<ScheduleRow>,
    allow_write_control: bool,
    dry_run: bool,
    status_only: bool,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
) -> ResultEnvelope {
    let command = kind.command();
    let mut details = base_details(source_file, kind, dry_run);
    details["row_count"] = json!(rows.len());
    let mut findings = vec![Finding::new(
        "pass",
        &format!("{command}.rows"),
        format!("Loaded {} schedule {} row(s).", rows.len(), kind.label()),
    )];

    if dry_run {
        details["planned_schedule_count"] = json!(rows.len());
        details["planned_schedules"] =
            Value::Array(rows.iter().take(MAX_REPORTED).map(safe_summary).collect());
        findings.push(
            Finding::new(
                "pass",
                &format!("{command}.dry-run"),
                "Dry run planned native schedule writes without runtime access or calendar payload logging."
                    .into(),
            )
            .with_details(json!({
                "reported_schedule_count": rows.len().min(MAX_REPORTED)
            })),
        );
        return finish_status(
            envelope(
                root,
                kind,
                runner,
                &format!(
                    "Native {} schedule creation dry run completed.",
                    kind.label()
                ),
                findings,
                details,
            ),
            kind,
            status_only,
        );
    }

    if !allow_write_control {
        findings.push(Finding::new(
            "fail",
            &format!("{command}.write-control-intent"),
            "Creating schedules requires --allow-write-control.".into(),
        ));
        return finish_status(
            envelope(
                root,
                kind,
                runner,
                &format!(
                    "Native {} schedule creation rejected before runtime access.",
                    kind.label()
                ),
                findings,
                details,
            ),
            kind,
            status_only,
        );
    }

    let mut selected = Vec::new();
    let mut existing_names = Vec::new();
    let mut duplicate_names = Vec::new();
    let mut preflight_failures = Vec::new();
    let mut planned_names = HashSet::new();
    let mut config_recorded = false;
    let mut lookup_requests = 0usize;

    for row in rows {
        if !planned_names.insert(row.name.clone()) {
            increment(&mut details, "duplicate_source_name_count");
            if kind == SourceKind::Csv {
                increment(&mut details, "duplicate_csv_name_count");
            }
            if duplicate_names.len() < MAX_REPORTED {
                duplicate_names.push(row.name);
            }
            continue;
        }
        match lookup_existing(
            root,
            command,
            &row.name,
            runner,
            api,
            &mut findings,
            &mut config_recorded,
            &mut lookup_requests,
        ) {
            Ok(true) => {
                increment(&mut details, "skipped_existing_schedule_count");
                if existing_names.len() < MAX_REPORTED {
                    existing_names.push(row.name);
                }
            }
            Ok(false) => selected.push(row),
            Err(failure) => {
                increment(&mut details, "preflight_failure_count");
                if preflight_failures.len() < MAX_REPORTED {
                    preflight_failures.push(json!({
                        "row": row.row_number,
                        "name": row.name,
                        "reason": failure,
                    }));
                }
            }
        }
    }

    details["duplicate_source_names"] = json!(duplicate_names);
    if kind == SourceKind::Csv {
        details["duplicate_csv_names"] = details["duplicate_source_names"].clone();
    }
    details["skipped_existing_schedule_names"] = json!(existing_names);
    details["lookup_request_count"] = json!(lookup_requests);
    if count(&details, "preflight_failure_count") != 0 {
        details["preflight_failures"] = json!(preflight_failures);
        findings.push(
            Finding::new(
                "fail",
                &format!("{command}.preflight"),
                format!(
                    "Native {} schedule preflight failed before creating schedules.",
                    kind.label()
                ),
            )
            .with_details(json!({
                "failure_count": count(&details, "preflight_failure_count"),
                "failures": details["preflight_failures"],
            })),
        );
        return finish_status(
            envelope(
                root,
                kind,
                runner,
                &format!(
                    "Native {} schedule creation rejected before schedule writes.",
                    kind.label()
                ),
                findings,
                details,
            ),
            kind,
            status_only,
        );
    }

    findings.push(Finding::new(
        "pass",
        &format!("{command}.preflight"),
        format!(
            "Preflight selected {} schedule create row(s), skipped {} existing schedule(s), and skipped {} duplicate row(s).",
            selected.len(),
            count(&details, "skipped_existing_schedule_count"),
            count(&details, "duplicate_source_name_count"),
        ),
    ));

    let mut created_ids = Vec::new();
    let mut create_failures = Vec::new();
    for row in selected {
        let reply = api.call(
            root,
            "/api/v1/schedules",
            "POST",
            Some(&schedule_body(&row)),
            &format!("{command}.request-body"),
            &format!("{command}.direct-config-shape"),
            &format!("{command}.direct-token-strength"),
            runner,
        );
        match reply {
            Ok(reply) => {
                let acknowledged = acknowledged_id(&reply, 201);
                let http_status = reply.http_status;
                if !config_recorded {
                    findings.push(reply.config);
                    config_recorded = true;
                }
                if let Some(id) = acknowledged {
                    increment(&mut details, "created_schedule_count");
                    if created_ids.len() < MAX_REPORTED {
                        created_ids.push(id);
                    }
                } else {
                    increment(&mut details, "create_failure_count");
                    if create_failures.len() < MAX_REPORTED {
                        create_failures.push(json!({
                            "row": row.row_number,
                            "name": row.name,
                            "http_status": http_status,
                        }));
                    }
                }
            }
            Err(rejected) => {
                record_rejection(&mut findings, rejected, command, &mut config_recorded);
                increment(&mut details, "create_failure_count");
                if create_failures.len() < MAX_REPORTED {
                    create_failures.push(json!({
                        "row": row.row_number,
                        "name": row.name,
                        "http_status": null,
                    }));
                }
            }
        }
    }

    details["created_schedule_ids"] = json!(created_ids);
    if count(&details, "create_failure_count") == 0 {
        findings.push(Finding::new(
            "pass",
            &format!("{command}.create"),
            format!(
                "Created {} schedule(s) through the native API.",
                count(&details, "created_schedule_count")
            ),
        ));
    } else {
        details["create_failures"] = json!(create_failures);
        findings.push(
            Finding::new(
                "fail",
                &format!("{command}.create"),
                "One or more native schedule create requests failed; remaining rows were attempted."
                    .into(),
            )
            .with_details(json!({
                "failure_count": count(&details, "create_failure_count"),
                "failures": details["create_failures"],
            })),
        );
    }

    let failed = findings.iter().any(|finding| finding.status == "fail");
    finish_status(
        envelope(
            root,
            kind,
            runner,
            &format!(
                "Native {} schedule creation {}.",
                kind.label(),
                if failed { "failed" } else { "completed" }
            ),
            findings,
            details,
        ),
        kind,
        status_only,
    )
}

fn schedule_body(row: &ScheduleRow) -> Value {
    json!({
        "name": row.name,
        "comment": row.comment,
        "timezone": row.timezone,
        "icalendar": row.icalendar,
    })
}

fn safe_summary(row: &ScheduleRow) -> Value {
    let mut digest = Sha256::new();
    digest.update(row.icalendar.as_bytes());
    json!({
        "row": row.row_number,
        "name": row.name,
        "timezone": row.timezone,
        "comment": row.comment,
        "icalendar_bytes": row.icalendar.len(),
        "icalendar_sha256": format!("{:x}", digest.finalize()),
    })
}

#[allow(clippy::too_many_arguments)]
fn lookup_existing(
    root: &Path,
    command: &str,
    name: &str,
    runner: &dyn CommandRunner,
    api: &dyn TargetApi,
    findings: &mut Vec<Finding>,
    config_recorded: &mut bool,
    request_count: &mut usize,
) -> Result<bool, String> {
    let encoded = percent_encode_component(name);
    let mut expected_total = None;
    let mut found = false;
    for page in 1..=MAX_LOOKUP_PAGES {
        if *request_count >= MAX_LOOKUP_REQUESTS {
            return Err("lookup request safety limit exceeded".into());
        }
        *request_count += 1;
        let path = format!("/api/v1/schedules?filter={encoded}&page={page}&page_size={PAGE_SIZE}");
        let reply = match api.call(
            root,
            &path,
            "GET",
            None,
            &format!("{command}.request-body"),
            &format!("{command}.direct-config-shape"),
            &format!("{command}.direct-token-strength"),
            runner,
        ) {
            Ok(reply) => reply,
            Err(rejected) => {
                record_rejection(findings, rejected, command, config_recorded);
                return Err("lookup failed".into());
            }
        };
        let ApiReply {
            output,
            parsed,
            http_status,
            oversized,
            config,
        } = reply;
        if !*config_recorded {
            findings.push(config);
            *config_recorded = true;
        }
        if oversized || !output.success || http_status != Some(200) {
            return Err("lookup failed".into());
        }
        let Some(object) = parsed.as_ref().and_then(Value::as_object) else {
            return Err("lookup response was malformed".into());
        };
        let Some(items) = object.get("items").and_then(Value::as_array) else {
            return Err("lookup response was malformed".into());
        };
        let Some(page_info) = object.get("page").and_then(Value::as_object) else {
            return Err("lookup pagination contract was invalid".into());
        };
        let (Some(total), Some(observed_page), Some(observed_page_size)) = (
            page_info.get("total").and_then(Value::as_u64),
            page_info.get("page").and_then(Value::as_u64),
            page_info.get("page_size").and_then(Value::as_u64),
        ) else {
            return Err("lookup pagination contract was invalid".into());
        };
        let offset = (page - 1).saturating_mul(PAGE_SIZE) as u64;
        let expected_items = total
            .checked_sub(offset)
            .map(|remaining| remaining.min(PAGE_SIZE as u64) as usize);
        if total > MAX_LOOKUP_ITEMS as u64
            || expected_total.is_some_and(|expected| expected != total)
            || observed_page != page as u64
            || observed_page_size != PAGE_SIZE as u64
            || expected_items != Some(items.len())
        {
            return Err("lookup pagination contract was invalid".into());
        }
        expected_total = Some(total);
        for item in items {
            let Some(item) = item.as_object() else {
                return Err("lookup item was malformed".into());
            };
            found |= item.get("name").and_then(Value::as_str) == Some(name);
        }
        if offset + items.len() as u64 >= total {
            return Ok(found);
        }
    }
    Err("lookup pagination exceeded safety limit".into())
}

fn record_rejection(
    findings: &mut Vec<Finding>,
    mut rejected: Vec<Finding>,
    command: &str,
    config_recorded: &mut bool,
) {
    let config_check = format!("{command}.direct-config-shape");
    if *config_recorded {
        rejected.retain(|finding| finding.check != config_check);
    } else if rejected.iter().any(|finding| finding.check == config_check) {
        *config_recorded = true;
    }
    findings.append(&mut rejected);
}

fn increment(details: &mut Value, key: &str) {
    details[key] = json!(count(details, key) + 1);
}

fn count(details: &Value, key: &str) -> u64 {
    details.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn finish_status(
    mut result: ResultEnvelope,
    kind: SourceKind,
    status_only: bool,
) -> ResultEnvelope {
    if !status_only {
        return result;
    }
    let details = result
        .details
        .as_ref()
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut compact = json!({
        "row_count": count(&details, "row_count"),
        "dry_run": details.get("dry_run").and_then(Value::as_bool).unwrap_or(false),
        "duplicate_source_name_count": count(&details, "duplicate_source_name_count"),
        "skipped_existing_schedule_count": count(&details, "skipped_existing_schedule_count"),
        "preflight_failure_count": count(&details, "preflight_failure_count"),
        "created_schedule_count": count(&details, "created_schedule_count"),
        "create_failure_count": count(&details, "create_failure_count"),
    });
    compact[kind.file_key()] = details.get(kind.file_key()).cloned().unwrap_or(Value::Null);
    if kind == SourceKind::Csv {
        compact["duplicate_csv_name_count"] = json!(count(&details, "duplicate_csv_name_count"));
    }
    result.details = Some(compact);
    result.findings.retain(|finding| finding.status != "pass");
    if result.findings.is_empty() {
        result.findings.push(Finding::new(
            "pass",
            &format!("{}.status-only", kind.command()),
            format!(
                "Native {} schedule creation passed; details summarized.",
                kind.label()
            ),
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
                "native-schedules-from-csv.direct-config-shape",
                "valid".into(),
            ),
        })
    }

    fn page(page: usize, total: usize, items: Value) -> Result<ApiReply, Vec<Finding>> {
        reply(
            200,
            json!({
                "page": {"page": page, "page_size": PAGE_SIZE, "total": total},
                "items": items,
            }),
        )
    }

    fn rows(names: &[&str]) -> Vec<ScheduleRow> {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| ScheduleRow {
                row_number: index + 1,
                name: (*name).into(),
                comment: CSV_COMMENT.into(),
                timezone: "UTC".into(),
                icalendar: format!("BEGIN:VCALENDAR\nSUMMARY:{name}\nEND:VCALENDAR"),
            })
            .collect()
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "yafvsctl-schedule-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn securely_loads_bounded_csv_and_preserves_calendar() {
        let directory = temp_dir("csv");
        let path = directory.join("schedules.csv");
        fs::write(
            &path,
            "Nightly, Europe/Berlin ,\"BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR\"\n",
        )
        .unwrap();
        let loaded = load_csv_rows(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Nightly");
        assert_eq!(loaded[0].timezone, "Europe/Berlin");
        assert_eq!(loaded[0].comment, CSV_COMMENT);
        assert!(loaded[0].icalendar.contains("VERSION:2.0"));

        let link = directory.join("link.csv");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_csv_rows(&link).unwrap_err().contains("failed to read"));
        assert!(
            load_csv_rows(&directory)
                .unwrap_err()
                .contains("not a regular file")
        );
        let oversized = directory.join("oversized.csv");
        fs::write(&oversized, vec![b'x'; MAX_CSV_BYTES + 1]).unwrap();
        assert!(
            load_csv_rows(&oversized)
                .unwrap_err()
                .contains("byte limit")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn validates_byte_and_control_boundaries() {
        let valid = validate_row(
            1,
            &"é".repeat(2048),
            "",
            "",
            "BEGIN:VCALENDAR\r\n\tEND:VCALENDAR",
            false,
        )
        .unwrap();
        assert!(valid.timezone.is_empty());
        assert!(
            validate_row(1, &"é".repeat(2049), "", "UTC", "BEGIN:VCALENDAR", false)
                .unwrap_err()
                .contains("exceeds 4096")
        );
        assert!(
            validate_row(1, "Bad\u{1}Name", "", "UTC", "BEGIN:VCALENDAR", false)
                .unwrap_err()
                .contains("printable")
        );
        assert!(
            validate_row(1, "Name", "", "UTC", "BEGIN\u{b}:VCALENDAR", false)
                .unwrap_err()
                .contains("unsupported control")
        );
        assert!(
            validate_row(1, "Name", "", "", "BEGIN:VCALENDAR", true)
                .unwrap_err()
                .contains("timezone")
        );
    }

    #[test]
    fn parses_direct_xml_and_rejects_dtd_nested_and_indirect_rows() {
        let calendar = "BEGIN:VCALENDAR\nSUMMARY:Private\nEND:VCALENDAR";
        let parsed = parse_xml_rows(
            format!(
                "<schedules><schedule><name> Nightly </name><comment> Imported </comment><timezone> UTC </timezone><icalendar>{calendar}</icalendar></schedule></schedules>"
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed[0].name, "Nightly");
        assert_eq!(parsed[0].comment, "Imported");
        assert_eq!(parsed[0].timezone, "UTC");
        assert!(parsed[0].icalendar.contains("Private"));
        assert!(
            parse_xml_rows(b"<!DOCTYPE schedules><schedules/>")
                .unwrap_err()
                .contains("DTDs")
        );
        assert!(
            parse_xml_rows(b"<schedules><schedule><name><nested/></name><timezone>UTC</timezone><icalendar>x</icalendar></schedule></schedules>")
                .unwrap_err()
                .contains("nested scalar")
        );
        assert!(
            parse_xml_rows(
                b"<schedules><group><schedule><name>x</name></schedule></group></schedules>"
            )
            .unwrap_err()
            .contains("direct <schedule>")
        );
    }

    #[test]
    fn dry_run_and_refusal_never_call_api_or_disclose_calendar() {
        let api = FakeApi::new(Vec::new());
        let dry = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("schedules.csv"),
            SourceKind::Csv,
            rows(&["Nightly"]),
            false,
            true,
            false,
            &Runner,
            &api,
        );
        assert_eq!(dry.status, "pass");
        let encoded = serde_json::to_string(&dry).unwrap();
        assert!(!encoded.contains("BEGIN:VCALENDAR"));
        assert!(encoded.contains("icalendar_sha256"));
        let refused = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("schedules.xml"),
            SourceKind::Xml,
            rows(&["Nightly"]),
            false,
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(refused.status, "fail");
        assert!(api.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn preflights_duplicates_existing_names_and_posts_exact_body() {
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(
                1,
                1,
                json!([{
                    "id": "11111111-1111-4111-8111-111111111111",
                    "name": "Existing"
                }]),
            ),
            reply(201, json!({"id":"22222222-2222-4222-8222-222222222222"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("schedules.csv"),
            SourceKind::Csv,
            rows(&["New", "New", "Existing"]),
            true,
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "pass");
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["duplicate_source_name_count"], 1);
        assert_eq!(details["skipped_existing_schedule_count"], 1);
        assert_eq!(details["created_schedule_count"], 1);
        let calls = api.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].0, "/api/v1/schedules");
        assert_eq!(calls[2].1, "POST");
        assert_eq!(calls[2].2["name"], "New");
        assert_eq!(calls[2].2["timezone"], "UTC");
        assert!(
            calls[2].2["icalendar"]
                .as_str()
                .unwrap()
                .contains("SUMMARY:New")
        );
    }

    #[test]
    fn malformed_preflight_prevents_every_post() {
        let api = FakeApi::new(vec![reply(
            200,
            json!({"page":{"page":2,"page_size":100,"total":0},"items":[]}),
        )]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("schedules.csv"),
            SourceKind::Csv,
            rows(&["New"]),
            true,
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.details.as_ref().unwrap()["preflight_failure_count"],
            1
        );
        assert!(api.calls.lock().unwrap().iter().all(|call| call.1 == "GET"));
    }

    #[test]
    fn exact_lookup_pages_with_strict_stable_total() {
        let first = Value::Array(
            (0..PAGE_SIZE)
                .map(|index| {
                    json!({
                        "id": format!("11111111-1111-4111-8111-{index:012}"),
                        "name": format!("near-{index}")
                    })
                })
                .collect(),
        );
        let api = FakeApi::new(vec![
            page(1, PAGE_SIZE + 1, first),
            page(
                2,
                PAGE_SIZE + 1,
                json!([{
                    "id": "22222222-2222-4222-8222-222222222222",
                    "name": "needle"
                }]),
            ),
        ]);
        let mut findings = Vec::new();
        let mut config = false;
        let mut requests = 0;
        assert!(
            lookup_existing(
                Path::new("/srv/YAFVS"),
                CSV_COMMAND,
                "needle",
                &Runner,
                &api,
                &mut findings,
                &mut config,
                &mut requests,
            )
            .unwrap()
        );
        assert_eq!(requests, 2);
    }

    #[test]
    fn create_failures_continue_and_strict_acknowledgement_does_not_leak() {
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            page(1, 0, json!([])),
            reply(500, json!({"secret":"do-not-retain"})),
            reply(201, json!({"id":"not-a-uuid"})),
            reply(201, json!({"id":"33333333-3333-4333-8333-333333333333"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("schedules.csv"),
            SourceKind::Csv,
            rows(&["One", "Two", "Three"]),
            true,
            false,
            false,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "fail");
        assert_eq!(
            result.details.as_ref().unwrap()["created_schedule_count"],
            1
        );
        assert_eq!(result.details.as_ref().unwrap()["create_failure_count"], 2);
        assert_eq!(api.calls.lock().unwrap().len(), 6);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("do-not-retain")
        );
    }

    #[test]
    fn status_only_keeps_compact_counts() {
        let api = FakeApi::new(vec![
            page(1, 0, json!([])),
            reply(201, json!({"id":"44444444-4444-4444-8444-444444444444"})),
        ]);
        let result = command_with(
            Path::new("/srv/YAFVS"),
            Path::new("schedules.xml"),
            SourceKind::Xml,
            rows(&["One"]),
            true,
            false,
            true,
            &Runner,
            &api,
        );
        assert_eq!(result.status, "pass");
        let details = result.details.as_ref().unwrap();
        assert_eq!(details["created_schedule_count"], 1);
        assert!(details.get("planned_schedules").is_none());
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].check,
            "native-schedules-from-xml.status-only"
        );
    }
}
