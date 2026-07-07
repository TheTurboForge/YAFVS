// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::errors::ApiError;

pub(crate) const MAX_PORT_LIST_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_PORT_LIST_CREATE_RANGES: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) port_ranges: Option<Vec<PortListCreateRangeRequest>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCreateRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    pub(crate) port_ranges: Vec<PortListCreateRangeRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListImportRequest {
    pub(crate) xml_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCloneRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListCreateRangeRequest {
    pub(crate) protocol: String,
    pub(crate) start: i32,
    pub(crate) end: i32,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) port_ranges: Option<Vec<ValidatedPortListCreateRange>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListCreate {
    pub(crate) imported_id: Option<String>,
    pub(crate) deduplicate_name: bool,
    pub(crate) name: String,
    pub(crate) comment: String,
    pub(crate) port_ranges: Vec<ValidatedPortListCreateRange>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListClone {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedPortListCreateRange {
    pub(crate) protocol_id: i32,
    pub(crate) start: i32,
    pub(crate) end: i32,
    pub(crate) comment: String,
}

pub(crate) fn validate_port_list_create_request(
    request: PortListCreateRequest,
) -> Result<ValidatedPortListCreate, ApiError> {
    let name = normalize_required_port_list_text(request.name, "name")?;
    let comment =
        normalize_optional_port_list_text(request.comment, "comment")?.unwrap_or_default();
    let port_ranges = validate_port_list_ranges(request.port_ranges, "port list create request")?;
    Ok(ValidatedPortListCreate {
        imported_id: None,
        deduplicate_name: false,
        name,
        comment,
        port_ranges,
    })
}

pub(crate) fn validate_port_list_import_request(
    request: PortListImportRequest,
) -> Result<ValidatedPortListCreate, ApiError> {
    if request.xml_file.len() > 1_048_576 {
        return Err(ApiError::BadRequest(
            "port list import XML must be at most 1048576 bytes".to_string(),
        ));
    }
    parse_port_list_import_xml(&request.xml_file)
}

fn parse_port_list_import_xml(xml: &str) -> Result<ValidatedPortListCreate, ApiError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_response = false;
    let mut in_port_list = false;
    let mut in_range = false;
    let mut current = String::new();
    let mut imported_id: Option<String> = None;
    let mut name: Option<String> = None;
    let mut comment: Option<String> = None;
    let mut range_protocol: Option<String> = None;
    let mut range_start: Option<String> = None;
    let mut range_end: Option<String> = None;
    let mut range_comment: Option<String> = None;
    let mut ranges = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let local = xml_local_name(event.name().as_ref()).to_vec();
                match local.as_slice() {
                    b"get_port_lists_response" => in_response = true,
                    b"port_list" if in_response && !in_port_list => {
                        in_port_list = true;
                        imported_id = xml_attr_value(&event, b"id")?;
                    }
                    b"port_range" if in_port_list => {
                        in_range = true;
                        range_protocol = None;
                        range_start = None;
                        range_end = None;
                        range_comment = None;
                    }
                    _ => {}
                }
                current = String::from_utf8_lossy(&local).into_owned();
            }
            Ok(Event::Text(event)) => {
                if in_port_list {
                    let text = event
                        .decode()
                        .map(|value| value.into_owned())
                        .unwrap_or_default();
                    match (in_range, current.as_str()) {
                        (false, "name") => name = Some(text),
                        (false, "comment") => comment = Some(text),
                        (true, "type") => range_protocol = Some(text),
                        (true, "start") => range_start = Some(text),
                        (true, "end") => range_end = Some(text),
                        (true, "comment") => range_comment = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::CData(event)) => {
                if in_port_list {
                    let text = event
                        .decode()
                        .map(|value| value.into_owned())
                        .unwrap_or_default();
                    match (in_range, current.as_str()) {
                        (false, "name") => name = Some(text),
                        (false, "comment") => comment = Some(text),
                        (true, "type") => range_protocol = Some(text),
                        (true, "start") => range_start = Some(text),
                        (true, "end") => range_end = Some(text),
                        (true, "comment") => range_comment = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(event)) => match xml_local_name(event.name().as_ref()) {
                b"port_range" if in_range => {
                    ranges.push(PortListCreateRangeRequest {
                        protocol: range_protocol.take().unwrap_or_default(),
                        start: parse_import_port(range_start.take(), "port range start")?,
                        end: parse_import_port(range_end.take(), "port range end")?,
                        comment: range_comment.take(),
                    });
                    in_range = false;
                    current.clear();
                }
                b"port_list" if in_port_list => break,
                b"get_port_lists_response" => in_response = false,
                _ => current.clear(),
            },
            Ok(Event::Eof) => break,
            Err(error) => {
                tracing::warn!(%error, "port list import XML parse failed");
                return Err(ApiError::BadRequest(
                    "port list import XML is invalid".to_string(),
                ));
            }
            _ => {}
        }
    }

    let imported_id = imported_id.ok_or_else(|| {
        ApiError::BadRequest("port list import XML must include a port_list id".to_string())
    })?;
    let imported_id = Uuid::parse_str(&imported_id)
        .map_err(|_| ApiError::BadRequest("port list import id must be a UUID".to_string()))?
        .to_string();
    let name =
        normalize_required_port_list_text(name.unwrap_or_default(), "port list import name")?;
    if ranges.is_empty() {
        return Err(ApiError::BadRequest(
            "port list import XML must include explicit port ranges".to_string(),
        ));
    }
    let port_ranges = validate_port_list_ranges(ranges, "port list import XML")?;
    Ok(ValidatedPortListCreate {
        imported_id: Some(imported_id),
        deduplicate_name: true,
        name,
        comment: normalize_optional_port_list_text(comment, "port list import comment")?
            .unwrap_or_default(),
        port_ranges,
    })
}

fn parse_import_port(value: Option<String>, field_name: &str) -> Result<i32, ApiError> {
    value
        .unwrap_or_default()
        .trim()
        .parse::<i32>()
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be an integer")))
}

fn xml_attr_value(event: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, ApiError> {
    for attr in event.attributes() {
        let attr =
            attr.map_err(|_| ApiError::BadRequest("port list import XML is invalid".to_string()))?;
        if xml_local_name(attr.key.as_ref()) == name {
            return Ok(Some(
                String::from_utf8_lossy(attr.value.as_ref()).into_owned(),
            ));
        }
    }
    Ok(None)
}

fn xml_local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

fn validate_port_list_create_range(
    range: PortListCreateRangeRequest,
) -> Result<ValidatedPortListCreateRange, ApiError> {
    let protocol_id = match range.protocol.trim().to_ascii_lowercase().as_str() {
        "tcp" => 0,
        "udp" => 1,
        _ => {
            return Err(ApiError::BadRequest(
                "port range protocol must be tcp or udp".to_string(),
            ));
        }
    };
    if !(1..=65535).contains(&range.start) || !(1..=65535).contains(&range.end) {
        return Err(ApiError::BadRequest(
            "port range start and end must be between 1 and 65535".to_string(),
        ));
    }
    if range.end < range.start {
        return Err(ApiError::BadRequest(
            "port range end must be greater than or equal to start".to_string(),
        ));
    }
    Ok(ValidatedPortListCreateRange {
        protocol_id,
        start: range.start,
        end: range.end,
        comment: normalize_optional_port_list_text(range.comment, "port range comment")?
            .unwrap_or_default(),
    })
}

pub(crate) fn validate_port_list_patch_request(
    request: PortListPatchRequest,
) -> Result<ValidatedPortListPatch, ApiError> {
    let port_ranges = request
        .port_ranges
        .map(|ranges| validate_port_list_ranges(ranges, "port list patch request"))
        .transpose()?;
    let validated = ValidatedPortListPatch {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
        port_ranges,
    };
    if validated.name.is_none() && validated.comment.is_none() && validated.port_ranges.is_none() {
        return Err(ApiError::BadRequest(
            "port list patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

pub(crate) fn validate_port_list_clone_request(
    request: PortListCloneRequest,
) -> Result<ValidatedPortListClone, ApiError> {
    Ok(ValidatedPortListClone {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
    })
}

fn validate_port_list_ranges(
    ranges: Vec<PortListCreateRangeRequest>,
    request_name: &str,
) -> Result<Vec<ValidatedPortListCreateRange>, ApiError> {
    if ranges.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{request_name} must include at least one port range"
        )));
    }
    if ranges.len() > MAX_PORT_LIST_CREATE_RANGES {
        return Err(ApiError::BadRequest(format!(
            "{request_name} may include at most {MAX_PORT_LIST_CREATE_RANGES} ranges"
        )));
    }
    let mut ranges = ranges
        .into_iter()
        .map(validate_port_list_create_range)
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_by_key(|range| (range.protocol_id, range.start, range.end));
    for pair in ranges.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.protocol_id == current.protocol_id && previous.end >= current.start {
            return Err(ApiError::BadRequest(format!(
                "{request_name} contains overlapping ranges"
            )));
        }
    }
    Ok(ranges)
}

fn normalize_optional_required_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_port_list_text(value, field_name))
        .transpose()
}

fn normalize_required_port_list_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_port_list_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_port_list_text_value(value, field_name))
        .transpose()
}

fn normalize_port_list_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_PORT_LIST_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_PORT_LIST_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}
