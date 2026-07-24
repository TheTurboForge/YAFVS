// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Component, Path as FsPath, PathBuf},
    time::Duration,
};

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use serde::Serialize;
use tokio::task;
use tokio_postgres::{Client, Row};

use crate::{
    app_state::AppState, auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid,
    scanner_write_db::require_scanner_write_operator,
};

const SCANNER_TYPE_OPENVAS: i64 = 2;
const SCANNER_TYPE_CVE: i64 = 3;
const SCANNER_TYPE_OSP_SENSOR: i64 = 5;
const SCANNER_TYPE_OPENVASD: i64 = 6;
const SCANNER_TYPE_OPENVASD_SENSOR: i64 = 8;
const OSP_GET_VERSION_COMMAND: &[u8] = b"<get_version/>";
const OSP_GET_VERSION_TIMEOUT: Duration = Duration::from_secs(10);
const OSP_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const ALLOWED_OSP_UNIX_SOCKET_DIR: &str = "/runtime/run/ospd";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScannerVerifyState {
    id: String,
    name: String,
    host: String,
    port: i64,
    scanner_type: i64,
    relay_host: Option<String>,
    relay_port: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ScannerVerifyResult {
    scanner_id: String,
    scanner_type: i64,
    verified: bool,
    verification_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OspVersionInfo {
    pub(crate) scanner_name: Option<String>,
    pub(crate) scanner_version: String,
    pub(crate) daemon_name: Option<String>,
    pub(crate) daemon_version: Option<String>,
    pub(crate) protocol_name: Option<String>,
    pub(crate) protocol_version: Option<String>,
}

pub(crate) async fn verify_scanner(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ScannerVerifyResult>, ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let scanner_id = parse_uuid(&scanner_id)?.to_string();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    ensure_scanner_verify_operator_exists(&client, &operator).await?;
    let scanner = load_scanner_verify_state(&client, &scanner_id).await?;
    Ok(Json(verify_scanner_state(scanner).await?))
}

async fn ensure_scanner_verify_operator_exists(
    client: &Client,
    operator: &DirectApiOperator,
) -> Result<(), ApiError> {
    let exists = client
        .query_opt(
            "SELECT id::integer FROM users WHERE uuid = $1;",
            &[&operator.user_uuid()],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner verify operator lookup failed");
            ApiError::Database
        })?
        .is_some();
    if exists {
        Ok(())
    } else {
        tracing::warn!("direct API scanner verify operator does not resolve to a database user");
        Err(ApiError::Forbidden)
    }
}

async fn load_scanner_verify_state(
    client: &Client,
    scanner_id: &str,
) -> Result<ScannerVerifyState, ApiError> {
    client
        .query_opt(scanner_verify_state_sql(), &[&scanner_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner verify state query failed");
            ApiError::Database
        })?
        .map(|row| scanner_verify_state_from_row(&row))
        .ok_or(ApiError::NotFound)
}

pub(crate) fn scanner_verify_state_sql() -> &'static str {
    "SELECT s.uuid::text AS id,
            coalesce(s.name, '')::text AS name,
            coalesce(s.host, '')::text AS host,
            coalesce(s.port, 0)::bigint AS port,
            coalesce(s.type, 0)::bigint AS scanner_type,
            nullif(s.relay_host, '')::text AS relay_host,
            coalesce(s.relay_port, 0)::bigint AS relay_port
       FROM scanners s
      WHERE s.uuid = $1
      LIMIT 1;"
}

fn scanner_verify_state_from_row(row: &Row) -> ScannerVerifyState {
    ScannerVerifyState {
        id: row.get("id"),
        name: row.get("name"),
        host: row.get("host"),
        port: row.get("port"),
        scanner_type: row.get("scanner_type"),
        relay_host: row.get("relay_host"),
        relay_port: row.get("relay_port"),
    }
}

pub(crate) async fn verify_scanner_state(
    scanner: ScannerVerifyState,
) -> Result<ScannerVerifyResult, ApiError> {
    match scanner.scanner_type {
        SCANNER_TYPE_OPENVAS | SCANNER_TYPE_OSP_SENSOR => verify_osp_scanner(scanner).await,
        SCANNER_TYPE_OPENVASD | SCANNER_TYPE_OPENVASD_SENSOR => Ok(no_contact_verify_result(
            scanner,
            "openvasd-no-contact",
            None,
        )),
        SCANNER_TYPE_CVE => Ok(no_contact_verify_result(
            scanner,
            "cve-builtin",
            Some("GVM/native".to_string()),
        )),
        _ => Err(ApiError::Conflict(format!(
            "scanner type {} is not supported by native verification",
            scanner.scanner_type
        ))),
    }
}

async fn verify_osp_scanner(scanner: ScannerVerifyState) -> Result<ScannerVerifyResult, ApiError> {
    ensure_native_osp_verify_scope(&scanner)?;
    let socket_path = scanner.host.clone();
    let version = task::spawn_blocking(move || probe_osp_unix_socket(&socket_path))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scanner verify OSP probe task failed");
            ApiError::Conflict("scanner verification probe failed".to_string())
        })?;
    let version = version.map_err(|message| {
        tracing::warn!(%message, "scanner verify OSP probe failed");
        ApiError::Conflict(message)
    })?;

    Ok(ScannerVerifyResult {
        scanner_id: scanner.id,
        scanner_type: scanner.scanner_type,
        verified: true,
        verification_mode: "osp-unix-socket".to_string(),
        name: Some(scanner.name),
        version: Some(version.scanner_version.clone()),
        scanner_name: version.scanner_name,
        scanner_version: Some(version.scanner_version),
        daemon_name: version.daemon_name,
        daemon_version: version.daemon_version,
        protocol_name: version.protocol_name,
        protocol_version: version.protocol_version,
    })
}

fn ensure_native_osp_verify_scope(scanner: &ScannerVerifyState) -> Result<(), ApiError> {
    if scanner.relay_host.is_some() || scanner.relay_port != 0 || scanner.port != 0 {
        return Err(ApiError::Conflict(
            "native scanner verification supports only local Unix-socket OSP scanners; remote, TLS, relay, and TCP probes are not part of this workflow".to_string(),
        ));
    }
    if !scanner_verify_osp_socket_is_allowed(&scanner.host) {
        return Err(ApiError::Conflict(
            "native scanner verification only probes OSPD Unix sockets under /runtime/run/ospd"
                .to_string(),
        ));
    }
    Ok(())
}

fn no_contact_verify_result(
    scanner: ScannerVerifyState,
    verification_mode: &str,
    version: Option<String>,
) -> ScannerVerifyResult {
    ScannerVerifyResult {
        scanner_id: scanner.id,
        scanner_type: scanner.scanner_type,
        verified: true,
        verification_mode: verification_mode.to_string(),
        name: Some(scanner.name),
        version,
        scanner_name: None,
        scanner_version: None,
        daemon_name: None,
        daemon_version: None,
        protocol_name: None,
        protocol_version: None,
    }
}

pub(crate) fn scanner_verify_osp_socket_is_allowed(host: &str) -> bool {
    if host.as_bytes().contains(&0) {
        return false;
    }
    let path = FsPath::new(host);
    path.is_absolute()
        && path.starts_with(ALLOWED_OSP_UNIX_SOCKET_DIR)
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn probe_osp_unix_socket(socket_path: &str) -> Result<OspVersionInfo, String> {
    let socket_path = canonical_osp_verify_socket_path(socket_path)?;
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|_| "scanner did not accept an OSP Unix-socket verification probe".to_string())?;
    stream
        .set_read_timeout(Some(OSP_GET_VERSION_TIMEOUT))
        .map_err(|_| "scanner verification could not set read timeout".to_string())?;
    stream
        .set_write_timeout(Some(OSP_GET_VERSION_TIMEOUT))
        .map_err(|_| "scanner verification could not set write timeout".to_string())?;
    stream
        .write_all(OSP_GET_VERSION_COMMAND)
        .map_err(|_| "scanner did not accept an OSP get_version request".to_string())?;
    let xml = read_osp_unix_xml_response(&mut stream)?;
    parse_osp_get_version_response(&xml)
        .map_err(|_| "scanner did not return a valid OSP get_version response".to_string())
}

fn canonical_osp_verify_socket_path(socket_path: &str) -> Result<PathBuf, String> {
    canonical_osp_verify_socket_path_in_dir(socket_path, FsPath::new(ALLOWED_OSP_UNIX_SOCKET_DIR))
}

pub(crate) fn canonical_osp_verify_socket_path_in_dir(
    socket_path: &str,
    allowed_dir: &FsPath,
) -> Result<PathBuf, String> {
    let resolved_dir = std::fs::canonicalize(allowed_dir)
        .map_err(|_| "scanner verification socket path is unavailable".to_string())?;
    let resolved_socket = std::fs::canonicalize(socket_path)
        .map_err(|_| "scanner verification socket path is unavailable".to_string())?;
    if resolved_socket == resolved_dir || !resolved_socket.starts_with(&resolved_dir) {
        return Err("scanner verification socket path is unavailable".to_string());
    }
    Ok(resolved_socket)
}

fn read_osp_unix_xml_response(stream: &mut UnixStream) -> Result<String, String> {
    let mut payload = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream.read(&mut buffer).map_err(|_| {
            if payload.is_empty() {
                "scanner did not return an OSP get_version response".to_string()
            } else {
                "scanner returned an incomplete OSP get_version response".to_string()
            }
        })?;
        if count == 0 {
            return Err("scanner closed the OSP connection before a complete response".to_string());
        }
        payload.extend_from_slice(&buffer[..count]);
        if payload.len() > OSP_MAX_RESPONSE_BYTES {
            return Err(
                "scanner OSP get_version response exceeded the native API limit".to_string(),
            );
        }
        let text = String::from_utf8_lossy(&payload);
        if xml_document_is_complete(&text) {
            return Ok(text.into_owned());
        }
    }
}

fn xml_document_is_complete(xml: &str) -> bool {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => return true,
            Err(_) => return false,
            _ => {}
        }
    }
}

pub(crate) fn parse_osp_get_version_response(xml: &str) -> Result<OspVersionInfo, ApiError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut response_status_ok = false;
    let mut section = String::new();
    let mut current = String::new();
    let mut scanner_name = None;
    let mut scanner_version = None;
    let mut daemon_name = None;
    let mut daemon_version = None;
    let mut protocol_name = None;
    let mut protocol_version = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event)) => {
                let local = xml_local_name(event.name().as_ref()).to_vec();
                match local.as_slice() {
                    b"get_version_response" => {
                        response_status_ok =
                            xml_attr_value(&event, b"status")?.as_deref() == Some("200");
                    }
                    b"scanner" | b"daemon" | b"protocol" => {
                        section = String::from_utf8_lossy(&local).into_owned();
                    }
                    b"name" | b"version" => {
                        current = String::from_utf8_lossy(&local).into_owned();
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(event)) => {
                let text = event
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                capture_osp_version_text(
                    section.as_str(),
                    current.as_str(),
                    text,
                    &mut scanner_name,
                    &mut scanner_version,
                    &mut daemon_name,
                    &mut daemon_version,
                    &mut protocol_name,
                    &mut protocol_version,
                );
            }
            Ok(Event::CData(event)) => {
                let text = event
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                capture_osp_version_text(
                    section.as_str(),
                    current.as_str(),
                    text,
                    &mut scanner_name,
                    &mut scanner_version,
                    &mut daemon_name,
                    &mut daemon_version,
                    &mut protocol_name,
                    &mut protocol_version,
                );
            }
            Ok(Event::End(event)) => match xml_local_name(event.name().as_ref()) {
                b"scanner" | b"daemon" | b"protocol" => {
                    section.clear();
                    current.clear();
                }
                b"name" | b"version" => current.clear(),
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(error) => {
                tracing::warn!(%error, "OSP get_version XML parse failed");
                return Err(ApiError::BadRequest(
                    "OSP get_version response XML is invalid".to_string(),
                ));
            }
            _ => {}
        }
    }

    if !response_status_ok {
        return Err(ApiError::BadRequest(
            "OSP get_version response did not report status 200".to_string(),
        ));
    }
    let scanner_version = scanner_version
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest("OSP get_version response is missing scanner version".to_string())
        })?;
    Ok(OspVersionInfo {
        scanner_name,
        scanner_version,
        daemon_name,
        daemon_version,
        protocol_name,
        protocol_version,
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_osp_version_text(
    section: &str,
    current: &str,
    text: String,
    scanner_name: &mut Option<String>,
    scanner_version: &mut Option<String>,
    daemon_name: &mut Option<String>,
    daemon_version: &mut Option<String>,
    protocol_name: &mut Option<String>,
    protocol_version: &mut Option<String>,
) {
    match (section, current) {
        ("scanner", "name") => *scanner_name = Some(text),
        ("scanner", "version") => *scanner_version = Some(text),
        ("daemon", "name") => *daemon_name = Some(text),
        ("daemon", "version") => *daemon_version = Some(text),
        ("protocol", "name") => *protocol_name = Some(text),
        ("protocol", "version") => *protocol_version = Some(text),
        _ => {}
    }
}

fn xml_attr_value(event: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, ApiError> {
    for attr in event.attributes() {
        let attr = attr.map_err(|_| {
            ApiError::BadRequest("OSP get_version response XML is invalid".to_string())
        })?;
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
