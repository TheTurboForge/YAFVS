// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
// SPDX-License-Identifier: GPL-3.0-or-later

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

const OSPD_VTS_VERSION_REQUEST: &[u8] = br#"<get_vts version_only="1"/>"#;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub(super) fn wait_for_unix_socket(
    socket_path: &Path,
    overall_timeout: Duration,
    retry_delay: Duration,
) -> bool {
    let deadline = Instant::now() + overall_timeout;
    loop {
        if UnixStream::connect(socket_path).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        if !retry_delay.is_zero() {
            std::thread::sleep(retry_delay.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

pub(super) fn wait_for_ospd_vts_version(
    socket_path: &Path,
    overall_timeout: Duration,
    probe_timeout: Duration,
    retry_delay: Duration,
) -> Result<String, OspdQueryError> {
    let deadline = Instant::now() + overall_timeout;
    loop {
        let retry_error = match query_ospd_vts_version(socket_path, probe_timeout) {
            Ok(version) => return Ok(version),
            Err(
                error @ (OspdQueryError::Socket
                | OspdQueryError::Timeout
                | OspdQueryError::IncompleteXml
                | OspdQueryError::MissingVersion),
            ) => error,
            Err(error @ (OspdQueryError::InvalidXml | OspdQueryError::ResponseTooLarge)) => {
                return Err(error);
            }
        };
        if Instant::now() >= deadline {
            return Err(retry_error);
        }
        if !retry_delay.is_zero() {
            std::thread::sleep(retry_delay.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OspdQueryError {
    Socket,
    Timeout,
    IncompleteXml,
    InvalidXml,
    MissingVersion,
    ResponseTooLarge,
}

impl fmt::Display for OspdQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Socket => "OSPD socket operation failed",
            Self::Timeout => "OSPD socket operation timed out",
            Self::IncompleteXml => "OSPD socket closed before a complete XML response",
            Self::InvalidXml => "OSPD returned invalid XML",
            Self::MissingVersion => "OSPD response did not contain a VT feed version",
            Self::ResponseTooLarge => "OSPD XML response exceeded the safety limit",
        })
    }
}

impl std::error::Error for OspdQueryError {}

pub(super) fn query_ospd_vts_version(
    socket_path: &Path,
    timeout: Duration,
) -> Result<String, OspdQueryError> {
    let mut connection = UnixStream::connect(socket_path).map_err(map_io_error)?;
    connection
        .set_read_timeout(Some(timeout))
        .map_err(map_io_error)?;
    connection
        .set_write_timeout(Some(timeout))
        .map_err(map_io_error)?;
    connection
        .write_all(OSPD_VTS_VERSION_REQUEST)
        .map_err(map_io_error)?;

    let mut response = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let read = connection.read(&mut chunk).map_err(map_io_error)?;
        if read == 0 {
            return Err(if response.is_empty() {
                OspdQueryError::IncompleteXml
            } else {
                match inspect_xml(&response) {
                    DocumentState::Invalid => OspdQueryError::InvalidXml,
                    _ => OspdQueryError::IncompleteXml,
                }
            });
        }
        if response.len().saturating_add(read) > MAX_RESPONSE_BYTES {
            return Err(OspdQueryError::ResponseTooLarge);
        }
        response.extend_from_slice(&chunk[..read]);
        match inspect_xml(&response) {
            DocumentState::Complete(Some(version)) => return Ok(version),
            DocumentState::Complete(None) => return Err(OspdQueryError::MissingVersion),
            DocumentState::Incomplete | DocumentState::Invalid => {}
        }
    }
}

fn map_io_error(error: std::io::Error) -> OspdQueryError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        OspdQueryError::Timeout
    } else {
        OspdQueryError::Socket
    }
}

enum DocumentState {
    Complete(Option<String>),
    Incomplete,
    Invalid,
}

fn inspect_xml(response: &[u8]) -> DocumentState {
    let mut reader = Reader::from_reader(response);
    let mut depth = 0_usize;
    let mut root_seen = false;
    let mut root_complete = false;
    let mut vts_seen = false;
    let mut version = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                if root_complete {
                    return DocumentState::Invalid;
                }
                root_seen = true;
                depth = depth.saturating_add(1);
                if element.local_name().as_ref() == b"vts" && !vts_seen {
                    vts_seen = true;
                    match vts_version(&element, reader.decoder()) {
                        Ok(observed) if observed.is_some() => version = observed,
                        Ok(_) => {}
                        Err(()) => return DocumentState::Invalid,
                    }
                }
            }
            Ok(Event::Empty(element)) => {
                if root_complete {
                    return DocumentState::Invalid;
                }
                if !root_seen {
                    root_seen = true;
                    root_complete = true;
                }
                if element.local_name().as_ref() == b"vts" && !vts_seen {
                    vts_seen = true;
                    match vts_version(&element, reader.decoder()) {
                        Ok(observed) if observed.is_some() => version = observed,
                        Ok(_) => {}
                        Err(()) => return DocumentState::Invalid,
                    }
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return DocumentState::Invalid;
                }
                depth -= 1;
                if depth == 0 {
                    root_complete = true;
                }
            }
            Ok(Event::Text(text)) if !root_seen || root_complete => {
                let bytes: &[u8] = text.as_ref();
                if !bytes.iter().all(u8::is_ascii_whitespace) {
                    return DocumentState::Invalid;
                }
            }
            Ok(Event::Eof) => {
                return if root_complete {
                    DocumentState::Complete(version)
                } else {
                    DocumentState::Incomplete
                };
            }
            Ok(_) => {}
            Err(_) => return DocumentState::Invalid,
        }
    }
}

fn vts_version(
    element: &BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
) -> Result<Option<String>, ()> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|_| ())?;
        if attribute.key.local_name().as_ref() != b"vts_version" {
            continue;
        }
        let value = attribute
            .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, decoder)
            .map_err(|_| ())?;
        return Ok((!value.is_empty()).then(|| value.into_owned()));
    }
    Ok(None)
}
