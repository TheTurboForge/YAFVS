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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(super) enum OspdVtLoadObservation {
    Pass,
    Fail,
    Wait,
}

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

#[cfg(test)]
fn parse_ospd_vts_version(response: &[u8]) -> Option<String> {
    match inspect_xml(response) {
        DocumentState::Complete(version) => version,
        DocumentState::Incomplete | DocumentState::Invalid => None,
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

#[cfg(test)]
fn ospd_vt_load_status_from_logs<I, S>(lines: I) -> (OspdVtLoadObservation, Vec<String>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut relevant: Vec<String> = Vec::new();
    for line in lines {
        let line = line.as_ref();
        if line.contains("Finished loading VTs") || line.contains("VTs were up to date") {
            push_relevant(&mut relevant, line);
            return (OspdVtLoadObservation::Pass, relevant);
        }
        if line.contains("Updating VTs failed")
            || line.contains("failed to load VTs")
            || line.contains("OpenVAS Scanner failed to load VTs")
        {
            push_relevant(&mut relevant, line);
            return (OspdVtLoadObservation::Fail, relevant);
        }
        if line.contains("Loading VTs") {
            push_relevant(&mut relevant, line);
        }
    }
    (OspdVtLoadObservation::Wait, relevant)
}

#[cfg(test)]
fn push_relevant(relevant: &mut Vec<String>, line: &str) {
    if relevant.len() == 20 {
        relevant.remove(0);
    }
    relevant.push(line.to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn socket_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "yafvsctl-ospd-{label}-{}-{}.sock",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn serve_once(label: &str, response: Vec<u8>) -> (PathBuf, thread::JoinHandle<Vec<u8>>) {
        let path = socket_path(label);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = vec![0_u8; OSPD_VTS_VERSION_REQUEST.len()];
            stream.read_exact(&mut request).unwrap();
            let _ = stream.write_all(&response);
            request
        });
        (path, handle)
    }

    #[test]
    fn pass_on_finished_loading_vts() {
        let (status, lines) =
            ospd_vt_load_status_from_logs(["Loading VTs", "Finished loading VTs"]);
        assert!(matches!(status, OspdVtLoadObservation::Pass));
        assert_eq!(
            lines,
            vec![
                "Loading VTs".to_string(),
                "Finished loading VTs".to_string()
            ]
        );
    }

    #[test]
    fn pass_on_vts_were_up_to_date() {
        let (status, lines) = ospd_vt_load_status_from_logs(["Loading VTs", "VTs were up to date"]);
        assert!(matches!(status, OspdVtLoadObservation::Pass));
        assert_eq!(
            lines,
            vec!["Loading VTs".to_string(), "VTs were up to date".to_string()]
        );
    }

    #[test]
    fn fail_on_updating_vts_failed() {
        let (status, lines) = ospd_vt_load_status_from_logs(["Loading VTs", "Updating VTs failed"]);
        assert!(matches!(status, OspdVtLoadObservation::Fail));
        assert_eq!(
            lines,
            vec!["Loading VTs".to_string(), "Updating VTs failed".to_string()]
        );
    }

    #[test]
    fn fail_on_failed_to_load_vts() {
        let (status, lines) = ospd_vt_load_status_from_logs(["Loading VTs", "failed to load VTs"]);
        assert!(matches!(status, OspdVtLoadObservation::Fail));
        assert_eq!(
            lines,
            vec!["Loading VTs".to_string(), "failed to load VTs".to_string()]
        );
    }

    #[test]
    fn fail_on_openvas_scanner_failed_to_load_vts() {
        let (status, lines) =
            ospd_vt_load_status_from_logs(["Loading VTs", "OpenVAS Scanner failed to load VTs"]);
        assert!(matches!(status, OspdVtLoadObservation::Fail));
        assert_eq!(
            lines,
            vec![
                "Loading VTs".to_string(),
                "OpenVAS Scanner failed to load VTs".to_string()
            ]
        );
    }

    #[test]
    fn wait_with_bounded_relevant_lines() {
        let mut input = Vec::new();
        for index in 0..25 {
            input.push(format!("Loading VTs {index}"));
        }
        input.push("still waiting".to_string());
        let (status, lines) = ospd_vt_load_status_from_logs(input);
        assert!(matches!(status, OspdVtLoadObservation::Wait));
        assert_eq!(lines.len(), 20);
        assert_eq!(lines[0], "Loading VTs 5");
        assert_eq!(lines[19], "Loading VTs 24");
    }

    #[test]
    fn unrelated_lines_are_ignored() {
        let (status, lines) = ospd_vt_load_status_from_logs(["alpha", "beta", "gamma"]);
        assert!(matches!(status, OspdVtLoadObservation::Wait));
        assert!(lines.is_empty());
    }

    #[test]
    fn terminal_marker_wins_by_input_order() {
        let (status, lines) = ospd_vt_load_status_from_logs([
            "Loading VTs",
            "Finished loading VTs",
            "Updating VTs failed",
        ]);
        assert!(matches!(status, OspdVtLoadObservation::Pass));
        assert_eq!(
            lines,
            vec![
                "Loading VTs".to_string(),
                "Finished loading VTs".to_string()
            ]
        );
    }

    #[test]
    fn pass_marker_takes_precedence_with_both_markers_on_one_line() {
        let (status, lines) = ospd_vt_load_status_from_logs([
            "Loading VTs and Finished loading VTs but also Updating VTs failed",
        ]);
        assert!(matches!(status, OspdVtLoadObservation::Pass));
        assert_eq!(
            lines,
            vec!["Loading VTs and Finished loading VTs but also Updating VTs failed".to_string()]
        );
    }

    #[test]
    fn query_writes_exact_request_and_reads_the_vt_version() {
        let response =
            br#"<get_vts_response><vts vts_version="202607181200"/></get_vts_response>"#.to_vec();
        let (path, server) = serve_once("exact", response);
        let version = query_ospd_vts_version(&path, Duration::from_secs(2)).unwrap();
        assert_eq!(version, "202607181200");
        assert_eq!(server.join().unwrap(), OSPD_VTS_VERSION_REQUEST);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn namespace_qualified_vts_is_accepted() {
        let response = br#"<o:get_vts_response xmlns:o="urn:ospd"><o:vts vts_version="qualified"/></o:get_vts_response>"#
            .to_vec();
        let (path, server) = serve_once("namespace", response);
        assert_eq!(
            query_ospd_vts_version(&path, Duration::from_secs(2)).unwrap(),
            "qualified"
        );
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_and_missing_versions_fail_closed() {
        assert_eq!(parse_ospd_vts_version(b"not xml"), None);
        assert_eq!(
            parse_ospd_vts_version(b"<get_vts_response><vts/></get_vts_response>"),
            None
        );
        assert_eq!(
            parse_ospd_vts_version(b"<get_vts_response><vts vts_version=\"\"/></get_vts_response>"),
            None
        );
        assert_eq!(
            parse_ospd_vts_version(
                b"<get_vts_response><vts/><vts vts_version=\"later\"/></get_vts_response>"
            ),
            None
        );
        assert_eq!(
            parse_ospd_vts_version(
                b"<get_vts_response><vts vts_version=\"first\"/><vts vts_version=\"second\"/></get_vts_response>"
            ),
            Some("first".to_owned())
        );
    }

    #[test]
    fn premature_close_fails_without_returning_partial_xml() {
        let (path, server) = serve_once("partial", b"<get_vts_response>".to_vec());
        assert!(matches!(
            query_ospd_vts_version(&path, Duration::from_secs(2)),
            Err(OspdQueryError::IncompleteXml | OspdQueryError::InvalidXml)
        ));
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn response_is_bounded_before_growth_beyond_one_mebibyte() {
        let response = vec![b' '; MAX_RESPONSE_BYTES + READ_CHUNK_BYTES];
        let (path, server) = serve_once("oversized", response);
        assert_eq!(
            query_ospd_vts_version(&path, Duration::from_secs(2)),
            Err(OspdQueryError::ResponseTooLarge)
        );
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn version_wait_retries_a_complete_starting_response() {
        let path = socket_path("retry");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            for response in [
                b"<error_response status=\"400\" status_text=\"OSPd OpenVAS is still starting\"/>"
                    .as_slice(),
                b"<get_vts_response><vts vts_version=\"ready\"/></get_vts_response>".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = vec![0_u8; OSPD_VTS_VERSION_REQUEST.len()];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(request, OSPD_VTS_VERSION_REQUEST);
                stream.write_all(response).unwrap();
            }
        });

        assert_eq!(
            wait_for_ospd_vts_version(
                &path,
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::ZERO,
            )
            .unwrap(),
            "ready"
        );
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unix_socket_wait_checks_the_live_listener_without_fixed_paths() {
        let path = socket_path("wait");
        let listener = UnixListener::bind(&path).unwrap();
        assert!(wait_for_unix_socket(&path, Duration::ZERO, Duration::ZERO));
        drop(listener);
        fs::remove_file(&path).unwrap();
        assert!(!wait_for_unix_socket(&path, Duration::ZERO, Duration::ZERO));
    }
}
