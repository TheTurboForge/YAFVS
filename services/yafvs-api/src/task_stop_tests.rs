// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    process,
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::Duration,
};

use crate::{
    errors::ApiError,
    task_stop::{
        ControlSocketError, TaskStopOutcome, gvmd_control_secret_from_source,
        map_control_socket_error, parse_task_stop_response, request_task_stop, task_stop_command,
    },
};

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
const OPERATOR_UUID: &str = "11111111-1111-1111-1111-111111111111";
const TASK_UUID: &str = "22222222-2222-2222-2222-222222222222";
static NEXT_SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

fn mock_socket_path() -> PathBuf {
    let sequence = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "turbovas-task-stop-{}-{sequence}.sock",
        process::id()
    ))
}

fn mock_control_socket(response_chunks: Vec<Vec<u8>>) -> (PathBuf, thread::JoinHandle<Vec<u8>>) {
    let socket_path = mock_socket_path();
    let listener = UnixListener::bind(&socket_path).expect("mock UDS must bind");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("mock UDS must accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("mock UDS must set read timeout");
        let mut command = Vec::new();
        let mut byte = [0_u8; 1];
        while command.len() < 256 {
            let count = stream.read(&mut byte).expect("mock UDS must read command");
            if count == 0 {
                break;
            }
            command.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        for response in response_chunks {
            stream
                .write_all(&response)
                .expect("mock UDS must write response");
        }
        command
    });
    (socket_path, handle)
}

async fn request_stop_from_mock(
    response_chunks: Vec<Vec<u8>>,
) -> (Result<TaskStopOutcome, ControlSocketError>, Vec<u8>) {
    let (socket_path, handle) = mock_control_socket(response_chunks);
    let result = request_task_stop(
        socket_path.to_str().unwrap(),
        CONTROL_SECRET,
        OPERATOR_UUID,
        TASK_UUID,
    )
    .await;
    let command = handle.join().expect("mock UDS thread must finish");
    std::fs::remove_file(socket_path).expect("mock UDS path must be removed");
    (result, command)
}

#[test]
fn task_stop_command_authenticates_before_operator_and_task() {
    assert_eq!(
        task_stop_command(CONTROL_SECRET, OPERATOR_UUID, TASK_UUID),
        format!("stop {CONTROL_SECRET} {OPERATOR_UUID} {TASK_UUID}\n")
    );
}

#[tokio::test]
async fn task_stop_mock_uds_sends_exact_command_and_maps_stopped_response() {
    let (result, command) = request_stop_from_mock(vec![b"0 stopped\n".to_vec()]).await;
    assert_eq!(result, Ok(TaskStopOutcome::Stopped));
    assert_eq!(
        command,
        format!("stop {CONTROL_SECRET} {OPERATOR_UUID} {TASK_UUID}\n").into_bytes()
    );
}

#[tokio::test]
async fn task_stop_mock_uds_maps_chunked_requested_response_without_reporting_stopped() {
    let (result, _) =
        request_stop_from_mock(vec![b"1 re".to_vec(), b"quested".to_vec(), b"\n".to_vec()]).await;
    assert_eq!(result, Err(ControlSocketError::Requested));
}

#[tokio::test]
async fn task_stop_mock_uds_rejects_trailing_and_overlong_responses() {
    let (partial, _) = request_stop_from_mock(vec![b"0 stopped".to_vec()]).await;
    assert_eq!(partial, Err(ControlSocketError::OutcomeIndeterminate));

    let (trailing, _) =
        request_stop_from_mock(vec![b"0 stopped\n".to_vec(), b"trailing".to_vec()]).await;
    assert_eq!(trailing, Err(ControlSocketError::OutcomeIndeterminate));

    let (overlong, _) = request_stop_from_mock(vec![vec![b'x'; 257]]).await;
    assert_eq!(overlong, Err(ControlSocketError::OutcomeIndeterminate));
}

#[test]
fn task_stop_response_parser_maps_only_documented_wire_responses() {
    for (response, expected) in [
        (b"0 stopped".as_slice(), Ok(TaskStopOutcome::Stopped)),
        (b"2 inactive".as_slice(), Ok(TaskStopOutcome::Stopped)),
        (
            b"1 requested".as_slice(),
            Err(ControlSocketError::Requested),
        ),
        (b"3 not_found".as_slice(), Err(ControlSocketError::NotFound)),
        (
            b"99 forbidden".as_slice(),
            Err(ControlSocketError::Forbidden),
        ),
        (b"-1 internal".as_slice(), Err(ControlSocketError::Failure)),
        (
            b"-2 scanner_status".as_slice(),
            Err(ControlSocketError::ScannerUnverified),
        ),
        (
            b"-3 scanner_stop".as_slice(),
            Err(ControlSocketError::ScannerUnverified),
        ),
        (
            b"-4 scanner_delete".as_slice(),
            Err(ControlSocketError::ScannerUnverified),
        ),
        (
            b"-5 scanner_verify".as_slice(),
            Err(ControlSocketError::ScannerUnverified),
        ),
    ] {
        assert_eq!(parse_task_stop_response(response), expected);
    }
    for response in [
        b"0 stopped\n".as_slice(),
        b"0 stopped extra".as_slice(),
        b"0 stopped\r".as_slice(),
        b"\xff".as_slice(),
        b"".as_slice(),
    ] {
        assert_eq!(
            parse_task_stop_response(response),
            Err(ControlSocketError::Failure)
        );
    }
}

#[test]
fn task_stop_gvmd_negative_statuses_keep_the_documented_http_mappings() {
    for (response, expected_status, expected_code) in [
        (b"1 requested".as_slice(), 409, "stop_requested"),
        (b"3 not_found".as_slice(), 404, "not_found"),
        (b"99 forbidden".as_slice(), 403, "forbidden"),
        (b"-1 internal".as_slice(), 502, "control_failure"),
        (b"-2 scanner_status".as_slice(), 502, "scanner_unverified"),
        (b"-3 scanner_stop".as_slice(), 502, "scanner_unverified"),
        (b"-4 scanner_delete".as_slice(), 502, "scanner_unverified"),
        (b"-5 scanner_verify".as_slice(), 502, "scanner_unverified"),
    ] {
        let error = map_control_socket_error(parse_task_stop_response(response).unwrap_err());
        assert_eq!(error.status_code().as_u16(), expected_status);
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn task_stop_control_secret_fails_closed_when_missing_weak_or_wire_unsafe() {
    assert!(matches!(
        gvmd_control_secret_from_source(None),
        Err(ApiError::Config)
    ));
    for invalid in [
        "too-short".to_string(),
        "0123456789abcdef0123456789abcde!".to_string(),
        "a".repeat(129),
    ] {
        assert!(matches!(
            gvmd_control_secret_from_source(Some(invalid)),
            Err(ApiError::Config)
        ));
    }
    assert_eq!(
        gvmd_control_secret_from_source(Some(CONTROL_SECRET.to_string())).unwrap(),
        CONTROL_SECRET
    );
}

#[tokio::test]
async fn task_stop_request_rejects_weak_secret_before_opening_socket() {
    let result = request_task_stop(
        mock_socket_path().to_str().unwrap(),
        "too-short",
        OPERATOR_UUID,
        TASK_UUID,
    )
    .await;
    assert_eq!(result, Err(ControlSocketError::Configuration));
    assert!(matches!(
        map_control_socket_error(result.unwrap_err()),
        ApiError::Config
    ));
}

#[tokio::test]
async fn task_stop_unavailable_socket_maps_to_service_unavailable_without_path_leakage() {
    let missing_socket = mock_socket_path();
    let result = request_task_stop(
        missing_socket.to_str().unwrap(),
        CONTROL_SECRET,
        OPERATOR_UUID,
        TASK_UUID,
    )
    .await;
    assert_eq!(result, Err(ControlSocketError::Unavailable));
    let error = map_control_socket_error(result.unwrap_err());
    assert!(matches!(error, ApiError::ControlUnavailable));
    assert_eq!(error.status_code().as_u16(), 503);
    assert!(
        !error
            .public_message()
            .contains(missing_socket.to_str().unwrap())
    );
}

#[test]
fn task_stop_handler_is_operator_authenticated_and_does_not_apply_a_rust_owner_equality_gate() {
    let source = include_str!("task_stop.rs");
    let handler = source
        .split_once("pub(crate) async fn stop_task")
        .unwrap()
        .1;
    for required in [
        "require_task_write_operator(operator)?",
        "parse_uuid(&task_id)?",
        "operator.user_uuid()",
        "request_task_stop(",
    ] {
        assert!(
            handler.contains(required),
            "task stop handler missing {required}"
        );
    }
    for forbidden in [
        "resolve_task_write_operator_owner",
        "ensure_task_owner_matches_operator",
        "transaction()",
        "state.pool",
        "spawn_blocking",
        "unsafe",
    ] {
        assert!(
            !handler.contains(forbidden),
            "task stop handler must delegate authorization to gvmd, not {forbidden}"
        );
    }
}
