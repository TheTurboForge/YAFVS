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

use axum::http::StatusCode;

use super::*;

const CONTROL_SECRET: &str = "0123456789abcdef0123456789abcdef";
const OPERATOR_UUID: &str = "11111111-1111-1111-1111-111111111111";
const SOURCE_TASK_UUID: &str = "22222222-2222-2222-8222-222222222222";
const CREATED_TASK_UUID: &str = "33333333-3333-3333-8333-333333333333";
static NEXT_SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

fn mock_socket_path() -> PathBuf {
    let sequence = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "turbovas-task-clone-{}-{sequence}.sock",
        process::id()
    ))
}

fn mock_control_socket(response: Vec<u8>) -> (PathBuf, thread::JoinHandle<Vec<u8>>) {
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
        stream
            .write_all(&response)
            .expect("mock UDS must write response");
        command
    });
    (socket_path, handle)
}

#[test]
fn task_clone_control_frame_uses_the_exact_bounded_canonical_protocol() {
    let frame = task_clone_command(CONTROL_SECRET, OPERATOR_UUID, SOURCE_TASK_UUID)
        .expect("valid task clone frame");
    assert_eq!(
        frame.as_bytes(),
        format!("task-clone {CONTROL_SECRET} {OPERATOR_UUID} {SOURCE_TASK_UUID}\n").as_bytes()
    );
    assert!(frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
}

#[test]
fn task_clone_control_frame_rejects_noncanonical_or_unbounded_identifiers() {
    for invalid_uuid in [
        "not-a-uuid",
        "22222222222222222222222222222222",
        &"a".repeat(MAX_CONTROL_REQUEST_BYTES),
    ] {
        let error = match task_clone_command(CONTROL_SECRET, invalid_uuid, SOURCE_TASK_UUID) {
            Err(error) => error,
            Ok(_) => panic!("invalid operator UUID must fail"),
        };
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);

        let error = match task_clone_command(CONTROL_SECRET, OPERATOR_UUID, invalid_uuid) {
            Err(error) => error,
            Ok(_) => panic!("invalid source task UUID must fail"),
        };
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }
}

#[test]
fn task_clone_control_frame_rejects_missing_weak_or_wire_unsafe_secrets() {
    for secret in [
        "too-short".to_string(),
        "0123456789abcdef0123456789abcde!".to_string(),
        "a".repeat(129),
    ] {
        let error = match task_clone_command(&secret, OPERATOR_UUID, SOURCE_TASK_UUID) {
            Err(error) => error,
            Ok(_) => panic!("invalid control secret must fail"),
        };
        assert!(matches!(error, ApiError::Config));
    }
}

#[tokio::test]
async fn task_clone_request_uses_the_configured_socket_and_exact_frame() {
    let (socket_path, handle) =
        mock_control_socket(format!("0 created {CREATED_TASK_UUID}\n").into_bytes());
    let created_task_id = request_task_clone(
        socket_path.to_str().expect("socket path is UTF-8"),
        CONTROL_SECRET,
        OPERATOR_UUID,
        SOURCE_TASK_UUID,
    )
    .await
    .expect("task clone must succeed");
    let command = handle.join().expect("mock UDS thread must finish");
    std::fs::remove_file(socket_path).expect("mock UDS path must be removed");

    assert_eq!(created_task_id, CREATED_TASK_UUID);
    assert_eq!(
        command,
        format!("task-clone {CONTROL_SECRET} {OPERATOR_UUID} {SOURCE_TASK_UUID}\n").into_bytes()
    );
}

#[test]
fn task_clone_response_maps_every_documented_outcome() {
    assert_eq!(
        parse_task_clone_response(format!("0 created {CREATED_TASK_UUID}").as_bytes())
            .expect("created response must return its UUID"),
        CREATED_TASK_UUID
    );

    for (response, status, code, message) in [
        (b"1 duplicate".as_slice(), 409, "conflict", "already exists"),
        (
            b"2 not_found".as_slice(),
            404,
            "not_found",
            "requested resource",
        ),
        (
            b"99 forbidden".as_slice(),
            403,
            "forbidden",
            "authenticated operator",
        ),
        (
            b"-2 malformed".as_slice(),
            400,
            "bad_request",
            "task clone control request was rejected",
        ),
        (
            b"-3 committed_indeterminate".as_slice(),
            502,
            "committed_response_unavailable",
            "mutation committed",
        ),
        (
            b"-1 internal".as_slice(),
            502,
            "control_failure",
            "control service failed",
        ),
    ] {
        let error = parse_task_clone_response(response).expect_err("documented failure must fail");
        assert_eq!(error.status_code().as_u16(), status);
        assert_eq!(error.code(), code);
        assert!(
            error
                .public_message()
                .to_ascii_lowercase()
                .contains(message)
        );
    }
}

#[test]
fn task_clone_response_rejects_invalid_created_ids_and_unknown_responses_as_indeterminate() {
    for response in [
        b"0 created not-a-uuid".as_slice(),
        b"0 created 33333333333333333333333333333333".as_slice(),
        b"0 created 33333333-3333-3333-8333-333333333333 extra".as_slice(),
        b"unexpected".as_slice(),
        b"".as_slice(),
    ] {
        let error = parse_task_clone_response(response).expect_err("invalid response must fail");
        assert!(matches!(error, ApiError::MutationOutcomeIndeterminate));
        assert_eq!(error.status_code(), StatusCode::BAD_GATEWAY);
    }
}
