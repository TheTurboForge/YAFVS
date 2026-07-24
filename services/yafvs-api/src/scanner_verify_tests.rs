// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    fs,
    os::unix::{fs::symlink, net::UnixListener},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use super::scanner_verify::{
    canonical_osp_verify_socket_path_in_dir, parse_osp_get_version_response,
    scanner_verify_osp_socket_is_allowed,
};

fn temporary_osp_socket_test_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("yafvs-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).expect("temporary test directory must be created");
    dir
}

#[test]
fn osp_get_version_parser_extracts_scanner_daemon_and_protocol_versions() {
    let parsed = parse_osp_get_version_response(
        r#"<get_version_response status_text="OK" status="200">
             <protocol><version>1.0</version><name>OSP</name></protocol>
             <daemon><version>22.9.0</version><name>ospd-openvas</name></daemon>
             <scanner><version>23.11.0</version><name>OpenVAS</name></scanner>
           </get_version_response>"#,
    )
    .expect("valid OSP get_version response must parse");

    assert_eq!(parsed.scanner_name.as_deref(), Some("OpenVAS"));
    assert_eq!(parsed.scanner_version, "23.11.0");
    assert_eq!(parsed.daemon_name.as_deref(), Some("ospd-openvas"));
    assert_eq!(parsed.daemon_version.as_deref(), Some("22.9.0"));
    assert_eq!(parsed.protocol_name.as_deref(), Some("OSP"));
    assert_eq!(parsed.protocol_version.as_deref(), Some("1.0"));
}

#[test]
fn osp_get_version_parser_rejects_non_ok_or_incomplete_responses() {
    assert!(
        parse_osp_get_version_response(
            r#"<get_version_response status_text="Error" status="500"/>"#
        )
        .is_err()
    );
    assert!(
        parse_osp_get_version_response(
            r#"<get_version_response status_text="OK" status="200"><scanner/></get_version_response>"#
        )
        .is_err()
    );
}

#[test]
fn scanner_verify_allows_only_runtime_ospd_unix_socket_paths() {
    assert!(scanner_verify_osp_socket_is_allowed(
        "/runtime/run/ospd/ospd-openvas.sock"
    ));
    assert!(scanner_verify_osp_socket_is_allowed(
        "/runtime/run/ospd/custom-sensor.sock"
    ));
    assert!(!scanner_verify_osp_socket_is_allowed(
        "/run/ospd/ospd-openvas.sock"
    ));
    assert!(!scanner_verify_osp_socket_is_allowed(
        "/runtime/run/ospd/../secret.sock"
    ));
    assert!(!scanner_verify_osp_socket_is_allowed("127.0.0.1"));
}

#[test]
fn canonical_osp_verify_socket_accepts_a_contained_unix_socket() {
    let root = temporary_osp_socket_test_dir("contained-osp-socket");
    let allowed_dir = root.join("ospd");
    fs::create_dir(&allowed_dir).expect("allowed directory must be created");
    let socket = allowed_dir.join("ospd-openvas.sock");
    let listener = UnixListener::bind(&socket).expect("contained Unix socket must bind");

    let resolved = canonical_osp_verify_socket_path_in_dir(
        socket.to_str().expect("temporary path must be UTF-8"),
        &allowed_dir,
    )
    .expect("contained Unix socket must be accepted");

    assert!(resolved.starts_with(fs::canonicalize(&allowed_dir).unwrap()));
    drop(listener);
    fs::remove_dir_all(&root).expect("temporary test directory must be removed");
}

#[test]
fn canonical_osp_verify_socket_rejects_an_in_directory_symlink_to_an_outside_socket() {
    let root = temporary_osp_socket_test_dir("symlinked-osp-socket");
    let allowed_dir = root.join("ospd");
    let outside_dir = root.join("outside");
    fs::create_dir(&allowed_dir).expect("allowed directory must be created");
    fs::create_dir(&outside_dir).expect("outside directory must be created");
    let outside_socket = outside_dir.join("outside.sock");
    let listener = UnixListener::bind(&outside_socket).expect("outside Unix socket must bind");
    let linked_socket = allowed_dir.join("linked.sock");
    symlink(&outside_socket, &linked_socket).expect("socket symlink must be created");

    let error = canonical_osp_verify_socket_path_in_dir(
        linked_socket
            .to_str()
            .expect("temporary path must be UTF-8"),
        &allowed_dir,
    )
    .expect_err("symlink to an outside Unix socket must be rejected");

    assert_eq!(error, "scanner verification socket path is unavailable");
    drop(listener);
    fs::remove_dir_all(&root).expect("temporary test directory must be removed");
}
