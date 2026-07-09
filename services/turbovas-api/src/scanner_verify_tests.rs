// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::scanner_verify::{parse_osp_get_version_response, scanner_verify_osp_socket_is_allowed};

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
