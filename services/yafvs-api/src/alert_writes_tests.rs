// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    alert_payloads::AlertAssetItem,
    alert_write_db::ensure_alert_owner_matches_operator,
    alert_write_sql::*,
    alert_write_validation::{
        AlertCloneRequest, AlertCreateRequest, AlertEmailCreateRequest, AlertPatchRequest,
        MAX_ALERT_MESSAGE_BYTES, MAX_ALERT_SUBJECT_BYTES, MAX_ALERT_TEXT_BYTES,
        ValidatedAlertCreate, ValidatedAlertScpCreate, ValidatedAlertSmbCreate,
        ValidatedAlertSnmpCreate, ValidatedAlertStartTaskCreate, ValidatedAlertSyslogCreate,
        validate_alert_clone_request, validate_alert_create_request,
        validate_alert_email_create_request, validate_alert_patch_request,
    },
    alert_writes::{
        alert_email_create_command, alert_scp_create_command, alert_smb_create_command,
        alert_snmp_create_command, alert_start_task_create_command, alert_syslog_create_command,
        parse_alert_create_response,
    },
    errors::ApiError,
    gvmd_control::{
        ControlSocketError, MAX_CONTROL_REQUEST_BYTES, request_gvmd_control_response_bytes,
    },
};

const TEST_UUID: &str = "12345678-1234-4234-8234-123456789abc";

fn email_create_json(notice: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "Daily findings",
        "comment": "Operator delivery",
        "active": true,
        "status": "Done",
        "to_address": "security@example.invalid",
        "from_address": "scanner@example.invalid",
        "subject": "Scan report",
        "notice": notice
    })
}

fn start_task_create_json() -> serde_json::Value {
    serde_json::json!({
        "method": "START_TASK",
        "name": "Start follow-up scan",
        "comment": "Operator automation",
        "active": true,
        "status": "Done",
        "task_id": TEST_UUID
    })
}

#[test]
fn alert_scp_create_frame_is_exact_bounded_and_scrubbed_without_value_leaks() {
    let request = validated_scp_create();
    let mut frame =
        alert_scp_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &request);
    assert_eq!(
        frame.as_bytes(),
        concat!(
            "alert-scp-create 0123456789abcdef0123456789abcdef ",
            "12345678-1234-4234-8234-123456789abc 1 ",
            "RGFpbHkgU0NQIGZpbmRpbmdz T3BlcmF0b3IgZGVsaXZlcnk= RG9uZQ== ",
            "MTIzNDU2NzgtMTIzNC00MjM0LTgyMzQtMTIzNDU2Nzg5YWJj ",
            "MTkyLjAuMi40NA== MjIyMg== ",
            "WzE5Mi4wLjIuNDRdOjIyMjIgc3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSVRlc3RLZXk= ",
            "L3Zhci9yZXBvcnRzL2RhaWx5LnBkZg== ",
            "MTIzNDU2NzgtMTIzNC00MjM0LTgyMzQtMTIzNDU2Nzg5YWJj\n"
        )
        .as_bytes()
    );
    assert!(frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    frame.scrub();
    assert!(frame.as_bytes().iter().all(|byte| *byte == 0));

    let mut maximum = scp_create_json();
    for field in ["name", "comment", "scp_known_hosts", "scp_path"] {
        maximum[field] = serde_json::json!("x".repeat(MAX_ALERT_TEXT_BYTES));
    }
    let maximum = serde_json::from_value::<AlertCreateRequest>(maximum).unwrap();
    let maximum = match validate_alert_create_request(maximum).unwrap() {
        ValidatedAlertCreate::Scp(request) => request,
        _ => unreachable!(),
    };
    let maximum_frame =
        alert_scp_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &maximum);
    assert!(maximum_frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
}

fn validated_start_task_create() -> ValidatedAlertStartTaskCreate {
    let request = serde_json::from_value::<AlertCreateRequest>(start_task_create_json())
        .expect("valid Start Task alert request shape");
    match validate_alert_create_request(request).expect("valid Start Task alert request") {
        ValidatedAlertCreate::StartTask(request) => request,
        _ => panic!("START_TASK method must select Start Task request"),
    }
}

#[test]
fn alert_scp_create_shape_is_strict_and_cross_method_fields_are_rejected() {
    assert!(matches!(
        validate_alert_create_request(
            serde_json::from_value::<AlertCreateRequest>(scp_create_json()).unwrap()
        ),
        Ok(ValidatedAlertCreate::Scp(_))
    ));

    for field in [
        "method",
        "name",
        "active",
        "status",
        "scp_credential_id",
        "scp_host",
        "scp_port",
        "scp_known_hosts",
        "scp_path",
        "report_format_id",
    ] {
        let mut value = scp_create_json();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AlertCreateRequest>(value).is_err(),
            "{field} must be required"
        );
    }

    for (field, value) in [
        (
            "smb_share_path",
            serde_json::json!("\\\\fileserver\\reports"),
        ),
        ("to_address", serde_json::json!("security@example.invalid")),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut request = scp_create_json();
        request[field] = value;
        assert!(serde_json::from_value::<AlertCreateRequest>(request).is_err());
    }
}

#[test]
fn alert_start_task_create_frame_is_exact_bounded_and_scrubbable() {
    let request = validated_start_task_create();
    let mut frame =
        alert_start_task_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &request);
    assert_eq!(
        frame.as_bytes(),
        concat!(
            "alert-start-task-create 0123456789abcdef0123456789abcdef ",
            "12345678-1234-4234-8234-123456789abc 1 ",
            "U3RhcnQgZm9sbG93LXVwIHNjYW4= T3BlcmF0b3IgYXV0b21hdGlvbg== RG9uZQ== ",
            "12345678-1234-4234-8234-123456789abc\n"
        )
        .as_bytes()
    );
    assert!(frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    frame.scrub();
    assert!(frame.as_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn alert_start_task_create_shape_is_strict_and_task_id_is_validated() {
    assert!(matches!(
        validate_alert_create_request(
            serde_json::from_value::<AlertCreateRequest>(start_task_create_json()).unwrap()
        ),
        Ok(ValidatedAlertCreate::StartTask(_))
    ));

    for field in ["method", "name", "active", "status", "task_id"] {
        let mut value = start_task_create_json();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AlertCreateRequest>(value).is_err(),
            "{field} must be required"
        );
    }

    for (field, value) in [
        ("to_address", serde_json::json!("security@example.invalid")),
        ("scp_path", serde_json::json!("/var/reports/daily.pdf")),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut request = start_task_create_json();
        request[field] = value;
        assert!(serde_json::from_value::<AlertCreateRequest>(request).is_err());
    }

    for invalid in [
        "not-a-uuid".to_string(),
        format!(" {TEST_UUID} "),
        TEST_UUID.replace('-', ""),
    ] {
        let mut request = start_task_create_json();
        request["task_id"] = serde_json::json!(invalid);
        let request = serde_json::from_value::<AlertCreateRequest>(request).unwrap();
        assert!(matches!(
            validate_alert_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
}

#[test]
fn alert_scp_create_rejects_unpinned_or_invalid_delivery_controls() {
    for field in ["scp_credential_id", "report_format_id"] {
        for invalid in [
            "not-a-uuid".to_string(),
            format!(" {TEST_UUID} "),
            TEST_UUID.replace("-", ""),
        ] {
            let mut value = scp_create_json();
            value[field] = serde_json::json!(invalid);
            let request = serde_json::from_value::<AlertCreateRequest>(value).unwrap();
            assert!(matches!(
                validate_alert_create_request(request),
                Err(ApiError::BadRequest(_))
            ));
        }
    }

    for (field, invalid) in [
        ("scp_host", ""),
        ("scp_host", "host name"),
        ("scp_host", "host.example.invalid."),
        ("scp_host", "host\nexample.invalid"),
        ("scp_path", ""),
        ("scp_path", "reports\u{000b}daily.pdf"),
        ("scp_known_hosts", ""),
        ("scp_known_hosts", "ssh-ed25519 AAAA\u{000b}key"),
    ] {
        let mut value = scp_create_json();
        value[field] = serde_json::json!(invalid);
        let request = serde_json::from_value::<AlertCreateRequest>(value).unwrap();
        assert!(matches!(
            validate_alert_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }

    let mut zero_port = scp_create_json();
    zero_port["scp_port"] = serde_json::json!(0);
    let request = serde_json::from_value::<AlertCreateRequest>(zero_port).unwrap();
    assert!(matches!(
        validate_alert_create_request(request),
        Err(ApiError::BadRequest(_))
    ));

    let mut oversized_port = scp_create_json();
    oversized_port["scp_port"] = serde_json::json!(65_536);
    assert!(serde_json::from_value::<AlertCreateRequest>(oversized_port).is_err());

    let known_hosts = "[192.0.2.44]:2222 ssh-ed25519 AAAA\r\nssh-rsa BBBB\tcomment";
    let mut permitted_controls = scp_create_json();
    permitted_controls["scp_known_hosts"] = serde_json::json!(known_hosts);
    let request = serde_json::from_value::<AlertCreateRequest>(permitted_controls).unwrap();
    let ValidatedAlertCreate::Scp(validated) = validate_alert_create_request(request).unwrap()
    else {
        panic!("SCP method must select SCP request");
    };
    assert_eq!(validated.scp_known_hosts.as_bytes(), known_hosts.as_bytes());
}

fn scp_create_json() -> serde_json::Value {
    serde_json::json!({
        "method": "SCP",
        "name": "Daily SCP findings",
        "comment": "Operator delivery",
        "active": true,
        "status": "Done",
        "scp_credential_id": TEST_UUID,
        "scp_host": "192.0.2.44",
        "scp_port": 2222,
        "scp_known_hosts": "[192.0.2.44]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
        "scp_path": "/var/reports/daily.pdf",
        "report_format_id": TEST_UUID
    })
}

fn syslog_create_json() -> serde_json::Value {
    serde_json::json!({
        "method": "SYSLOG",
        "name": "Security event log",
        "comment": "Operator delivery",
        "active": true,
        "status": "Done"
    })
}

fn validated_scp_create() -> ValidatedAlertScpCreate {
    let request = serde_json::from_value::<AlertCreateRequest>(scp_create_json())
        .expect("valid SCP alert request shape");
    match validate_alert_create_request(request).expect("valid SCP alert request") {
        ValidatedAlertCreate::Scp(request) => request,
        _ => panic!("SCP method must select SCP request"),
    }
}

fn snmp_create_json() -> serde_json::Value {
    serde_json::json!({
        "method": "SNMP",
        "name": "SNMP security event",
        "comment": "Operator delivery",
        "active": true,
        "status": "Done",
        "snmp_agent": "localhost",
        "snmp_community": "private-community",
        "snmp_message": "$e"
    })
}

fn tagged_email_create_json(notice: &str) -> serde_json::Value {
    let mut value = email_create_json(notice);
    value["method"] = serde_json::json!("EMAIL");
    value
}

fn smb_create_json() -> serde_json::Value {
    serde_json::json!({
        "method": "SMB",
        "name": "Daily findings",
        "comment": "Operator delivery",
        "active": true,
        "status": "Done",
        "smb_credential_id": TEST_UUID,
        "smb_share_path": "\\\\fileserver\\reports",
        "smb_file_path": "daily-%Y%m%d.pdf",
        "report_format_id": TEST_UUID
    })
}

fn validated_smb_create(protocol: Option<&str>) -> ValidatedAlertSmbCreate {
    let mut value = smb_create_json();
    if let Some(protocol) = protocol {
        value["smb_max_protocol"] = serde_json::json!(protocol);
    }
    let request =
        serde_json::from_value::<AlertCreateRequest>(value).expect("valid SMB alert request shape");
    match validate_alert_create_request(request).expect("valid SMB alert request") {
        ValidatedAlertCreate::Smb(request) => request,
        _ => panic!("SMB method must select SMB request"),
    }
}

fn validated_syslog_create() -> ValidatedAlertSyslogCreate {
    let request = serde_json::from_value::<AlertCreateRequest>(syslog_create_json())
        .expect("valid Syslog alert request shape");
    match validate_alert_create_request(request).expect("valid Syslog alert request") {
        ValidatedAlertCreate::Syslog(request) => request,
        _ => panic!("SYSLOG method must select Syslog request"),
    }
}

fn validated_snmp_create() -> ValidatedAlertSnmpCreate {
    let request = serde_json::from_value::<AlertCreateRequest>(snmp_create_json())
        .expect("valid SNMP alert request shape");
    match validate_alert_create_request(request).expect("valid SNMP alert request") {
        ValidatedAlertCreate::Snmp(request) => request,
        _ => panic!("SNMP method must select SNMP request"),
    }
}

#[test]
fn email_and_smb_alert_references_are_locked_inside_create_transactions() {
    let manager = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
    let function = manager
        .split_once("create_alert_email_with_report_refs")
        .unwrap()
        .1
        .split_once("/* SecInfo. */")
        .unwrap()
        .0;
    for required in [
        "sql_begin_immediate ();",
        "acl_user_may (\"create_alert\")",
        "lock_alert_create_owner",
        "lock_alert_report_format",
        "lock_alert_recipient_credential",
        "EVENT_TASK_RUN_STATUS_CHANGED",
        "ALERT_CONDITION_ALWAYS",
        "ALERT_METHOD_EMAIL",
        "create_alert_body",
        "sql_rollback ();",
        "sql_commit ();",
    ] {
        assert!(
            function.contains(required),
            "atomic EMAIL create missing {required}"
        );
    }
    assert!(manager.matches("FOR SHARE").count() >= 3);
    assert!(manager.contains("SELECT id FROM users WHERE uuid = '%s' FOR UPDATE;"));
    assert!(manager.matches("ret = lock_alert_create_owner ();").count() >= 4);
    assert!(
        function.find("acl_user_may").unwrap() < function.find("lock_alert_report_format").unwrap()
    );
    assert!(
        function.find("lock_alert_report_format").unwrap()
            < function.find("create_alert_body").unwrap()
    );
    assert!(function.find("create_alert_body").unwrap() < function.rfind("sql_commit").unwrap());

    let smb_function = manager
        .split_once("create_alert_smb_with_report_refs")
        .unwrap()
        .1
        .split_once("/**\n * @brief Delete an alert.")
        .unwrap()
        .0;
    for required in [
        "sql_begin_immediate ();",
        "acl_user_may (\"create_alert\")",
        "lock_alert_create_owner",
        "lock_alert_smb_credential",
        "lock_alert_report_format",
        "EVENT_TASK_RUN_STATUS_CHANGED",
        "ALERT_CONDITION_ALWAYS",
        "ALERT_METHOD_SMB",
        "create_alert_body",
        "sql_rollback ();",
        "sql_commit ();",
    ] {
        assert!(
            smb_function.contains(required),
            "atomic SMB create missing {required}"
        );
    }
    assert!(
        smb_function.find("acl_user_may").unwrap()
            < smb_function.find("lock_alert_smb_credential").unwrap()
    );
    assert!(
        smb_function.find("lock_alert_smb_credential").unwrap()
            < smb_function.find("lock_alert_report_format").unwrap()
    );
    assert!(
        smb_function.find("lock_alert_report_format").unwrap()
            < smb_function.find("create_alert_body").unwrap()
    );
    assert!(
        smb_function.find("create_alert_body").unwrap() < smb_function.rfind("sql_commit").unwrap()
    );

    let user_manager = include_str!("../../../components/gvmd/src/manage_sql_users.c");
    let delete_user = user_manager
        .split_once("delete_user (const char *user_id_arg")
        .unwrap()
        .1
        .split_once("int\ncopy_user")
        .unwrap()
        .0;
    assert!(delete_user.contains("SELECT id FROM users WHERE id = %llu FOR UPDATE;"));
    assert!(
        delete_user.find("FOR UPDATE").unwrap()
            < delete_user.find("information_schema.columns").unwrap()
    );

    let control = include_str!("../../../components/gvmd/src/turbovas_control.c");
    let control_create = control
        .split_once("turbovas_control_create_alert_email")
        .unwrap()
        .1
        .split_once("turbovas_control_create_schedule")
        .unwrap()
        .0;
    assert!(control_create.contains("create_alert_email_with_report_refs"));
    assert!(!control_create.contains("create_alert ("));
}

#[test]
fn alert_create_openapi_metadata_is_direct_guarded_and_redacted() {
    let openapi = include_str!("../../../api/openapi/yafvs-v1.yaml");
    let block = openapi
        .split_once("  /alerts:\n")
        .unwrap()
        .1
        .split_once("  /alerts/{alert_id}:\n")
        .unwrap()
        .0;
    for expected in [
        "operationId: postAlerts",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-write",
        "x-yafvs-replaces: alert-email-smb-syslog-snmp-scp-start-task-create",
        "x-yafvs-operator-identity: direct-token-operator",
        "x-yafvs-owner-semantics: request-operator-owner",
        "x-yafvs-safety-contract: write-control-v1",
        "x-yafvs-side-effect: alert-delivery-control",
        "$ref: '#/components/schemas/AlertCreateRequest'",
        "$ref: '#/components/schemas/AlertAsset'",
        "response contains redacted metadata only",
        "'502':",
        "'503':",
    ] {
        assert!(
            block.contains(expected),
            "alert create OpenAPI missing {expected}"
        );
    }
    let mut simple_with_empty_message = email_create_json("simple");
    simple_with_empty_message["message"] = serde_json::json!("");
    let request =
        serde_json::from_value::<AlertEmailCreateRequest>(simple_with_empty_message).unwrap();
    assert!(validate_alert_email_create_request(request).is_ok());
    let schema = openapi
        .split_once("    AlertCreateRequest:\n")
        .unwrap()
        .1
        .split_once("    AlertPatchRequest:\n")
        .unwrap()
        .0;
    assert!(schema.contains("additionalProperties: false"));
    assert!(schema.contains("propertyName: method"));
    assert!(schema.contains("EMAIL: '#/components/schemas/AlertEmailCreateRequest'"));
    assert!(schema.contains("SMB: '#/components/schemas/AlertSmbCreateRequest'"));
    assert!(schema.contains("SYSLOG: '#/components/schemas/AlertSyslogCreateRequest'"));
    assert!(schema.contains("SNMP: '#/components/schemas/AlertSnmpCreateRequest'"));
    assert!(schema.contains("START_TASK: '#/components/schemas/AlertStartTaskCreateRequest'"));
    assert!(schema.contains("enum: [simple, include, attach]"));
    assert!(schema.contains("enum: [default, NT1, SMB2, SMB3]"));
    assert!(schema.contains("writeOnly: true"));
    assert!(schema.contains("AlertScpCreateRequest"));
    assert!(schema.contains("AlertStartTaskCreateRequest"));
    assert!(schema.contains("required: [method, name, active, status, task_id]"));
    assert!(schema.contains("const: START_TASK"));
    for field in [
        "to_address",
        "from_address",
        "subject",
        "recipient_credential_id",
        "report_format_id",
        "message",
        "smb_credential_id",
        "smb_share_path",
        "smb_file_path",
        "smb_max_protocol",
        "scp_credential_id",
        "scp_host",
        "scp_port",
        "scp_known_hosts",
        "scp_path",
    ] {
        assert!(schema.contains(&format!("{field}:")));
    }
    let mut padded_uuid = email_create_json("include");
    padded_uuid["report_format_id"] = serde_json::json!(format!(" {TEST_UUID} "));
    let request = serde_json::from_value::<AlertEmailCreateRequest>(padded_uuid).unwrap();
    assert!(matches!(
        validate_alert_email_create_request(request),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_create_requires_exact_method_and_rejects_cross_method_fields() {
    assert!(
        serde_json::from_value::<AlertCreateRequest>(tagged_email_create_json("simple")).is_ok()
    );
    assert!(serde_json::from_value::<AlertCreateRequest>(smb_create_json()).is_ok());
    assert!(serde_json::from_value::<AlertCreateRequest>(start_task_create_json()).is_ok());

    for method in [None, Some("email"), Some("smb"), Some("SCP"), Some("")] {
        let mut value = tagged_email_create_json("simple");
        match method {
            Some(method) => value["method"] = serde_json::json!(method),
            None => {
                value.as_object_mut().unwrap().remove("method");
            }
        }
        assert!(serde_json::from_value::<AlertCreateRequest>(value).is_err());
    }

    let mut email_with_smb_field = tagged_email_create_json("simple");
    email_with_smb_field["smb_share_path"] = serde_json::json!("reports");
    assert!(serde_json::from_value::<AlertCreateRequest>(email_with_smb_field).is_err());

    let mut smb_with_email_field = smb_create_json();
    smb_with_email_field["to_address"] = serde_json::json!("security@example.invalid");
    assert!(serde_json::from_value::<AlertCreateRequest>(smb_with_email_field).is_err());
}

#[test]
fn alert_smb_create_requires_fixed_fields_and_rejects_unknown_fields() {
    for field in [
        "method",
        "name",
        "active",
        "status",
        "smb_credential_id",
        "smb_share_path",
        "smb_file_path",
        "report_format_id",
    ] {
        let mut value = smb_create_json();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AlertCreateRequest>(value).is_err(),
            "{field} must be required"
        );
    }
    let mut unknown = smb_create_json();
    unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AlertCreateRequest>(unknown).is_err());
}

#[test]
fn alert_smb_create_validates_uuids_paths_caps_and_protocols() {
    for field in ["smb_credential_id", "report_format_id"] {
        for invalid in [
            "not-a-uuid".to_string(),
            format!(" {TEST_UUID} "),
            TEST_UUID.replace('-', ""),
        ] {
            let mut value = smb_create_json();
            value[field] = serde_json::json!(invalid);
            let request = serde_json::from_value::<AlertCreateRequest>(value).unwrap();
            assert!(matches!(
                validate_alert_create_request(request),
                Err(ApiError::BadRequest(_))
            ));
        }
    }
    for (field, value) in [
        ("name", ""),
        ("smb_share_path", ""),
        ("smb_share_path", "bad\nshare"),
        ("smb_file_path", "bad\0path"),
    ] {
        let mut request = smb_create_json();
        request[field] = serde_json::json!(value);
        let request = serde_json::from_value::<AlertCreateRequest>(request).unwrap();
        assert!(matches!(
            validate_alert_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
    for field in ["name", "comment", "smb_share_path", "smb_file_path"] {
        let mut value = smb_create_json();
        value[field] = serde_json::json!("x".repeat(MAX_ALERT_TEXT_BYTES + 1));
        let request = serde_json::from_value::<AlertCreateRequest>(value).unwrap();
        assert!(matches!(
            validate_alert_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }

    assert_eq!(validated_smb_create(None).smb_max_protocol.as_bytes(), b"");
    for (protocol, expected) in [
        ("default", b"".as_slice()),
        ("NT1", b"NT1".as_slice()),
        ("SMB2", b"SMB2".as_slice()),
        ("SMB3", b"SMB3".as_slice()),
    ] {
        assert_eq!(
            validated_smb_create(Some(protocol))
                .smb_max_protocol
                .as_bytes(),
            expected
        );
    }
    for protocol in ["", "nt1", "SMB1", "SMB 3"] {
        let mut value = smb_create_json();
        value["smb_max_protocol"] = serde_json::json!(protocol);
        assert!(serde_json::from_value::<AlertCreateRequest>(value).is_err());
    }
}

fn validated_email_create(
    notice: &str,
) -> crate::alert_write_validation::ValidatedAlertEmailCreate {
    let mut value = email_create_json(notice);
    if notice != "simple" {
        value["report_format_id"] = serde_json::json!(TEST_UUID);
    }
    let request = serde_json::from_value::<AlertEmailCreateRequest>(value)
        .expect("valid email alert request shape");
    validate_alert_email_create_request(request).expect("valid email alert request")
}

#[test]
fn alert_smb_create_frame_is_exact_bounded_and_scrubbable() {
    let request = validated_smb_create(Some("SMB3"));
    let mut frame =
        alert_smb_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &request);
    assert_eq!(
        frame.as_bytes(),
        concat!(
            "alert-smb-create 0123456789abcdef0123456789abcdef ",
            "12345678-1234-4234-8234-123456789abc 1 ",
            "RGFpbHkgZmluZGluZ3M= T3BlcmF0b3IgZGVsaXZlcnk= RG9uZQ== ",
            "MTIzNDU2NzgtMTIzNC00MjM0LTgyMzQtMTIzNDU2Nzg5YWJj ",
            "XFxmaWxlc2VydmVyXHJlcG9ydHM= ZGFpbHktJVklbSVkLnBkZg== ",
            "MTIzNDU2NzgtMTIzNC00MjM0LTgyMzQtMTIzNDU2Nzg5YWJj U01CMw==\n"
        )
        .as_bytes()
    );
    assert!(frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    frame.scrub();
    assert!(frame.as_bytes().iter().all(|byte| *byte == 0));

    let mut maximum = smb_create_json();
    for field in ["name", "comment", "smb_file_path"] {
        maximum[field] = serde_json::json!("x".repeat(MAX_ALERT_TEXT_BYTES));
    }
    maximum["smb_share_path"] =
        serde_json::json!(format!("\\\\h\\{}", "x".repeat(MAX_ALERT_TEXT_BYTES - 4)));
    let maximum = serde_json::from_value::<AlertCreateRequest>(maximum).unwrap();
    let maximum = match validate_alert_create_request(maximum).unwrap() {
        ValidatedAlertCreate::Smb(request) => request,
        _ => unreachable!(),
    };
    let maximum_frame =
        alert_smb_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &maximum);
    assert!(maximum_frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
}

#[test]
fn alert_syslog_and_snmp_create_frames_are_exact_bounded_and_scrubbable() {
    let syslog = validated_syslog_create();
    let mut syslog_frame =
        alert_syslog_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &syslog);
    assert_eq!(
        syslog_frame.as_bytes(),
        concat!(
            "alert-syslog-create 0123456789abcdef0123456789abcdef ",
            "12345678-1234-4234-8234-123456789abc 1 ",
            "U2VjdXJpdHkgZXZlbnQgbG9n T3BlcmF0b3IgZGVsaXZlcnk= RG9uZQ==\n"
        )
        .as_bytes()
    );
    assert!(syslog_frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    syslog_frame.scrub();
    assert!(syslog_frame.as_bytes().iter().all(|byte| *byte == 0));

    let snmp = validated_snmp_create();
    let mut snmp_frame =
        alert_snmp_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &snmp);
    assert_eq!(
        snmp_frame.as_bytes(),
        concat!(
            "alert-snmp-create 0123456789abcdef0123456789abcdef ",
            "12345678-1234-4234-8234-123456789abc 1 ",
            "U05NUCBzZWN1cml0eSBldmVudA== T3BlcmF0b3IgZGVsaXZlcnk= RG9uZQ== ",
            "bG9jYWxob3N0 cHJpdmF0ZS1jb21tdW5pdHk= JGU=\n"
        )
        .as_bytes()
    );
    assert!(snmp_frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    snmp_frame.scrub();
    assert!(snmp_frame.as_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn alert_syslog_and_snmp_create_shapes_are_strict_and_sensitive() {
    let syslog = serde_json::from_value::<AlertCreateRequest>(syslog_create_json()).unwrap();
    assert!(matches!(
        validate_alert_create_request(syslog),
        Ok(ValidatedAlertCreate::Syslog(_))
    ));

    for field in ["snmp_agent", "snmp_community", "snmp_message"] {
        let mut value = snmp_create_json();
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<AlertCreateRequest>(value).is_err());
    }
    let mut control = snmp_create_json();
    control["snmp_community"] = serde_json::json!("secret\nvalue");
    let request = serde_json::from_value::<AlertCreateRequest>(control).unwrap();
    assert!(validate_alert_create_request(request).is_err());

    let validation = include_str!("alert_write_validation.rs");
    for field in [
        "snmp_agent: SensitiveAlertField",
        "snmp_community: SensitiveAlertField",
        "snmp_message: SensitiveAlertField",
    ] {
        assert!(
            validation.contains(field),
            "missing sensitive field {field}"
        );
    }
}

#[test]
fn alert_email_create_schema_requires_fixed_fields_and_rejects_unknown_fields() {
    for field in [
        "name",
        "active",
        "status",
        "to_address",
        "subject",
        "notice",
    ] {
        let mut value = email_create_json("simple");
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AlertEmailCreateRequest>(value).is_err(),
            "{field} must be required"
        );
    }
    let mut unknown = email_create_json("simple");
    unknown["method"] = serde_json::json!("EMAIL");
    assert!(serde_json::from_value::<AlertEmailCreateRequest>(unknown).is_err());
}

#[test]
fn alert_email_create_accepts_only_exact_status_values() {
    for status in [
        "Delete Requested",
        "Ultimate Delete Requested",
        "Ultimate Delete Waiting",
        "Delete Waiting",
        "Done",
        "New",
        "Requested",
        "Running",
        "Queued",
        "Stop Requested",
        "Stop Waiting",
        "Stopped",
        "Processing",
        "Interrupted",
    ] {
        let mut value = email_create_json("simple");
        value["status"] = serde_json::json!(status);
        let request = serde_json::from_value::<AlertEmailCreateRequest>(value).unwrap();
        assert!(
            validate_alert_email_create_request(request).is_ok(),
            "{status}"
        );
    }
    for status in ["done", "Delete requested", "Container", ""] {
        let mut value = email_create_json("simple");
        value["status"] = serde_json::json!(status);
        assert!(serde_json::from_value::<AlertEmailCreateRequest>(value).is_err());
    }
    for field in ["name", "comment", "to_address", "from_address"] {
        let mut value = email_create_json("simple");
        value[field] = serde_json::json!(format!("{} ", "x".repeat(MAX_ALERT_TEXT_BYTES)));
        let request = serde_json::from_value::<AlertEmailCreateRequest>(value).unwrap();
        assert!(
            matches!(
                validate_alert_email_create_request(request),
                Err(ApiError::BadRequest(_))
            ),
            "{field} raw byte cap"
        );
    }
}

#[test]
fn alert_email_create_enforces_notice_mode_cross_fields() {
    assert_eq!(validated_email_create("simple").notice.control_token(), 1);
    assert_eq!(validated_email_create("include").notice.control_token(), 0);
    assert_eq!(validated_email_create("attach").notice.control_token(), 2);

    let mut simple = email_create_json("simple");
    for field in ["report_format_id"] {
        simple[field] = serde_json::json!(TEST_UUID);
        let request = serde_json::from_value::<AlertEmailCreateRequest>(simple.clone()).unwrap();
        assert!(matches!(
            validate_alert_email_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
        simple.as_object_mut().unwrap().remove(field);
    }
    let mut simple_with_message = email_create_json("simple");
    simple_with_message["message"] = serde_json::json!("plain text body");
    let request = serde_json::from_value::<AlertEmailCreateRequest>(simple_with_message).unwrap();
    assert!(validate_alert_email_create_request(request).is_ok());

    for notice in ["include", "attach"] {
        let request =
            serde_json::from_value::<AlertEmailCreateRequest>(email_create_json(notice)).unwrap();
        assert!(matches!(
            validate_alert_email_create_request(request),
            Err(ApiError::BadRequest(_))
        ));

        let mut valid = email_create_json(notice);
        valid["report_format_id"] = serde_json::json!(TEST_UUID);
        valid["message"] = serde_json::json!("bounded body");
        let request = serde_json::from_value::<AlertEmailCreateRequest>(valid).unwrap();
        assert!(validate_alert_email_create_request(request).is_ok());
    }
}

#[test]
fn alert_email_create_rejects_bad_uuids_controls_blanks_and_byte_overflow() {
    for field in ["recipient_credential_id", "report_format_id"] {
        let mut value = email_create_json("include");
        value["report_format_id"] = serde_json::json!(TEST_UUID);
        value[field] = serde_json::json!("not-a-uuid");
        let request = serde_json::from_value::<AlertEmailCreateRequest>(value).unwrap();
        assert!(matches!(
            validate_alert_email_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
    for (field, value) in [
        ("name", ""),
        ("to_address", "bad\naddress"),
        ("from_address", "bad\0address"),
        ("subject", ""),
        ("message", "bad\u{000b}message"),
    ] {
        let mut request = email_create_json(if field == "message" {
            "include"
        } else {
            "simple"
        });
        if field == "message" {
            request["report_format_id"] = serde_json::json!(TEST_UUID);
        }
        request[field] = serde_json::json!(value);
        let request = serde_json::from_value::<AlertEmailCreateRequest>(request).unwrap();
        assert!(matches!(
            validate_alert_email_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
    for (field, value) in [
        ("smb_credential_id", format!("{TEST_UUID}\r\n")),
        (
            "smb_share_path",
            "\\\\fileserver\\reports\"; quit".to_string(),
        ),
        ("smb_share_path", "\\\\fileserver\\reports;quit".to_string()),
        ("smb_share_path", "\\\\fileserver\\reports|quit".to_string()),
        (
            "smb_share_path",
            "\\\\fileserver\\reports&&quit".to_string(),
        ),
        (
            "smb_share_path",
            "\\\\fileserver\\reports\r\nnext".to_string(),
        ),
        ("smb_file_path", "daily.pdf\"; quit".to_string()),
        ("smb_file_path", "daily.pdf;quit".to_string()),
        ("smb_file_path", "daily.pdf|quit".to_string()),
        ("smb_file_path", "daily.pdf&&quit".to_string()),
        ("smb_file_path", "daily.pdf$HOME".to_string()),
        ("smb_file_path", "daily.pdf\r\nnext".to_string()),
    ] {
        let mut request = smb_create_json();
        request[field] = serde_json::json!(value);
        let request = serde_json::from_value::<AlertCreateRequest>(request).unwrap();
        assert!(matches!(
            validate_alert_create_request(request),
            Err(ApiError::BadRequest(_))
        ));
    }
    for (share_path, file_path) in [
        ("\\\\fileserver\\reports", "daily-%Y%m%d.pdf"),
        (
            "//fileserver/team-reports",
            "archive/weekly report-%Y%m%d.pdf",
        ),
        ("\\\\192.0.2.10\\reports", "2026/scan-report.pdf"),
    ] {
        let mut request = smb_create_json();
        request["smb_share_path"] = serde_json::json!(share_path);
        request["smb_file_path"] = serde_json::json!(file_path);
        let request = serde_json::from_value::<AlertCreateRequest>(request).unwrap();
        assert!(validate_alert_create_request(request).is_ok());
    }
    for (field, limit, notice) in [
        ("name", MAX_ALERT_TEXT_BYTES, "simple"),
        ("comment", MAX_ALERT_TEXT_BYTES, "simple"),
        ("to_address", MAX_ALERT_TEXT_BYTES, "simple"),
        ("from_address", MAX_ALERT_TEXT_BYTES, "simple"),
        ("subject", MAX_ALERT_SUBJECT_BYTES, "simple"),
        ("message", MAX_ALERT_MESSAGE_BYTES, "include"),
    ] {
        let mut value = email_create_json(notice);
        if notice == "include" {
            value["report_format_id"] = serde_json::json!(TEST_UUID);
        }
        value[field] = serde_json::json!("x".repeat(limit + 1));
        let request = serde_json::from_value::<AlertEmailCreateRequest>(value).unwrap();
        assert!(
            matches!(
                validate_alert_email_create_request(request),
                Err(ApiError::BadRequest(_))
            ),
            "{field}"
        );
    }
}

#[test]
fn alert_email_create_preserves_multiline_message_content() {
    let mut value = email_create_json("include");
    value["report_format_id"] = serde_json::json!(TEST_UUID);
    value["message"] = serde_json::json!("  first line\r\nsecond\tline  ");
    let request = serde_json::from_value::<AlertEmailCreateRequest>(value).unwrap();
    let validated = validate_alert_email_create_request(request).unwrap();
    assert_eq!(
        validated.message.as_bytes(),
        b"  first line\r\nsecond\tline  "
    );
}

#[test]
fn alert_email_create_frame_is_exact_bounded_and_scrubbable() {
    let request = validated_email_create("include");
    let mut frame =
        alert_email_create_command("0123456789abcdef0123456789abcdef", TEST_UUID, &request);
    assert_eq!(
        frame.as_bytes(),
        concat!(
            "alert-email-create 0123456789abcdef0123456789abcdef ",
            "12345678-1234-4234-8234-123456789abc 1 ",
            "RGFpbHkgZmluZGluZ3M= T3BlcmF0b3IgZGVsaXZlcnk= RG9uZQ== ",
            "c2VjdXJpdHlAZXhhbXBsZS5pbnZhbGlk c2Nhbm5lckBleGFtcGxlLmludmFsaWQ= ",
            "U2NhbiByZXBvcnQ= 0  ",
            "MTIzNDU2NzgtMTIzNC00MjM0LTgyMzQtMTIzNDU2Nzg5YWJj \n"
        )
        .as_bytes()
    );
    assert!(frame.as_bytes().len() < MAX_CONTROL_REQUEST_BYTES);
    frame.scrub();
    assert!(frame.as_bytes().iter().all(|byte| *byte == 0));
}

#[tokio::test]
async fn alert_email_create_control_frame_cap_is_enforced_before_socket_io() {
    let command = vec![b'x'; MAX_CONTROL_REQUEST_BYTES];
    assert_eq!(
        request_gvmd_control_response_bytes(
            "/definitely/not/a/socket",
            "0123456789abcdef0123456789abcdef",
            &command,
        )
        .await,
        Err(ControlSocketError::Failure)
    );
}

#[test]
fn alert_create_maps_explicit_control_responses() {
    for response in [
        b"2 invalid_email".as_slice(),
        b"4 invalid_filter_type",
        b"5 invalid_condition_name",
        b"6 invalid_condition_data",
        b"7 subject_too_long",
        b"8 message_too_long",
        b"15 invalid_scp_host",
        b"16 invalid_scp_port",
        b"18 invalid_scp_credential",
        b"19 invalid_scp_path",
        b"20 method_event_mismatch",
        b"21 condition_event_mismatch",
        b"31 invalid_event_name",
        b"32 invalid_event_data",
        b"40 invalid_smb_credential",
        b"41 invalid_smb_share",
        b"42 invalid_smb_path",
        b"43 dotted_smb_path",
        b"61 invalid_recipient_credential",
        b"-2 malformed",
    ] {
        assert!(matches!(
            parse_alert_create_response(response),
            Err(ApiError::BadRequest(_))
        ));
    }
    assert!(matches!(
        parse_alert_create_response(b"99 forbidden"),
        Err(ApiError::Forbidden)
    ));
    for response in [
        b"3 filter_not_found".as_slice(),
        b"3 task_not_found",
        b"9 condition_filter_not_found",
        b"17 scp_format_not_found",
        b"60 recipient_credential_not_found",
        b"90 report_format_not_found",
    ] {
        assert!(matches!(
            parse_alert_create_response(response),
            Err(ApiError::NotFound)
        ));
    }
    assert!(matches!(
        parse_alert_create_response(b"1 exists"),
        Err(ApiError::Conflict(_))
    ));
    assert!(matches!(
        parse_alert_create_response(b"-3 committed_indeterminate"),
        Err(ApiError::MutationCommittedResponseUnavailable)
    ));
    let internal = parse_alert_create_response(b"-1 internal").unwrap_err();
    assert_eq!(
        internal.status_code(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        parse_alert_create_response(b"0 created 12345678-1234-4234-8234-123456789abc").unwrap(),
        TEST_UUID
    );
    assert!(matches!(
        parse_alert_create_response(b"0 created not-a-uuid"),
        Err(ApiError::MutationCommittedResponseUnavailable)
    ));
    assert!(matches!(
        parse_alert_create_response(b"unexpected-response"),
        Err(ApiError::MutationOutcomeIndeterminate)
    ));

    let gsad = include_str!("../../../components/gsad/src/gsad_native_api.c");
    assert!(gsad.contains("cJSON_ParseWithOpts"));
    assert!(gsad.contains("cJSON_IsObject"));
    assert!(gsad.contains("response_body_is_json_object (body)"));
}

#[test]
fn alert_create_handler_dispatches_methods_and_returns_only_redacted_asset_shape() {
    let handler = include_str!("alert_writes.rs")
        .split_once("pub(crate) async fn create_alert")
        .unwrap()
        .1
        .split_once("pub(crate) fn parse_alert_create_payload")
        .unwrap()
        .0;
    assert!(handler.contains("StatusCode::CREATED"));
    assert!(handler.contains("parse_alert_create_payload(payload)?"));
    assert!(handler.contains("ValidatedAlertCreate::Email(request)"));
    assert!(handler.contains("ValidatedAlertCreate::Smb(request)"));
    assert!(handler.contains("ValidatedAlertCreate::Syslog(request)"));
    assert!(handler.contains("ValidatedAlertCreate::Snmp(request)"));
    assert!(handler.contains("ValidatedAlertCreate::Scp(request)"));
    assert!(handler.contains("ValidatedAlertCreate::StartTask(request)"));
    assert!(handler.contains("request_alert_email_create"));
    assert!(handler.contains("request_alert_smb_create"));
    assert!(handler.contains("request_alert_syslog_create"));
    assert!(handler.contains("request_alert_snmp_create"));
    assert!(handler.contains("request_alert_scp_create"));
    assert!(handler.contains("request_alert_start_task_create"));
    assert!(handler.contains("load_alert_asset_detail"));
    assert!(handler.contains("JOIN users u ON u.id = a.owner"));
    assert!(handler.contains("u.uuid = $2"));
    assert!(handler.contains("MutationCommittedResponseUnavailable"));
    assert!(!handler.contains(".user_name()"));
    for forbidden in [
        "to_address",
        "from_address",
        "subject",
        "message",
        "recipient_credential_id",
        "report_format_id",
        "smb_credential_id",
        "smb_share_path",
        "smb_file_path",
        "scp_credential_id",
        "scp_host",
        "scp_port",
        "scp_known_hosts",
        "scp_path",
        "task_id",
    ] {
        assert!(
            !handler.contains(forbidden),
            "handler response leaked {forbidden}"
        );
    }
    let response_shape = std::any::type_name::<AlertAssetItem>();
    assert!(response_shape.ends_with("AlertAssetItem"));
    let payload_source = include_str!("alert_payloads.rs");
    assert!(payload_source.contains("method_data_redacted: true"));
    for forbidden in ["to_address", "from_address", "subject", "message"] {
        assert!(!payload_source.contains(forbidden));
    }
}

#[test]
fn alert_create_maps_json_extractor_rejections_before_mutation() {
    let direct = include_str!("alert_writes.rs");
    let browser = include_str!("browser_proxy_metadata_patch.rs");
    assert!(direct.contains("Result<Json<AlertCreateRequest>, JsonRejection>"));
    assert!(direct.contains("request body must be application/json matching AlertCreateRequest"));
    assert!(browser.contains("Result<Json<AlertCreateRequest>, JsonRejection>"));
    assert!(browser.contains("parse_alert_create_payload(payload)?"));
}

#[test]
fn alert_smb_sensitive_fields_are_byte_backed_and_drop_scrubbed() {
    let validation = include_str!("alert_write_validation.rs");
    for field in [
        "smb_credential_id: SensitiveAlertField",
        "smb_share_path: SensitiveAlertField",
        "smb_file_path: SensitiveAlertField",
        "report_format_id: SensitiveAlertField",
    ] {
        assert!(
            validation.contains(field),
            "missing sensitive field {field}"
        );
    }
    assert!(validation.contains("impl Drop for SensitiveAlertField"));
    assert!(validation.contains("self.0.fill(0)"));
}

#[test]
fn alert_snmp_secrets_are_byte_backed_parameterized_unlogged_and_scrubbed() {
    let validation = include_str!("alert_write_validation.rs");
    for field in [
        "snmp_agent: SensitiveAlertField",
        "snmp_community: SensitiveAlertField",
        "snmp_message: SensitiveAlertField",
    ] {
        assert!(
            validation.contains(field),
            "missing sensitive SNMP field {field}"
        );
    }
    assert!(validation.contains("impl Drop for SensitiveAlertField"));
    assert!(validation.contains("self.0.fill(0)"));

    let manager = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
    assert!(manager.contains("|| method == ALERT_METHOD_SNMP"));
    assert!(manager.contains("sql_ps_sensitive"));
    assert!(manager.contains("VALUES ($1, $2, $3)"));

    let delivery = include_str!("../../../components/gvmd/src/manage_alerts.c");
    for forbidden in [
        "g_debug (\"SNMP to host: %s\"",
        "g_debug (\"snmp_agent: %s\"",
        "g_debug (\"snmp_message: %s\"",
        "g_debug (\"snmp_community: %s\"",
        "g_debug (\"   command: %s\"",
        "system failed with ret %i, %i, %s",
        "child failed, %s",
    ] {
        assert!(!delivery.contains(forbidden), "SNMP log leaks {forbidden}");
    }
    for required in [
        "alert_secure_gfree (clean_community)",
        "alert_secure_gfree (clean_agent)",
        "alert_secure_gfree (clean_message)",
        "alert_secure_gfree (command_args)",
        "alert_secure_free (agent)",
        "alert_secure_free (community)",
        "alert_secure_free (snmp_message)",
        "alert_secure_gfree (message)",
    ] {
        assert!(
            delivery.contains(required),
            "SNMP secret cleanup missing {required}"
        );
    }
}

#[test]
fn alert_scp_delivery_is_pinned_isolated_unlogged_and_scrubbed() {
    let validation = include_str!("alert_write_validation.rs");
    for field in [
        "scp_credential_id: SensitiveAlertField",
        "scp_host: SensitiveAlertField",
        "scp_known_hosts: SensitiveAlertField",
        "scp_path: SensitiveAlertField",
        "report_format_id: SensitiveAlertField",
    ] {
        assert!(
            validation.contains(field),
            "missing sensitive SCP field {field}"
        );
    }

    let manager = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
    assert!(manager.contains("|| method == ALERT_METHOD_SCP"));
    assert!(manager.contains("lock_alert_scp_credential"));
    assert!(manager.contains("FOR SHARE;"));
    assert!(manager.contains("create_alert_scp_with_report_refs"));

    let delivery = include_str!("../../../components/gvmd/src/manage_alerts.c");
    for forbidden in [
        "g_debug (\"scp to host",
        "g_debug (\"scp_",
        "clean_known_hosts =",
        "system failed with ret %i, %i, %s",
        "child failed, %s",
    ] {
        assert!(!delivery.contains(forbidden), "SCP log leaks {forbidden}");
    }
    for required in [
        "chmod (path, S_IRUSR | S_IWUSR)",
        "alert_write_data_file (report_dir, \"known_hosts\"",
        "clean_known_hosts_path = g_shell_quote (known_hosts_path)",
        "alert_secure_gfree (command_args)",
        "alert_secure_free (credential_id)",
        "alert_secure_free (private_key)",
        "alert_secure_free (password)",
        "alert_secure_free (username)",
        "alert_secure_free (host)",
        "alert_secure_free (port_str)",
        "alert_secure_free (known_hosts)",
        "alert_secure_gfree (alert_path)",
        "alert_secure_gfree_bytes (report_content, content_length)",
    ] {
        assert!(
            delivery.contains(required),
            "SCP secret cleanup missing {required}"
        );
    }

    let script = include_str!("../../../components/gvmd/src/alert_methods/SCP/alert");
    for required in [
        "-F /dev/null",
        "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=$KNOWN_HOSTS_FILE",
        "GlobalKnownHostsFile=/dev/null",
        "IdentityAgent=none",
        "IdentitiesOnly=yes",
    ] {
        assert!(
            script.contains(required),
            "SCP isolation missing {required}"
        );
    }
    for forbidden in ["~/.ssh", "ERROR_SHORT", "$KNOWN_HOSTS >"] {
        assert!(
            !script.contains(forbidden),
            "SCP script retains unsafe behavior {forbidden}"
        );
    }
}

#[test]
fn alert_smb_delivery_logs_do_not_include_destination_values() {
    let delivery = include_str!("../../../components/gvmd/src/manage_alerts.c");
    for forbidden in [
        "smb as %s",
        "smb_credential: %s",
        "smb_share_path: %s",
        "smb_file_path: %s",
        "g_debug (\"report: %s\"",
        "Could not find credential %s",
    ] {
        assert!(!delivery.contains(forbidden), "SMB log leaks {forbidden}");
    }
    assert!(delivery.contains("Sending report through SMB alert delivery"));
    assert!(delivery.contains("Preparing SMB alert delivery destination"));
    assert!(delivery.contains("alert_secure_gfree (password)"));
    assert!(delivery.contains("alert_secure_gfree_bytes (report_content, content_length)"));
}

#[test]
fn alert_email_create_sensitive_sql_is_parameterized_unlogged_and_scrubbed() {
    let manager = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
    let sql_api = include_str!("../../../components/gvmd/src/sql.c");
    let sql_backend = include_str!("../../../components/gvmd/src/sql_pg.c");
    assert!(manager.contains("sql_ps_sensitive"));
    assert!(manager.contains("VALUES ($1, $2, $3)"));
    assert!(sql_api.contains("sql_prepare_ps_internal (sensitive ? 0 : 1"));
    assert!(sql_backend.contains("sql_finalize_sensitive"));
    assert!(sql_backend.contains("*cursor++ = 0"));
}

#[test]
fn alert_delivery_reference_deletes_lock_before_usage_checks() {
    let credential_sql = include_str!("../../../components/gvmd/src/manage_sql.c");
    for source in [credential_sql] {
        let lock = source.find("FOR UPDATE;").expect("delete lock");
        let usage = source[lock..]
            .find("_in_use (")
            .expect("usage check after delete lock");
        assert!(usage > 0);
    }
}

fn patch_request(name: Option<&str>, comment: Option<&str>) -> AlertPatchRequest {
    AlertPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> AlertCloneRequest {
    AlertCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn alert_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_alert_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_alert_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn alert_clone_handler_requires_operator_owner_and_unique_name_before_mutation() {
    let source = include_str!("alert_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn clone_alert")
        .expect("clone alert handler must exist")
        .1
        .split_once("pub(crate) async fn delete_alert")
        .expect("delete alert handler follows clone handler")
        .0;

    let owner_check = "ensure_alert_owner_matches_operator(source.owner_id, owner_id)?;";
    let unique_check = "ensure_unique_alert_name(&tx, name, -1).await?;";
    assert!(handler.contains("let operator = require_alert_write_operator(operator)?;"));
    assert!(handler.contains("let request = validate_alert_clone_request(request)?;"));
    assert!(handler.contains("resolve_alert_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(handler.contains(unique_check));
    assert!(handler.contains("execute_alert_clone_transaction"));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_alert_clone_transaction").unwrap()
    );
    assert!(
        handler.find(unique_check).unwrap()
            < handler.find("execute_alert_clone_transaction").unwrap()
    );
}

#[test]
fn alert_delete_handler_requires_operator_owner_and_live_task_guard_before_mutation() {
    let source = include_str!("alert_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn delete_alert")
        .expect("delete alert handler must exist")
        .1
        .split_once("pub(crate) async fn patch_alert")
        .expect("patch alert handler follows delete handler")
        .0;

    let owner_check = "ensure_alert_owner_matches_operator(state.owner_id, operator_owner_id)?;";
    let task_guard = "ensure_alert_not_in_use_by_live_tasks(&tx, state.internal_id).await?;";
    assert!(handler.contains("let operator = require_alert_write_operator(operator)?;"));
    assert!(handler.contains("resolve_alert_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(handler.contains(task_guard));
    assert!(handler.contains("execute_alert_trash_transaction"));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_alert_trash_transaction").unwrap()
    );
    assert!(
        handler.find(task_guard).unwrap()
            < handler.find("execute_alert_trash_transaction").unwrap()
    );
}

#[test]
fn alert_patch_handler_requires_operator_and_owner_before_mutation() {
    let source = include_str!("alert_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_alert")
        .expect("patch alert handler must exist")
        .1;

    let owner_check =
        "ensure_alert_owner_matches_operator(alert_state.owner_id, operator_owner_id)?;";
    assert!(handler.contains("let operator = require_alert_write_operator(operator)?;"));
    assert!(handler.contains("resolve_alert_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler.find("execute_alert_patch_transaction").unwrap(),
        "alert patch must verify owner before metadata mutation"
    );
}

#[test]
fn alert_clone_request_trims_optional_metadata_fields() {
    let validated =
        validate_alert_clone_request(clone_request(Some("  copied alert  "), Some("  note  ")))
            .expect("valid alert clone");
    assert_eq!(validated.name.as_deref(), Some("copied alert"));
    assert_eq!(validated.comment.as_deref(), Some("note"));
}

#[test]
fn alert_clone_request_accepts_empty_body_for_inherited_clone_name() {
    let validated = validate_alert_clone_request(clone_request(None, None))
        .expect("empty clone request uses inherited defaults");
    assert_eq!(validated.name, None);
    assert_eq!(validated.comment, None);
}

#[test]
fn alert_clone_request_rejects_blank_name_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_alert_clone_request(clone_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_alert_clone_request(clone_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_alert_clone_request(clone_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Clone", "method_data": {"recipient": "operator@example.invalid"}});
    assert!(serde_json::from_value::<AlertCloneRequest>(request).is_err());
}

#[test]
fn alert_patch_request_trims_metadata_fields() {
    let validated =
        validate_alert_patch_request(patch_request(Some("  daily alert  "), Some("  comment  ")))
            .expect("valid alert patch");
    assert_eq!(validated.name.as_deref(), Some("daily alert"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn alert_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_alert_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_alert_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_alert_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn alert_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_alert_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_alert_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Alert", "method_data": {"recipient": "operator@example.invalid"}});
    assert!(serde_json::from_value::<AlertPatchRequest>(request).is_err());
}

#[test]
fn alert_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_alert_patch_request(AlertPatchRequest {
            name: Some("x".repeat(MAX_ALERT_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn alert_patch_sql_is_metadata_only() {
    let sql = alert_update_metadata_sql();
    assert!(sql.contains("UPDATE alerts"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("RETURNING id::integer, uuid::text"));
    for forbidden in [
        "active",
        "filter",
        "event",
        "condition",
        "method",
        "alert_method_data",
        "alert_event_data",
        "alert_condition_data",
        "task_alerts",
        "credential",
        "password",
        "secret",
    ] {
        assert!(
            !sql.contains(forbidden),
            "alert patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn alert_clone_sql_copies_metadata_child_rows_and_live_tag_links_only() {
    let metadata = alert_clone_metadata_sql();
    assert!(metadata.contains("INSERT INTO alerts"));
    assert!(metadata.contains("make_uuid()"));
    assert!(metadata.contains("coalesce($3, uniquify('alert', name, $2, ' Clone'))"));
    assert!(metadata.contains("coalesce($4, comment)"));
    assert!(metadata.contains("RETURNING id::integer, uuid::text"));
    assert!(!metadata.contains("alerts_trash"));

    for (sql, table) in [
        (alert_clone_condition_data_sql(), "alert_condition_data"),
        (alert_clone_event_data_sql(), "alert_event_data"),
        (alert_clone_method_data_sql(), "alert_method_data"),
    ] {
        assert!(sql.contains(&format!("INSERT INTO {table}")));
        assert!(sql.contains("SELECT $2, name, data"));
        assert!(sql.contains("WHERE alert = $1"));
        assert!(!sql.contains("_trash"));
    }

    let tags = alert_clone_tags_sql();
    assert!(tags.contains("INSERT INTO tag_resources"));
    assert!(tags.contains("resource_type = 'alert'"));
    assert!(tags.contains("resource = $1"));
    assert!(tags.contains("resource_location = 0"));
    assert!(!tags.contains("tag_resources_trash"));
}

#[test]
fn alert_delete_sql_moves_metadata_children_tasks_and_tags_to_trash_before_live_delete() {
    let task_guard = alert_live_task_count_sql();
    assert!(task_guard.contains("JOIN tasks t ON t.id = ta.task"));
    assert!(task_guard.contains("ta.alert_location = 0"));
    assert!(task_guard.contains("coalesce(t.hidden, 0) < 2"));

    let metadata = alert_trash_insert_sql();
    assert!(metadata.contains("INSERT INTO alerts_trash"));
    assert!(metadata.contains("FROM alerts"));
    assert!(metadata.contains("RETURNING id::integer, uuid::text"));

    for (sql, table) in [
        (
            alert_condition_data_trash_insert_sql(),
            "alert_condition_data_trash",
        ),
        (
            alert_event_data_trash_insert_sql(),
            "alert_event_data_trash",
        ),
        (
            alert_method_data_trash_insert_sql(),
            "alert_method_data_trash",
        ),
    ] {
        assert!(sql.contains(&format!("INSERT INTO {table}")));
        assert!(sql.contains("SELECT $1, name, data"));
        assert!(sql.contains("WHERE alert = $2"));
    }

    let task_relink = alert_task_relink_to_trash_sql();
    assert!(task_relink.contains("UPDATE task_alerts"));
    assert!(task_relink.contains("alert_location = 1"));

    let live_tags = alert_tag_locations_to_trash_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_location = 1"));
    assert!(live_tags.contains("resource_type = 'alert'"));

    let trashed_tags = alert_trash_tag_locations_to_trash_sql();
    assert!(trashed_tags.contains("UPDATE tag_resources_trash"));
    assert!(trashed_tags.contains("resource_location = 1"));

    assert_eq!(
        alert_delete_condition_data_sql(),
        "DELETE FROM alert_condition_data WHERE alert = $1;"
    );
    assert_eq!(
        alert_delete_event_data_sql(),
        "DELETE FROM alert_event_data WHERE alert = $1;"
    );
    assert_eq!(
        alert_delete_method_data_sql(),
        "DELETE FROM alert_method_data WHERE alert = $1;"
    );
    assert_eq!(
        alert_delete_metadata_sql(),
        "DELETE FROM alerts WHERE id = $1;"
    );
}

#[test]
fn alert_patch_state_and_uniqueness_are_live_metadata_only() {
    let state = alert_write_state_sql();
    assert!(state.contains("FROM alerts"));
    assert!(state.contains("owner::integer"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(!state.contains("alerts_trash"));

    let unique = alert_unique_name_sql();
    assert!(unique.contains("FROM alerts"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(!unique.contains("alerts_trash"));
}
