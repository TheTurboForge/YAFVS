// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    host_write_db::{ensure_host_owner_matches_operator, require_host_write_operator},
    host_write_sql::{host_create_ip_identifier_sql, host_create_sql, host_update_comment_sql},
    host_write_transactions::{execute_host_create_transaction, execute_host_patch_transaction},
    host_write_validation::{
        HostCreateRequest, HostPatchRequest, validate_host_create_request,
        validate_host_patch_request,
    },
};

#[test]
fn host_create_request_accepts_ip_and_printable_comment_only() {
    let request = validate_host_create_request(HostCreateRequest {
        name: " 192.0.2.44 ".to_string(),
        comment: Some(" dev host ".to_string()),
    })
    .expect("valid host create");
    assert_eq!(request.name, "192.0.2.44");
    assert_eq!(request.comment, "dev host");

    assert!(matches!(
        validate_host_create_request(HostCreateRequest {
            name: "web".to_string(),
            comment: None
        }),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_host_create_request(HostCreateRequest {
            name: "2001:db8::1".to_string(),
            comment: Some("bad\ncomment".to_string())
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn host_patch_request_normalizes_printable_comment() {
    let request = validate_host_patch_request(HostPatchRequest {
        comment: " note ".to_string(),
    })
    .expect("valid host patch");
    assert_eq!(request.comment, "note");
    assert!(matches!(
        validate_host_patch_request(HostPatchRequest {
            comment: "bad\ncomment".to_string()
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn host_write_requires_operator_and_owner_match() {
    let operator = DirectApiOperator::new("12345678-1234-1234-1234-123456789abc", None)
        .expect("valid operator");
    assert_eq!(
        require_host_write_operator(Some(Extension(operator.clone()))).expect("operator"),
        operator
    );
    assert!(matches!(
        require_host_write_operator(None),
        Err(ApiError::Forbidden)
    ));
    assert!(ensure_host_owner_matches_operator(Some(1), 1).is_ok());
    assert!(matches!(
        ensure_host_owner_matches_operator(Some(1), 2),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        ensure_host_owner_matches_operator(None, 1),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn host_create_sql_matches_inherited_manual_host_shape() {
    let create = host_create_sql();
    assert!(create.contains("INSERT INTO hosts"));
    assert!(create.contains("make_uuid()"));
    assert!(create.contains("owner, name, comment"));
    assert!(create.contains("RETURNING id::integer, uuid::text"));

    let identifier = host_create_ip_identifier_sql();
    assert!(identifier.contains("INSERT INTO host_identifiers"));
    assert!(identifier.contains("'ip'"));
    assert!(identifier.contains("'User'"));
    assert!(identifier.contains("source_id"));
    assert!(!identifier.contains("hostname"));
}

#[test]
fn host_patch_sql_updates_comment_only() {
    let sql = host_update_comment_sql();
    assert!(sql.contains("UPDATE hosts"));
    assert!(sql.contains("comment = $2"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(!sql.contains("name ="));
    assert!(!sql.contains("host_identifiers"));
}

#[test]
fn host_handlers_preserve_ordered_owner_checks_and_transactions() {
    let source = include_str!("host_writes.rs");
    let create_body = source
        .split_once("pub(crate) async fn create_host")
        .expect("create handler")
        .1
        .split_once("pub(crate) async fn patch_host")
        .expect("patch follows create")
        .0;
    assert!(
        create_body.find("validate_host_create_request").unwrap()
            < create_body.find("execute_host_create_transaction").unwrap()
    );
    assert!(create_body.contains("operator.user_uuid()"));

    let patch_body = source
        .split_once("pub(crate) async fn patch_host")
        .expect("patch handler")
        .1;
    assert!(
        patch_body.find("load_host_write_state").unwrap()
            < patch_body
                .find("ensure_host_owner_matches_operator")
                .unwrap()
    );
    assert!(
        patch_body
            .find("ensure_host_owner_matches_operator")
            .unwrap()
            < patch_body.find("execute_host_patch_transaction").unwrap()
    );
}

#[test]
fn host_transactions_keep_create_and_patch_side_effects_narrow() {
    let source = include_str!("host_write_transactions.rs");
    assert!(source.contains("host_create_sql()"));
    assert!(source.contains("host_create_ip_identifier_sql()"));
    assert!(source.contains("host_update_comment_sql()"));
    assert!(!source.contains("host_oss"));
    assert!(!source.contains("host_details"));
    assert!(!source.contains("host_max_severities"));
    let _ = execute_host_create_transaction;
    let _ = execute_host_patch_transaction;
}
