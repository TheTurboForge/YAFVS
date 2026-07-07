// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    credential_write_db::ensure_credential_owner_matches_operator,
    credential_write_sql::*,
    credential_write_validation::{
        CredentialPatchRequest, MAX_CREDENTIAL_TEXT_BYTES, validate_credential_patch_request,
    },
    errors::ApiError,
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> CredentialPatchRequest {
    CredentialPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn credential_patch_rejects_operator_owner_mismatch() {
    assert!(ensure_credential_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_credential_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn credential_patch_handler_requires_operator_and_owner_before_mutation() {
    let source = include_str!("credential_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_credential")
        .expect("patch credential handler must exist")
        .1;

    let owner_check =
        "ensure_credential_owner_matches_operator(credential_state.owner_id, operator_owner_id)?;";
    assert!(handler.contains("let operator = require_credential_write_operator(operator)?;"));
    assert!(handler.contains("resolve_credential_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler
                .find("execute_credential_patch_transaction")
                .unwrap(),
        "credential patch must verify owner before metadata mutation"
    );
}

#[test]
fn credential_patch_request_trims_metadata_fields() {
    let validated = validate_credential_patch_request(patch_request(
        Some("  ssh credential  "),
        Some("  comment  "),
    ))
    .expect("valid credential patch");
    assert_eq!(validated.name.as_deref(), Some("ssh credential"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn credential_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_credential_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn credential_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_credential_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn credential_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_credential_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn credential_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_credential_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_credential_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Credential", "password": "secret"});
    assert!(serde_json::from_value::<CredentialPatchRequest>(request).is_err());
}

#[test]
fn credential_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_credential_patch_request(CredentialPatchRequest {
            name: Some("x".repeat(MAX_CREDENTIAL_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn credential_patch_sql_is_metadata_only() {
    let sql = credential_update_metadata_sql();
    assert!(sql.contains("UPDATE credentials"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(sql.contains("RETURNING uuid::text"));
    for forbidden in [
        "credentials_data",
        "credentials_trash_data",
        "targets_login_data",
        "scanners",
        "allow_insecure",
        "type =",
        "credential_store",
        "vault_id",
        "host_identifier",
        "password",
        "private_key",
        "community",
        "secret",
        "value",
    ] {
        assert!(
            !sql.contains(forbidden),
            "credential patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn credential_patch_state_and_uniqueness_are_live_metadata_only() {
    let state = credential_write_state_sql();
    assert!(state.contains("FROM credentials"));
    assert!(state.contains("WHERE uuid = $1"));
    assert!(state.contains("owner::integer"));
    assert!(!state.contains("credentials_data"));
    assert!(!state.contains("credentials_trash"));

    let unique = credential_unique_name_sql();
    assert!(unique.contains("FROM credentials"));
    assert!(unique.contains("name = $1"));
    assert!(unique.contains("id != $2"));
    assert!(unique.contains("owner = $3"));
    assert!(!unique.contains("credentials_data"));
    assert!(!unique.contains("credentials_trash"));
}
