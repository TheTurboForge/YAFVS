// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    credential_write_db::ensure_credential_is_human_owned,
    credential_write_sql::*,
    credential_write_validation::{
        CredentialCreateRequest, CredentialCreateType, CredentialPatchRequest,
        MAX_CREDENTIAL_PRIVATE_KEY_BYTES, MAX_CREDENTIAL_TEXT_BYTES,
        validate_credential_create_request, validate_credential_patch_request,
    },
    errors::ApiError,
};

fn patch_request(name: Option<&str>, comment: Option<&str>) -> CredentialPatchRequest {
    CredentialPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn create_request(credential_type: CredentialCreateType) -> CredentialCreateRequest {
    CredentialCreateRequest {
        name: "  operator credential  ".to_string(),
        comment: Some("  imported  ".to_string()),
        login: "  operator  ".to_string(),
        credential_type,
        password: (credential_type == CredentialCreateType::Up)
            .then(|| serde_json::from_value(serde_json::json!("password")).unwrap()),
        passphrase: None,
        private_key: (credential_type == CredentialCreateType::Usk).then(|| {
            serde_json::from_value(serde_json::json!(
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
            ))
            .unwrap()
        }),
    }
}

#[test]
fn credential_create_validates_up_and_usk_without_echoing_secrets() {
    let up = validate_credential_create_request(create_request(CredentialCreateType::Up))
        .expect("valid up credential");
    assert_eq!(up.name, "operator credential");
    assert_eq!(up.comment, "imported");
    assert_eq!(up.login, "operator");
    assert_eq!(up.secret.as_bytes(), b"password");
    assert!(up.private_key.as_bytes().is_empty());

    let mut usk_request = create_request(CredentialCreateType::Usk);
    usk_request.passphrase = Some(serde_json::from_value(serde_json::json!("")).unwrap());
    let usk = validate_credential_create_request(usk_request).expect("valid usk credential");
    assert_eq!(usk.credential_type, CredentialCreateType::Usk);
    assert!(usk.secret.as_bytes().is_empty());
    assert!(
        std::str::from_utf8(usk.private_key.as_bytes())
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );

    let command = crate::credential_writes::credential_create_command(
        "0123456789abcdef0123456789abcdef",
        "123e4567-e89b-12d3-a456-426614174000",
        &up,
    );
    let command = String::from_utf8(command.as_bytes().to_vec()).unwrap();
    assert!(command.starts_with("credential-create "));
    assert!(command.contains(" up "));
    assert!(!command.contains("password"));
    assert!(!command.contains("operator credential"));
}

#[test]
fn credential_create_command_uses_drop_scrubbing_across_the_await_boundary() {
    let source = include_str!("credential_writes.rs");
    let request = source
        .split_once("pub(crate) async fn request_credential_create")
        .expect("credential create request helper must exist")
        .1
        .split_once("pub(crate) fn credential_create_command")
        .expect("credential create command helper must follow request helper")
        .0;
    assert!(request.contains("command.as_bytes()"));
    assert!(!request.contains("command.fill(0)"));
    assert!(source.contains(") -> ScrubbedControlFrame"));
    assert!(source.contains("ScrubbedControlFrame::new(command)"));
}

#[test]
fn credential_create_rejects_cross_type_fields_unknown_fields_and_bad_bounds() {
    let mut up = create_request(CredentialCreateType::Up);
    up.private_key = Some(serde_json::from_value(serde_json::json!("key")).unwrap());
    assert!(matches!(
        validate_credential_create_request(up),
        Err(ApiError::BadRequest(_))
    ));

    let mut usk = create_request(CredentialCreateType::Usk);
    usk.password = Some(serde_json::from_value(serde_json::json!("wrong field")).unwrap());
    assert!(matches!(
        validate_credential_create_request(usk),
        Err(ApiError::BadRequest(_))
    ));

    let mut oversized = create_request(CredentialCreateType::Usk);
    oversized.private_key = Some(
        serde_json::from_value(serde_json::json!(
            "x".repeat(MAX_CREDENTIAL_PRIVATE_KEY_BYTES + 1)
        ))
        .unwrap(),
    );
    assert!(matches!(
        validate_credential_create_request(oversized),
        Err(ApiError::BadRequest(_))
    ));

    let mut oversized_aggregate = create_request(CredentialCreateType::Usk);
    oversized_aggregate.name = "n".repeat(MAX_CREDENTIAL_TEXT_BYTES);
    oversized_aggregate.comment = Some("c".repeat(MAX_CREDENTIAL_TEXT_BYTES));
    oversized_aggregate.login = "l".repeat(MAX_CREDENTIAL_TEXT_BYTES);
    oversized_aggregate.passphrase = Some(
        serde_json::from_value(serde_json::json!("p".repeat(MAX_CREDENTIAL_TEXT_BYTES))).unwrap(),
    );
    oversized_aggregate.private_key = Some(
        serde_json::from_value(serde_json::json!(
            "k".repeat(MAX_CREDENTIAL_PRIVATE_KEY_BYTES)
        ))
        .unwrap(),
    );
    assert!(matches!(
        validate_credential_create_request(oversized_aggregate),
        Err(ApiError::BadRequest(_))
    ));

    assert!(
        serde_json::from_value::<CredentialCreateRequest>(serde_json::json!({
            "name": "credential",
            "login": "operator",
            "type": "up",
            "password": "secret",
            "unexpected": true
        }))
        .is_err()
    );
}

#[test]
fn credential_create_maps_only_bounded_control_responses() {
    use crate::credential_writes::parse_credential_create_response;

    assert_eq!(
        parse_credential_create_response(b"0 created 123e4567-e89b-12d3-a456-426614174003")
            .unwrap(),
        "123e4567-e89b-12d3-a456-426614174003"
    );
    assert!(matches!(
        parse_credential_create_response(b"1 exists"),
        Err(ApiError::Conflict(_))
    ));
    assert!(matches!(
        parse_credential_create_response(b"3 invalid_key"),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        parse_credential_create_response(b"99 forbidden"),
        Err(ApiError::Forbidden)
    ));
    assert!(matches!(
        parse_credential_create_response(b"0 created not-a-uuid"),
        Err(ApiError::ControlFailure)
    ));
}

#[test]
fn credential_patch_accepts_any_human_owner_and_rejects_ownerless_credentials() {
    assert_eq!(ensure_credential_is_human_owned(Some(7)).unwrap(), 7);
    assert_eq!(ensure_credential_is_human_owned(Some(8)).unwrap(), 8);
    assert!(matches!(
        ensure_credential_is_human_owned(None),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn credential_patch_handler_requires_operator_and_preserves_owner_before_mutation() {
    let source = include_str!("credential_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_credential")
        .expect("patch credential handler must exist")
        .1;

    let owner_check =
        "let credential_owner_id = ensure_credential_is_human_owned(credential_state.owner_id)?;";
    assert!(handler.contains("let operator = require_credential_write_operator(operator)?;"));
    assert!(handler.contains("resolve_credential_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains(owner_check));
    assert!(
        handler.find(owner_check).unwrap()
            < handler
                .find("execute_credential_patch_transaction")
                .unwrap(),
        "credential patch must verify human ownership before metadata mutation"
    );
    assert!(handler.contains("credential_owner_id)"));
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
