// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use uuid::Uuid;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    credential_generation::generate_credential_secrets,
    credential_payloads::CredentialAssetItem,
    credential_write_db::*,
    credential_write_transactions::{
        execute_credential_clone_transaction, execute_credential_hard_delete_transaction,
        execute_credential_patch_transaction, execute_credential_restore_transaction,
        execute_credential_trash_transaction,
    },
    credential_write_validation::{
        CredentialCreateRequest, CredentialPatchRequest, ValidatedCredentialCreate,
        validate_credential_create_request, validate_credential_patch_request,
    },
    credentials::load_credential_asset_detail,
    errors::{ApiError, mutation_committed_response_unavailable},
    gvmd_control::{
        ScrubbedControlFrame, gvmd_control_secret, gvmd_control_socket_path,
        map_control_socket_error, request_gvmd_control_response_bytes,
    },
};

pub(crate) async fn clone_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<(StatusCode, Json<CredentialAssetItem>), ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_credential_write_db_error(error, "begin clone credential transaction")
    })?;
    let owner_id = resolve_credential_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE users, credentials, credentials_data, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_credential_write_db_error(error, "lock credential tables for clone"))?;
    let source = load_credential_write_state(&tx, &credential_id).await?;
    ensure_credential_is_human_owned(source.owner_id)?;
    let record = execute_credential_clone_transaction(&tx, source.internal_id, owner_id).await?;
    tx.commit().await.map_err(|error| {
        map_credential_write_db_error(error, "commit clone credential transaction")
    })?;
    Ok((
        StatusCode::CREATED,
        Json(
            load_credential_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(
                        error,
                        "clone credential response reload",
                    )
                })?,
        ),
    ))
}

pub(crate) async fn create_credential(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<CredentialCreateRequest>,
) -> Result<(StatusCode, Json<CredentialAssetItem>), ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let mut request = validate_credential_create_request(request)?;
    generate_credential_secrets(&mut request).await?;
    let control_secret = gvmd_control_secret()?;
    let credential_id = request_credential_create(
        &gvmd_control_socket_path(),
        &control_secret,
        operator.user_uuid(),
        &request,
    )
    .await?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok((
        StatusCode::CREATED,
        Json(load_credential_asset_detail(&client, &credential_id).await?),
    ))
}

pub(crate) async fn hard_delete_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_credential_write_db_error(error, "begin hard-delete credential transaction")
    })?;
    resolve_credential_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE credentials_trash, credentials_trash_data, targets_trash_login_data, scanners_trash, alert_method_data_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_credential_write_db_error(error, "lock credential hard-delete tables"))?;
    let trash = load_credential_trash_state(&tx, &credential_id).await?;
    ensure_credential_is_human_owned(trash.owner_id)?;
    ensure_trash_credential_not_in_use(&tx, trash.internal_id, &trash.uuid).await?;
    execute_credential_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_credential_write_db_error(error, "commit hard-delete credential transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_credential_write_db_error(error, "begin delete credential transaction")
    })?;
    resolve_credential_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE credentials, credentials_trash, credentials_data, credentials_trash_data, targets_login_data, targets_trash_login_data, scanners, scanners_trash, alert_method_data, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_credential_write_db_error(error, "lock credential tables for delete"))?;
    let credential = load_credential_write_state(&tx, &credential_id).await?;
    ensure_credential_is_human_owned(credential.owner_id)?;
    ensure_live_credential_not_in_use(&tx, credential.internal_id, &credential.uuid).await?;
    execute_credential_trash_transaction(&tx, credential.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_credential_write_db_error(error, "commit delete credential transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_credential_write_db_error(error, "begin restore credential transaction")
    })?;
    resolve_credential_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE credentials, credentials_trash, credentials_data, credentials_trash_data, targets_trash_login_data, scanners_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_credential_write_db_error(error, "lock credential restore tables"))?;
    let trash = load_credential_trash_state(&tx, &credential_id).await?;
    let owner_id = ensure_credential_is_human_owned(trash.owner_id)?;
    ensure_credential_uuid_not_live(&tx, &trash.uuid).await?;
    ensure_unique_credential_name(&tx, &trash.name, -1, owner_id).await?;
    let record = execute_credential_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_credential_write_db_error(error, "commit restore credential transaction")
    })?;

    Ok(Json(
        load_credential_asset_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "restore credential response reload")
            })?,
    ))
}

pub(crate) async fn request_credential_create(
    socket_path: &str,
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedCredentialCreate,
) -> Result<String, ApiError> {
    let command = credential_create_command(control_secret, operator_uuid, request);
    let response =
        request_gvmd_control_response_bytes(socket_path, control_secret, command.as_bytes()).await;
    let response = response.map_err(map_control_socket_error)?;
    parse_credential_create_response(&response)
}

pub(crate) fn credential_create_command(
    control_secret: &str,
    operator_uuid: &str,
    request: &ValidatedCredentialCreate,
) -> ScrubbedControlFrame {
    let mut command = Vec::with_capacity(512 + request.private_key.as_bytes().len() * 2);
    command.extend_from_slice(b"credential-create ");
    command.extend_from_slice(control_secret.as_bytes());
    command.push(b' ');
    command.extend_from_slice(operator_uuid.as_bytes());
    command.push(b' ');
    command.extend_from_slice(request.credential_type.control_token().as_bytes());
    for field in [
        request.name.as_bytes(),
        request.comment.as_bytes(),
        request.login.as_bytes(),
        request.secret.as_bytes(),
        request.private_key.as_bytes(),
    ] {
        command.push(b' ');
        append_base64(&mut command, field);
    }
    command.push(b'\n');
    ScrubbedControlFrame::new(command)
}

fn append_base64(command: &mut Vec<u8>, value: &[u8]) {
    let start = command.len();
    let encoded_capacity = value.len().div_ceil(3) * 4;
    command.resize(start + encoded_capacity, 0);
    let written = STANDARD
        .encode_slice(value, &mut command[start..])
        .expect("preallocated base64 output must be sufficient");
    command.truncate(start + written);
}

pub(crate) fn parse_credential_create_response(response: &[u8]) -> Result<String, ApiError> {
    match response {
        b"1 exists" => Err(ApiError::Conflict(
            "A credential with this name already exists.".to_string(),
        )),
        b"2 invalid_login" => Err(ApiError::BadRequest(
            "The credential login is invalid.".to_string(),
        )),
        b"3 invalid_key" => Err(ApiError::BadRequest(
            "The private key or passphrase is invalid.".to_string(),
        )),
        b"5 login_required" => Err(ApiError::BadRequest(
            "The credential login is required.".to_string(),
        )),
        b"6 password_required" => Err(ApiError::BadRequest(
            "The credential password is required.".to_string(),
        )),
        b"7 key_required" => Err(ApiError::BadRequest(
            "The credential private key is required.".to_string(),
        )),
        b"99 forbidden" => Err(ApiError::Forbidden),
        b"-2 malformed" => Err(ApiError::BadRequest(
            "The credential control request was rejected.".to_string(),
        )),
        b"-1 internal" => Err(ApiError::ControlFailure),
        _ => parse_created_credential_id(response),
    }
}

fn parse_created_credential_id(response: &[u8]) -> Result<String, ApiError> {
    let Some(uuid) = response.strip_prefix(b"0 created ") else {
        return Err(ApiError::ControlFailure);
    };
    let uuid = std::str::from_utf8(uuid).map_err(|_| ApiError::ControlFailure)?;
    let uuid = Uuid::parse_str(uuid).map_err(|_| ApiError::ControlFailure)?;
    Ok(uuid.to_string())
}

pub(crate) async fn patch_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<CredentialPatchRequest>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let request = validate_credential_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_credential_write_db_error(error, "begin patch credential transaction")
    })?;
    resolve_credential_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE credentials IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_credential_write_db_error(error, "lock credentials for patch"))?;
    let credential_state = load_credential_write_state(&tx, &credential_id).await?;
    let credential_owner_id = ensure_credential_is_human_owned(credential_state.owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_credential_name(&tx, name, credential_state.internal_id, credential_owner_id)
            .await?;
    }
    let record =
        execute_credential_patch_transaction(&tx, credential_state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_credential_write_db_error(error, "commit patch credential transaction")
    })?;

    Ok(Json(
        load_credential_asset_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "patch credential response reload")
            })?,
    ))
}
