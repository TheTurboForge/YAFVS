// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    target_handlers::load_target_detail,
    target_write_db::*,
    target_write_transactions::*,
    target_write_validation::{
        TargetCloneRequest, TargetCreateRequest, TargetPatchRequest, validate_target_clone_request,
        validate_target_create_request, validate_target_patch_request,
    },
    task_target_payloads::TargetItem,
};

pub(crate) async fn create_target(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin create target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, credentials, targets, targets_login_data IN SHARE ROW EXCLUSIVE MODE;",
    )
        .await
        .map_err(|error| map_target_write_db_error(error, "lock targets for create"))?;
    ensure_unique_target_name(&tx, &request.name, -1, owner_id).await?;
    let port_list = load_assignable_target_port_list(&tx, &request.port_list_id, owner_id).await?;
    let credential_links = if request.credentials.has_changes() {
        resolve_target_create_credential_links(&tx, owner_id, &request.credentials).await?
    } else {
        ResolvedTargetCredentialsPatch::default()
    };
    let record = execute_target_create_transaction(
        &tx,
        owner_id,
        port_list.internal_id,
        &request,
        &credential_links,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit create target transaction"))?;

    Ok((
        StatusCode::CREATED,
        target_write_location_headers(&record.uuid)?,
        Json(load_target_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn clone_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin clone target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, credentials, targets, targets_login_data, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for clone"))?;
    let source = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(source.owner_id, owner_id)?;
    ensure_target_source_port_list_assignable(&tx, source.internal_id, owner_id).await?;
    ensure_target_source_credentials_assignable(&tx, source.internal_id, owner_id).await?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, -1, owner_id).await?;
    }
    let record =
        execute_target_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit clone target transaction"))?;

    Ok((
        StatusCode::CREATED,
        target_write_location_headers(&record.uuid)?,
        Json(load_target_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn delete_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin delete target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_trash, targets_login_data, targets_trash_login_data, tasks, scope_targets, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for delete"))?;
    let state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(state.owner_id, owner_id)?;
    ensure_target_not_in_use_for_delete(&tx, state.internal_id).await?;
    ensure_target_not_in_scope(&tx, state.internal_id).await?;
    execute_target_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit delete target transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_target_write_db_error(error, "begin hard-delete target transaction")
    })?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets_trash, targets_trash_login_data, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target trash tables for hard delete"))?;
    let trash = load_target_trash_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(trash.owner_id, owner_id)?;
    ensure_trash_target_not_in_use(&tx, trash.internal_id).await?;
    execute_target_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_target_write_db_error(error, "commit hard-delete target transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin restore target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_trash, targets_login_data, targets_trash_login_data, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for restore"))?;
    let trash = load_target_trash_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(trash.owner_id, owner_id)?;
    ensure_unique_live_target_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_target_uuid_not_live(&tx, &trash.uuid).await?;
    ensure_trash_target_references_live_resources(&tx, trash.internal_id).await?;
    let record = execute_target_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit restore target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
}

pub(crate) async fn patch_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetPatchRequest>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin patch target transaction"))?;
    let operator_owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, credentials, targets, targets_login_data IN SHARE ROW EXCLUSIVE MODE;",
    )
        .await
        .map_err(|error| map_target_write_db_error(error, "lock targets for patch"))?;
    let target_state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(target_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, target_state.internal_id, target_state.owner_id)
            .await?;
    }
    let port_list_internal_id = if let Some(port_list_id) = request.port_list_id.as_ref() {
        Some(
            load_assignable_target_port_list(&tx, port_list_id, operator_owner_id)
                .await?
                .internal_id,
        )
    } else {
        None
    };
    if request.changes_task_in_use_guarded_scan_inputs() {
        ensure_target_not_in_use_for_scan_inputs(&tx, target_state.internal_id).await?;
    }
    let credential_links = if request.changes_credential_links() {
        ensure_target_not_in_use_for_scan_inputs(&tx, target_state.internal_id).await?;
        resolve_target_credential_link_changes(
            &tx,
            target_state.internal_id,
            operator_owner_id,
            &request.credentials,
        )
        .await?
    } else {
        ResolvedTargetCredentialsPatch::default()
    };
    let record = execute_target_patch_transaction(
        &tx,
        target_state.internal_id,
        &request,
        &port_list_internal_id,
        &credential_links,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit patch target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
}

fn target_write_location_headers(target_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/targets/{target_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}
