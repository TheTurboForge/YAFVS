// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    override_payloads::OverrideAssetItem,
    override_write_db::{
        ensure_override_is_human_owned, ensure_override_live_uuid_available,
        ensure_override_nvt_exists, ensure_override_task_result_match, load_override_result_scope,
        load_override_trash_state, load_override_write_state, map_override_write_db_error,
        require_override_write_operator, resolve_override_result_scope,
        resolve_override_task_scope, resolve_override_write_operator_owner,
    },
    override_write_transactions::{
        execute_override_clone_transaction, execute_override_create_transaction,
        execute_override_hard_delete_transaction, execute_override_patch_transaction,
        execute_override_restore_transaction, execute_override_trash_transaction,
    },
    override_write_validation::{
        OverrideCloneRequest, OverrideCreateRequest, OverridePatchRequest, PatchField,
        validate_override_create_request, validate_override_patch_request,
    },
    overrides::load_override_asset_detail,
};

pub(crate) async fn create_override(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<OverrideCreateRequest>,
) -> Result<(StatusCode, Json<OverrideAssetItem>), ApiError> {
    let operator = require_override_write_operator(operator)?;
    let request = validate_override_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_override_write_db_error(error, "begin create override transaction"))?;
    let operator_owner_id = resolve_override_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE overrides, overrides_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_override_write_db_error(error, "lock override tables for create"))?;
    ensure_override_nvt_exists(&tx, &request.nvt_id).await?;
    let task_id = match request.task_id.as_deref() {
        Some(task_uuid) => resolve_override_task_scope(&tx, task_uuid).await?,
        None => 0,
    };
    let result = match request.result_id.as_deref() {
        Some(result_uuid) => Some(resolve_override_result_scope(&tx, result_uuid).await?),
        None => None,
    };
    ensure_override_task_result_match(task_id, result.as_ref())?;
    let result_id = result.as_ref().map_or(0, |result| result.internal_id);
    let record =
        execute_override_create_transaction(&tx, operator_owner_id, &request, task_id, result_id)
            .await?;
    tx.commit().await.map_err(|error| {
        map_override_write_db_error(error, "commit create override transaction")
    })?;
    let item = load_override_after_commit(&client, &record.uuid, "create").await?;
    Ok((StatusCode::CREATED, Json(item)))
}

pub(crate) async fn restore_override(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    let operator = require_override_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_override_write_db_error(error, "begin restore override transaction")
    })?;
    resolve_override_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE overrides, overrides_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_override_write_db_error(error, "lock override tables for restore"))?;
    let trash = load_override_trash_state(&tx, &override_id).await?;
    ensure_override_is_human_owned(trash.write_state.owner_id)?;
    ensure_override_live_uuid_available(&tx, &trash.uuid).await?;
    let record = execute_override_restore_transaction(&tx, &trash.write_state).await?;
    tx.commit().await.map_err(|error| {
        map_override_write_db_error(error, "commit restore override transaction")
    })?;
    let item = load_override_after_commit(&client, &record.uuid, "restore").await?;
    Ok(Json(item))
}

pub(crate) async fn hard_delete_override(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_override_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_override_write_db_error(error, "begin hard-delete override transaction")
    })?;
    resolve_override_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE overrides_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| {
        map_override_write_db_error(error, "lock override tables for hard delete")
    })?;
    let trash = load_override_trash_state(&tx, &override_id).await?;
    ensure_override_is_human_owned(trash.write_state.owner_id)?;
    execute_override_hard_delete_transaction(&tx, trash.write_state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_override_write_db_error(error, "commit hard-delete override transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn clone_override(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(_request): Json<OverrideCloneRequest>,
) -> Result<(StatusCode, Json<OverrideAssetItem>), ApiError> {
    let operator = require_override_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_override_write_db_error(error, "begin clone override transaction"))?;
    let operator_owner_id = resolve_override_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE overrides, overrides_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_override_write_db_error(error, "lock override tables for clone"))?;
    let source = load_override_write_state(&tx, &override_id).await?;
    ensure_override_is_human_owned(source.owner_id)?;
    let record = execute_override_clone_transaction(&tx, &source, operator_owner_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_override_write_db_error(error, "commit clone override transaction"))?;
    let item = load_override_after_commit(&client, &record.uuid, "clone").await?;
    Ok((StatusCode::CREATED, Json(item)))
}

pub(crate) async fn patch_override(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<OverridePatchRequest>,
) -> Result<Json<OverrideAssetItem>, ApiError> {
    let operator = require_override_write_operator(operator)?;
    let request = validate_override_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_override_write_db_error(error, "begin patch override transaction"))?;
    resolve_override_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE overrides, overrides_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_override_write_db_error(error, "lock override tables for patch"))?;
    let current = load_override_write_state(&tx, &override_id).await?;
    ensure_override_is_human_owned(current.owner_id)?;
    if let Some(nvt_id) = request.nvt_id.as_deref() {
        ensure_override_nvt_exists(&tx, nvt_id).await?;
    }
    let final_task_id = match &request.task_id {
        PatchField::Missing => current.task_id,
        PatchField::Null => 0,
        PatchField::Value(task_uuid) => resolve_override_task_scope(&tx, task_uuid).await?,
    };
    let result = match &request.result_id {
        PatchField::Missing if current.result_id == 0 => None,
        PatchField::Missing => Some(load_override_result_scope(&tx, current.result_id).await?),
        PatchField::Null => None,
        PatchField::Value(result_uuid) => {
            Some(resolve_override_result_scope(&tx, result_uuid).await?)
        }
    };
    ensure_override_task_result_match(final_task_id, result.as_ref())?;
    let final_result_id = result.as_ref().map_or(0, |result| result.internal_id);
    let record =
        execute_override_patch_transaction(&tx, &current, &request, final_task_id, final_result_id)
            .await?;
    tx.commit()
        .await
        .map_err(|error| map_override_write_db_error(error, "commit patch override transaction"))?;
    let item = load_override_after_commit(&client, &record.uuid, "patch").await?;
    Ok(Json(item))
}

pub(crate) async fn delete_override(
    State(state): State<AppState>,
    Path(override_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_override_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_override_write_db_error(error, "begin delete override transaction"))?;
    resolve_override_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE overrides, overrides_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_override_write_db_error(error, "lock override tables for delete"))?;
    let override_state = load_override_write_state(&tx, &override_id).await?;
    ensure_override_is_human_owned(override_state.owner_id)?;
    execute_override_trash_transaction(&tx, &override_state).await?;
    tx.commit().await.map_err(|error| {
        map_override_write_db_error(error, "commit delete override transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn load_override_after_commit(
    client: &tokio_postgres::Client,
    override_id: &str,
    action: &'static str,
) -> Result<OverrideAssetItem, ApiError> {
    load_override_asset_detail(client, override_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, action, override_id, "override mutation committed but response reload failed");
            ApiError::MutationCommittedResponseUnavailable
        })
}

#[cfg(test)]
#[path = "override_writes_tests.rs"]
mod override_writes_tests;
