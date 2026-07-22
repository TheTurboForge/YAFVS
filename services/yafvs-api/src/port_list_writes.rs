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
    errors::{ApiError, mutation_committed_response_unavailable},
    port_list_payloads::PortListAssetDetail,
    port_list_write_db::*,
    port_list_write_transactions::*,
    port_list_write_validation::{
        PortListCloneRequest, PortListCreateRangeRequest, PortListCreateRequest,
        PortListImportRequest, PortListPatchRequest, validate_port_list_clone_request,
        validate_port_list_create_range_request, validate_port_list_create_request,
        validate_port_list_import_request, validate_port_list_patch_request,
    },
    port_lists::load_port_list_asset_detail,
};

pub(crate) async fn create_port_list(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListCreateRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut request = validate_port_list_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin create port list transaction")
    })?;
    let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for create"))?;
    if request.deduplicate_name {
        request.name = unique_port_list_name_with_suffix(&tx, &request.name).await?;
    } else {
        ensure_unique_port_list_name(&tx, &request.name, -1).await?;
    }
    let record = execute_port_list_create_transaction(&tx, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit create port list transaction")
    })?;
    Ok((
        StatusCode::CREATED,
        Json(
            load_port_list_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(
                        error,
                        "create port list response reload",
                    )
                })?,
        ),
    ))
}

pub(crate) async fn import_port_list(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListImportRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut request = validate_port_list_import_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin import port list transaction")
    })?;
    let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for import"))?;
    if let Some(imported_id) = request.imported_id.as_ref() {
        ensure_port_list_uuid_not_live_or_trash(&tx, imported_id).await?;
    }
    if request.deduplicate_name {
        request.name = unique_port_list_name_with_suffix(&tx, &request.name).await?;
    } else {
        ensure_unique_port_list_name(&tx, &request.name, -1).await?;
    }
    let record = execute_port_list_create_transaction(&tx, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit import port list transaction")
    })?;
    Ok((
        StatusCode::CREATED,
        Json(
            load_port_list_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(
                        error,
                        "import port list response reload",
                    )
                })?,
        ),
    ))
}

pub(crate) async fn clone_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListCloneRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let request = validate_port_list_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin clone port list transaction")
    })?;
    let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for clone"))?;
    let source = load_port_list_write_state(&tx, &port_list_id).await?;
    ensure_port_list_clone_source_allowed(&source)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_port_list_name(&tx, name, -1).await?;
    }
    let record =
        execute_port_list_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit clone port list transaction")
    })?;
    Ok((
        StatusCode::CREATED,
        Json(
            load_port_list_asset_detail(&client, &record.uuid)
                .await
                .map_err(|error| {
                    mutation_committed_response_unavailable(
                        error,
                        "clone port list response reload",
                    )
                })?,
        ),
    ))
}

pub(crate) async fn patch_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListPatchRequest>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let request = validate_port_list_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin patch port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, targets, targets_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for patch"))?;
    let state = load_port_list_write_state(&tx, &port_list_id).await?;
    ensure_port_list_is_human_owned(state.owner_id)?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port lists cannot be patched".to_string(),
        ));
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_port_list_name(&tx, name, state.internal_id).await?;
    }
    if request.port_ranges.is_some() {
        ensure_port_list_not_in_use_by_live_targets(&tx, state.internal_id).await?;
        ensure_port_list_not_in_use_by_live_location_trash_targets(&tx, state.internal_id).await?;
    }
    let record = execute_port_list_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit patch port list transaction")
    })?;
    Ok(Json(
        load_port_list_asset_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "patch port list response reload")
            })?,
    ))
}

pub(crate) async fn create_port_list_range(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListCreateRangeRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let range = validate_port_list_create_range_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin create port list range transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_ranges, targets, targets_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list range create tables"))?;
    let state = load_port_list_write_state(&tx, &port_list_id).await?;
    ensure_port_list_is_human_owned(state.owner_id)?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port list ranges cannot be created".to_string(),
        ));
    }
    ensure_port_list_not_in_use_by_live_targets(&tx, state.internal_id).await?;
    ensure_port_list_not_in_use_by_live_location_trash_targets(&tx, state.internal_id).await?;
    ensure_port_list_range_can_be_created(&tx, state.internal_id, &range).await?;
    execute_port_list_range_create_transaction(&tx, state.internal_id, &range).await?;
    let detail = load_port_list_asset_detail(&tx, &port_list_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit create port list range transaction")
    })?;
    Ok((StatusCode::CREATED, Json(detail)))
}

pub(crate) async fn delete_port_list_range(
    State(state): State<AppState>,
    Path((port_list_id, port_range_id)): Path<(String, String)>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin delete port list range transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_ranges, targets, targets_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list range delete tables"))?;
    let state = load_port_list_range_write_state(&tx, &port_list_id, &port_range_id).await?;
    ensure_port_list_is_human_owned(state.owner_id)?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port list ranges cannot be deleted".to_string(),
        ));
    }
    ensure_port_list_not_in_use_by_live_targets(&tx, state.port_list_internal_id).await?;
    ensure_port_list_not_in_use_by_live_location_trash_targets(&tx, state.port_list_internal_id)
        .await?;
    execute_port_list_range_delete_transaction(&tx, state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit delete port list range transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin delete port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, port_ranges_trash, targets, targets_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for delete"))?;
    let state = load_port_list_write_state(&tx, &port_list_id).await?;
    ensure_port_list_is_human_owned(state.owner_id)?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port lists cannot be deleted".to_string(),
        ));
    }
    ensure_port_list_not_in_use_by_live_targets(&tx, state.internal_id).await?;
    execute_port_list_trash_transaction(&tx, state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit delete port list transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin hard-delete port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists_trash, port_ranges_trash, targets_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list trash tables for hard delete"))?;
    let trash = load_port_list_trash_state(&tx, &port_list_id).await?;
    ensure_port_list_is_human_owned(trash.owner_id)?;
    ensure_port_list_not_in_use_by_trash_targets(&tx, trash.internal_id).await?;
    execute_port_list_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit hard-delete port list transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin restore port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, port_ranges_trash, targets_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for restore"))?;
    let trash = load_port_list_trash_state(&tx, &port_list_id).await?;
    let port_list_owner_id = ensure_port_list_is_human_owned(trash.owner_id)?;
    ensure_unique_live_port_list_name_for_owner(&tx, &trash.name, port_list_owner_id).await?;
    ensure_port_list_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_port_list_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit restore port list transaction")
    })?;

    Ok(Json(
        load_port_list_asset_detail(&client, &record.uuid)
            .await
            .map_err(|error| {
                mutation_committed_response_unavailable(error, "restore port list response reload")
            })?,
    ))
}

#[cfg(test)]
#[path = "port_list_writes_tests.rs"]
mod port_list_writes_tests;
