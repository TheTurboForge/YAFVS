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
    tag_payloads::TagAssetItem,
    tag_write_db::*,
    tag_write_validation::{
        TagCloneRequest, TagCreateRequest, TagPatchRequest, TagResourceUpdateRequest,
        validate_tag_clone_request, validate_tag_create_request, validate_tag_patch_request,
        validate_tag_resource_update_request,
    },
};

pub(crate) async fn create_tag(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin create tag transaction"))?;
    let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    let record = execute_tag_create_transaction(&tx, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit create tag transaction"))?;

    let tag = load_tag_write_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn restore_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin restore tag transaction"))?;
    let operator_owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags, tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag tables for restore"))?;
    let trash = load_tag_trash_state(&tx, &tag_id).await?;
    ensure_tag_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;
    ensure_tag_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_tag_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit restore tag transaction"))?;

    Ok(Json(load_tag_write_detail(&client, &record.uuid).await?))
}

pub(crate) async fn hard_delete_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin hard-delete tag transaction"))?;
    let operator_owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag trash tables for hard delete"))?;
    let trash = load_tag_trash_state(&tx, &tag_id).await?;
    ensure_tag_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;
    execute_tag_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit hard-delete tag transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn patch_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagPatchRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin patch tag transaction"))?;
    let operator_owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    let record = execute_tag_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit patch tag transaction"))?;

    Ok(Json(load_tag_write_detail(&client, &record.uuid).await?))
}

pub(crate) async fn clone_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin clone tag transaction"))?;
    let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_tag_write_db_error(error, "lock tag tables for clone"))?;
    let source = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_owner_matches_operator(source.owner_id, owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&source.resource_type)?;
    let record = execute_tag_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit clone tag transaction"))?;

    let tag = load_tag_write_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn delete_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin delete tag transaction"))?;
    let operator_owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags, tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag tables for delete"))?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    execute_tag_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit delete tag transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn update_tag_resources(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagResourceUpdateRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_resource_update_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin tag resource transaction"))?;
    let operator_owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    execute_tag_resource_update_transaction(&tx, &state, operator_owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit tag resource transaction"))?;

    Ok(Json(load_tag_write_detail(&client, &state.uuid).await?))
}

fn tag_write_location_headers(tag_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/tags/{tag_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

#[cfg(test)]
#[path = "tag_writes_tests.rs"]
mod tag_writes_tests;
