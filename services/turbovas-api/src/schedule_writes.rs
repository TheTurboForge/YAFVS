// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    schedule_payloads::ScheduleAssetDetail,
    schedule_write_db::*,
    schedule_write_transactions::*,
    schedule_write_validation::{
        ScheduleCloneRequest, SchedulePatchRequest, validate_schedule_clone_request,
        validate_schedule_patch_request,
    },
    schedules::load_schedule_asset_detail,
};

pub(crate) async fn clone_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScheduleCloneRequest>,
) -> Result<(StatusCode, Json<ScheduleAssetDetail>), ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let request = validate_schedule_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "begin clone schedule transaction"))?;
    let owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for clone"))?;
    let source = load_schedule_write_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(source.owner_id, owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_schedule_name(&tx, name, -1).await?;
    }
    let record =
        execute_schedule_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "commit clone schedule transaction"))?;
    Ok((
        StatusCode::CREATED,
        Json(load_schedule_asset_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn delete_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "begin delete schedule transaction"))?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for delete"))?;
    let state = load_schedule_write_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(state.owner_id, operator_owner_id)?;
    ensure_schedule_not_in_use_by_live_tasks(&tx, state.internal_id).await?;
    execute_schedule_trash_transaction(&tx, state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_schedule_write_db_error(error, "commit delete schedule transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_schedule_write_db_error(error, "begin hard-delete schedule transaction")
    })?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule trash tables for hard delete"))?;
    let trash = load_schedule_trash_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_schedule_not_in_use_by_trash_tasks(&tx, trash.internal_id).await?;
    execute_schedule_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_schedule_write_db_error(error, "commit hard-delete schedule transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_schedule_write_db_error(error, "begin restore schedule transaction")
    })?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for restore"))?;
    let trash = load_schedule_trash_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(trash.owner_id, operator_owner_id)?;
    ensure_unique_live_schedule_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_schedule_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_schedule_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_schedule_write_db_error(error, "commit restore schedule transaction")
    })?;

    Ok(Json(
        load_schedule_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn patch_schedule(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<SchedulePatchRequest>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    let operator = require_schedule_write_operator(operator)?;
    let request = validate_schedule_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "begin patch schedule transaction"))?;
    let operator_owner_id = resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE schedules, schedules_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_schedule_write_db_error(error, "lock schedules for patch"))?;
    let state = load_schedule_write_state(&tx, &schedule_id).await?;
    ensure_schedule_owner_matches_operator(state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_schedule_name(&tx, name, state.internal_id).await?;
    }
    let record = execute_schedule_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_schedule_write_db_error(error, "commit patch schedule transaction"))?;
    Ok(Json(
        load_schedule_asset_detail(&client, &record.uuid).await?,
    ))
}

#[cfg(test)]
#[path = "schedule_writes_tests.rs"]
mod schedule_writes_tests;
