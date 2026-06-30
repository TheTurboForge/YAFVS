// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    schedule_payloads::ScheduleAssetDetail,
    schedule_write_db::*,
    schedule_write_sql::*,
    schedule_write_validation::{
        ScheduleCloneRequest, SchedulePatchRequest, ValidatedScheduleClone, ValidatedSchedulePatch,
        validate_schedule_clone_request, validate_schedule_patch_request,
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
    resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for delete"))?;
    let state = load_schedule_write_state(&tx, &schedule_id).await?;
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
    resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule trash tables for hard delete"))?;
    let trash = load_schedule_trash_state(&tx, &schedule_id).await?;
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
    resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE schedules, schedules_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "lock schedule tables for restore"))?;
    let trash = load_schedule_trash_state(&tx, &schedule_id).await?;
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

pub(crate) async fn execute_schedule_trash_transaction(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
) -> Result<ScheduleTrashWriteRecord, ApiError> {
    let record = query_schedule_trash_write_record(
        tx,
        schedule_trash_insert_sql(),
        &[&schedule_internal_id],
        "move schedule metadata to trash",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_task_relink_sql(),
        &[&record.internal_id, &schedule_internal_id],
        "relink tasks to trashed schedule",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_tag_locations_to_trash_sql(),
        &[&record.internal_id, &schedule_internal_id],
        "move live schedule tag links to trash",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &schedule_internal_id],
        "move trashed tag links to schedule trash id",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_delete_metadata_sql(),
        &[&schedule_internal_id],
        "delete live schedule after trash move",
    )
    .await?;
    Ok(record)
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
    resolve_schedule_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE schedules, schedules_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_schedule_write_db_error(error, "lock schedules for patch"))?;
    let state = load_schedule_write_state(&tx, &schedule_id).await?;
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

pub(crate) async fn execute_schedule_patch_transaction(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
    request: &ValidatedSchedulePatch,
) -> Result<ScheduleWriteRecord, ApiError> {
    query_schedule_write_record(
        tx,
        schedule_update_metadata_sql(),
        &[&schedule_internal_id, &request.name, &request.comment],
        "update schedule metadata",
    )
    .await
}

pub(crate) async fn execute_schedule_clone_transaction(
    tx: &Transaction<'_>,
    source_schedule_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScheduleClone,
) -> Result<ScheduleWriteRecord, ApiError> {
    let record = query_schedule_trash_write_record(
        tx,
        schedule_clone_metadata_sql(),
        &[
            &source_schedule_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone schedule metadata",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_clone_tags_sql(),
        &[
            &source_schedule_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone schedule tags",
    )
    .await?;
    Ok(ScheduleWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_schedule_restore_transaction(
    tx: &Transaction<'_>,
    schedule_trash_internal_id: i32,
) -> Result<ScheduleWriteRecord, ApiError> {
    let record = query_schedule_trash_write_record(
        tx,
        schedule_restore_metadata_sql(),
        &[&schedule_trash_internal_id],
        "restore schedule metadata",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_task_relink_to_live_sql(),
        &[&schedule_trash_internal_id, &record.internal_id],
        "relink trash tasks to restored schedule",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_tag_locations_to_live_sql(),
        &[&schedule_trash_internal_id, &record.internal_id],
        "move schedule tag links to live",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_locations_to_live_sql(),
        &[&schedule_trash_internal_id, &record.internal_id],
        "move trashed tag links to restored schedule",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_delete_trash_metadata_sql(),
        &[&schedule_trash_internal_id],
        "delete schedule trash metadata after restore",
    )
    .await?;
    Ok(ScheduleWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_schedule_hard_delete_transaction(
    tx: &Transaction<'_>,
    schedule_trash_internal_id: i32,
) -> Result<(), ApiError> {
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_delete_sql(),
        &[&schedule_trash_internal_id],
        "delete schedule trash tag links",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_trash_delete_sql(),
        &[&schedule_trash_internal_id],
        "delete trashed tag links to schedule trash id",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_delete_trash_metadata_sql(),
        &[&schedule_trash_internal_id],
        "delete schedule trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "schedule_writes_tests.rs"]
mod schedule_writes_tests;
