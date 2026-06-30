// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    app_state::AppState, auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid,
    schedule_payloads::ScheduleAssetDetail, schedule_write_sql::*,
    schedules::load_schedule_asset_detail,
};

const MAX_SCHEDULE_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchedulePatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedSchedulePatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleWriteRecord {
    uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleTrashWriteRecord {
    internal_id: i32,
    uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduleWriteState {
    internal_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduleTrashWriteState {
    internal_id: i32,
    uuid: String,
    name: String,
    owner_id: i32,
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleWriteOperation {
    Create,
    Patch,
    Delete,
    Restore,
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

async fn ensure_schedule_not_in_use_by_live_tasks(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_live_task_count_sql(), &[&schedule_internal_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check schedule task usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule is still referenced by a live task".to_string(),
        ))
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleWriteStep {
    ResolveOperatorOwner,
    VerifyExistingScheduleMutable,
    ResolveTimezone,
    ValidateTimezone,
    ParseICalendar,
    DeriveScheduleFields,
    VerifyUniqueLiveName,
    VerifyTaskDeleteSafety,
    InsertSchedule,
    UpdateScheduleMetadata,
    RefreshTaskNextTimes,
    MoveScheduleToTrash,
    RestoreScheduleFromTrash,
    RelocateTasks,
    RelocatePermissionsAndTags,
}

async fn query_schedule_trash_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScheduleTrashWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_schedule_write_db_error(error, action))?
        .map(|row| ScheduleTrashWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

async fn load_schedule_trash_state(
    tx: &Transaction<'_>,
    schedule_id: &str,
) -> Result<ScheduleTrashWriteState, ApiError> {
    let schedule_id = parse_uuid(schedule_id)?.to_string();
    tx.query_opt(schedule_trash_state_sql(), &[&schedule_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "load schedule trash state"))?
        .map(|row| ScheduleTrashWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

async fn execute_schedule_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_schedule_write_db_error(error, action))
}

async fn ensure_unique_live_schedule_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_unique_live_owner_name_sql(), &[&name, &owner_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check live schedule name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule with the same name already exists".to_string(),
        ))
    }
}

async fn ensure_schedule_uuid_not_live(
    tx: &Transaction<'_>,
    schedule_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_live_uuid_conflict_sql(), &[&schedule_uuid])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check live schedule uuid conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule with the same id already exists".to_string(),
        ))
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScheduleWriteTransactionPlan {
    pub(crate) operation: ScheduleWriteOperation,
    pub(crate) steps: Vec<ScheduleWriteStep>,
}

pub(crate) fn validate_schedule_patch_request(
    request: SchedulePatchRequest,
) -> Result<ValidatedSchedulePatch, ApiError> {
    let validated = ValidatedSchedulePatch {
        name: normalize_optional_required_schedule_text(request.name, "name")?,
        comment: normalize_optional_schedule_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "schedule patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_optional_required_schedule_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_schedule_text(value, field_name))
        .transpose()
}

fn normalize_required_schedule_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_schedule_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_schedule_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_schedule_text_value(value, field_name))
        .transpose()
}

fn normalize_schedule_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCHEDULE_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCHEDULE_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
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

fn require_schedule_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("schedule write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

async fn resolve_schedule_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        schedule_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| map_schedule_write_db_error(error, "resolve schedule write operator"))?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!("direct API schedule write operator does not resolve to a database user");
        ApiError::Forbidden
    })
}

async fn load_schedule_write_state(
    tx: &Transaction<'_>,
    schedule_id: &str,
) -> Result<ScheduleWriteState, ApiError> {
    let schedule_id = parse_uuid(schedule_id)?.to_string();
    tx.query_opt(schedule_write_state_sql(), &[&schedule_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "load schedule write state"))?
        .map(|row| ScheduleWriteState {
            internal_id: row.get(0),
        })
        .ok_or(ApiError::NotFound)
}

async fn ensure_unique_schedule_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(schedule_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_schedule_write_db_error(error, "check schedule name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "schedule with the same name already exists".to_string(),
        ))
    }
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

async fn query_schedule_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScheduleWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_schedule_write_db_error(error, action))?
        .map(schedule_write_record_from_row)
        .ok_or(ApiError::NotFound)
}

#[cfg(test)]
pub(crate) fn schedule_restore_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Restore,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::RestoreScheduleFromTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

fn schedule_write_record_from_row(row: Row) -> ScheduleWriteRecord {
    ScheduleWriteRecord { uuid: row.get(0) }
}

fn map_schedule_write_db_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::warn!(%error, action, "schedule write database operation failed");
    ApiError::Database
}

#[cfg(test)]
pub(crate) fn schedule_create_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Create,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::InsertSchedule,
        ],
    }
}

#[cfg(test)]
pub(crate) fn schedule_patch_transaction_plan(
    changes_calendar: bool,
) -> ScheduleWriteTransactionPlan {
    let mut steps = vec![
        ScheduleWriteStep::ResolveOperatorOwner,
        ScheduleWriteStep::VerifyExistingScheduleMutable,
    ];
    if changes_calendar {
        steps.extend([
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
        ]);
    }
    steps.extend([
        ScheduleWriteStep::VerifyUniqueLiveName,
        ScheduleWriteStep::UpdateScheduleMetadata,
    ]);
    if changes_calendar {
        steps.push(ScheduleWriteStep::RefreshTaskNextTimes);
    }
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Patch,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn schedule_delete_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Delete,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTaskDeleteSafety,
            ScheduleWriteStep::MoveScheduleToTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

#[cfg(test)]
#[path = "schedule_writes_tests.rs"]
mod schedule_writes_tests;
