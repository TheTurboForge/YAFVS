// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::Serialize;
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    task_control_sql::*,
    task_write_db::{
        ensure_task_owner_matches_operator, map_task_write_db_error, require_task_write_operator,
        resolve_task_write_operator_owner,
    },
};

#[derive(Debug, Serialize)]
pub(crate) struct TaskStartResult {
    task_id: String,
    report_id: String,
    status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskStartState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
    pub(crate) run_status: i32,
    pub(crate) target_id: Option<i32>,
    pub(crate) target_has_hosts: bool,
    pub(crate) config_id: Option<i32>,
    pub(crate) scanner_id: Option<i32>,
    pub(crate) scanner_type: Option<i32>,
}

pub(crate) async fn start_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<(StatusCode, Json<TaskStartResult>), ApiError> {
    let operator = require_task_write_operator(operator)?;
    let task_id = parse_uuid(&task_id)?.to_string();
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_task_write_db_error(error, "begin task start transaction"))?;
    let operator_owner_id = resolve_task_write_operator_owner(&tx, &operator).await?;
    let task = load_task_start_state(&tx, &task_id).await?;
    ensure_task_owner_matches_operator(task.owner_id, operator_owner_id)?;
    ensure_task_is_startable(&task)?;
    ensure_task_is_not_already_queued(&tx, task.internal_id).await?;
    let (report_internal_id, report_id) = insert_task_start_report(&tx, &task).await?;
    insert_task_start_scan_queue(&tx, report_internal_id).await?;
    mark_task_start_requested(&tx, task.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_task_write_db_error(error, "commit task start transaction"))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(TaskStartResult {
            task_id,
            report_id,
            status: "requested",
        }),
    ))
}

async fn load_task_start_state(
    tx: &Transaction<'_>,
    task_id: &str,
) -> Result<TaskStartState, ApiError> {
    tx.query_opt(task_start_state_sql(), &[&task_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "load task start state"))?
        .map(|row| TaskStartState {
            internal_id: row.get(0),
            owner_id: row.get(1),
            run_status: row.get(2),
            target_id: row.get(3),
            target_has_hosts: row.get(4),
            config_id: row.get(5),
            scanner_id: row.get(6),
            scanner_type: row.get(7),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_task_is_startable(task: &TaskStartState) -> Result<(), ApiError> {
    if task.target_id.is_none() {
        return Err(ApiError::BadRequest(
            "task must have a target before it can start".to_string(),
        ));
    }
    if !task.target_has_hosts {
        return Err(ApiError::BadRequest(
            "task target must include at least one host before the task can start".to_string(),
        ));
    }
    if task.config_id.is_none() {
        return Err(ApiError::BadRequest(
            "task must have an available scan config before it can start".to_string(),
        ));
    }
    if task.scanner_id.is_none() || task.scanner_type.is_none() {
        return Err(ApiError::BadRequest(
            "task must have an available scanner before it can start".to_string(),
        ));
    }
    if !matches!(task.scanner_type, Some(2 | 5 | 6 | 8)) {
        return Err(ApiError::BadRequest(
            "task scanner type cannot run scan tasks".to_string(),
        ));
    }

    match task.run_status {
        1 | 2 | 12 | 13 => Ok(()),
        0 | 14 | 16 | 17 => Err(ApiError::Conflict(
            "task start is unavailable while deletion is pending".to_string(),
        )),
        3 | 4 | 10 | 11 | 18 => Err(ApiError::Conflict(
            "task start is unavailable while the task is active or queued".to_string(),
        )),
        19 => Err(ApiError::Conflict(
            "task start is unavailable while report processing is active".to_string(),
        )),
        _ => Err(ApiError::Conflict(
            "task start is unavailable for the current task status".to_string(),
        )),
    }
}

async fn ensure_task_is_not_already_queued(
    tx: &Transaction<'_>,
    task_internal_id: i32,
) -> Result<(), ApiError> {
    let already_queued: bool = tx
        .query_one(task_start_scan_queue_exists_sql(), &[&task_internal_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "check task scan queue"))?
        .get(0);
    if already_queued {
        Err(ApiError::Conflict(
            "task already has a scan queue entry".to_string(),
        ))
    } else {
        Ok(())
    }
}

async fn insert_task_start_report(
    tx: &Transaction<'_>,
    task: &TaskStartState,
) -> Result<(i32, String), ApiError> {
    let row = tx
        .query_one(
            task_start_insert_report_sql(),
            &[&task.owner_id, &task.internal_id],
        )
        .await
        .map_err(|error| map_task_write_db_error(error, "create requested task report"))?;
    Ok((row.get(0), row.get(1)))
}

async fn insert_task_start_scan_queue(
    tx: &Transaction<'_>,
    report_internal_id: i32,
) -> Result<(), ApiError> {
    tx.execute(task_start_insert_scan_queue_sql(), &[&report_internal_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "insert task scan queue entry"))?;
    Ok(())
}

async fn mark_task_start_requested(
    tx: &Transaction<'_>,
    task_internal_id: i32,
) -> Result<(), ApiError> {
    tx.execute(task_start_mark_requested_sql(), &[&task_internal_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "mark task start requested"))?;
    Ok(())
}
