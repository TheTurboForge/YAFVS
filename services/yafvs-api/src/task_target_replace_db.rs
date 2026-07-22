// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError, path_ids::parse_uuid, task_status::TaskStatus, task_target_replace_sql::*,
    task_write_db::map_task_write_db_error,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskTargetReplaceTaskState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: Option<i32>,
    pub(crate) target_internal_id: Option<i32>,
    pub(crate) run_status: TaskStatus,
    pub(crate) target_location: i32,
    pub(crate) hidden: i32,
    pub(crate) usage_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskTargetReplaceSourceTargetState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
}

pub(crate) async fn load_task_target_replace_task_state(
    tx: &Transaction<'_>,
    task_id: &str,
) -> Result<TaskTargetReplaceTaskState, ApiError> {
    let task_id = parse_uuid(task_id)?.to_string();
    let row = tx
        .query_opt(task_target_replace_task_state_sql(), &[&task_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "load task target replacement state"))?
        .ok_or(ApiError::NotFound)?;
    Ok(TaskTargetReplaceTaskState {
        internal_id: row.get(0),
        owner_id: row.get(1),
        target_internal_id: row.get(2),
        run_status: TaskStatus::from_database(row.get(3))?,
        target_location: row.get(4),
        hidden: row.get(5),
        usage_type: row.get(6),
    })
}

pub(crate) async fn load_task_target_replace_source_target_state(
    tx: &Transaction<'_>,
    source_target_internal_id: i32,
) -> Result<TaskTargetReplaceSourceTargetState, ApiError> {
    tx.query_opt(
        task_target_replace_source_target_state_sql(),
        &[&source_target_internal_id],
    )
    .await
    .map_err(|error| map_task_write_db_error(error, "load task source target"))?
    .map(|row| TaskTargetReplaceSourceTargetState {
        internal_id: row.get(0),
        uuid: row.get(1),
        owner_id: row.get(2),
    })
    .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_task_target_replace_state(
    task: &TaskTargetReplaceTaskState,
) -> Result<i32, ApiError> {
    if task.hidden != 0 || task.usage_type != "scan" || task.target_location != 0 {
        return Err(ApiError::Conflict(
            "task target replacement is only available for a live scan task".to_string(),
        ));
    }
    if task.run_status != TaskStatus::New {
        return Err(ApiError::Conflict(
            "task target replacement is only available while task status is New".to_string(),
        ));
    }
    task.target_internal_id.ok_or_else(|| {
        ApiError::Conflict("task target replacement requires a live source target".to_string())
    })
}

pub(crate) fn ensure_task_target_replace_ownership(
    task_owner_id: Option<i32>,
    source_target_owner_id: Option<i32>,
) -> Result<(), ApiError> {
    if task_owner_id.is_none() {
        tracing::warn!("task target replacement rejects an ownerless task");
        return Err(ApiError::Forbidden);
    }
    if source_target_owner_id.is_none() {
        tracing::warn!("task target replacement rejects an ownerless source target");
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub(crate) async fn ensure_task_target_replace_has_no_reports(
    tx: &Transaction<'_>,
    task_internal_id: i32,
) -> Result<(), ApiError> {
    let report_count: i64 = tx
        .query_one(task_target_replace_report_count_sql(), &[&task_internal_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "check task reports"))?
        .get(0);
    if report_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "task target replacement is unavailable after reports exist".to_string(),
        ))
    }
}

pub(crate) async fn task_target_replace_source_is_unreferenced(
    tx: &Transaction<'_>,
    source_target_internal_id: i32,
) -> Result<bool, ApiError> {
    let live_task_references: i64 = tx
        .query_one(
            task_target_replace_live_task_reference_count_sql(),
            &[&source_target_internal_id],
        )
        .await
        .map_err(|error| map_task_write_db_error(error, "check source target task references"))?
        .get(0);
    let scope_references: i64 = tx
        .query_one(
            task_target_replace_scope_reference_count_sql(),
            &[&source_target_internal_id],
        )
        .await
        .map_err(|error| map_task_write_db_error(error, "check source target scope references"))?
        .get(0);
    Ok(live_task_references == 0 && scope_references == 0)
}
