// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use serde::Serialize;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    target_write_db::{
        ensure_target_source_credentials_assignable, ensure_target_source_port_list_assignable,
    },
    task_target_replace_db::{
        ensure_task_target_replace_has_no_reports, ensure_task_target_replace_ownership,
        ensure_task_target_replace_state, load_task_target_replace_source_target_state,
        load_task_target_replace_task_state,
    },
    task_target_replace_transactions::{
        OldTargetDisposition, execute_task_target_replace_transaction,
    },
    task_target_replace_validation::{
        TaskTargetReplaceRequest, validate_task_target_replace_request,
    },
    task_write_db::{
        map_task_write_db_error, require_task_write_operator, resolve_task_write_operator_owner,
    },
};

#[derive(Debug, Serialize)]
pub(crate) struct TaskTargetReplaceResponse {
    task_id: String,
    old_target_id: String,
    new_target_id: String,
    status: TaskTargetReplaceStatus,
    old_target_disposition: OldTargetDisposition,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum TaskTargetReplaceStatus {
    Replaced,
}

pub(crate) async fn replace_task_target(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TaskTargetReplaceRequest>,
) -> Result<Json<TaskTargetReplaceResponse>, ApiError> {
    let operator = require_task_write_operator(operator)?;
    let request = validate_task_target_replace_request(request)?;
    let task_id = parse_uuid(&task_id)?.to_string();
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_task_write_db_error(error, "begin task target replacement transaction")
    })?;
    let operator_owner_id = resolve_task_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, credentials, targets, targets_login_data, targets_trash, targets_trash_login_data, tasks, reports, scope_targets, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_task_write_db_error(error, "lock task target replacement tables"))?;

    let task = load_task_target_replace_task_state(&tx, &task_id).await?;
    let source_target_internal_id = ensure_task_target_replace_state(&task)?;
    let source_target =
        load_task_target_replace_source_target_state(&tx, source_target_internal_id).await?;
    ensure_task_target_replace_ownership(task.owner_id, source_target.owner_id)?;
    ensure_target_source_port_list_assignable(&tx, source_target.internal_id).await?;
    ensure_target_source_credentials_assignable(&tx, source_target.internal_id).await?;
    ensure_task_target_replace_has_no_reports(&tx, task.internal_id).await?;

    let (new_target, disposition) = execute_task_target_replace_transaction(
        &tx,
        task.internal_id,
        source_target.internal_id,
        operator_owner_id,
        &request,
    )
    .await?;
    tx.commit().await.map_err(|error| {
        map_task_write_db_error(error, "commit task target replacement transaction")
    })?;

    Ok(Json(TaskTargetReplaceResponse {
        task_id,
        old_target_id: source_target.uuid,
        new_target_id: new_target.uuid,
        status: TaskTargetReplaceStatus::Replaced,
        old_target_disposition: disposition,
    }))
}
