// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    task_handlers::load_task_detail,
    task_target_payloads::TaskItem,
    task_write_db::*,
    task_write_transactions::execute_task_patch_transaction,
    task_write_validation::{TaskPatchRequest, validate_task_patch_request},
};

pub(crate) async fn patch_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TaskPatchRequest>,
) -> Result<Json<TaskItem>, ApiError> {
    let operator = require_task_write_operator(operator)?;
    let request = validate_task_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_task_write_db_error(error, "begin patch task transaction"))?;
    let operator_owner_id = resolve_task_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE tasks IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_task_write_db_error(error, "lock tasks for patch"))?;
    let task_state = load_task_write_state(&tx, &task_id).await?;
    ensure_task_owner_matches_operator(task_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_task_name(&tx, name, task_state.internal_id, task_state.owner_id).await?;
    }
    let record = execute_task_patch_transaction(&tx, task_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_task_write_db_error(error, "commit patch task transaction"))?;

    Ok(Json(load_task_detail(&client, &record.uuid).await?))
}
