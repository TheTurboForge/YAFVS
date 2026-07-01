// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    target_handlers::load_target_detail,
    target_write_db::*,
    target_write_sql::target_update_metadata_sql,
    target_write_validation::{
        TargetPatchRequest, ValidatedTargetPatch, validate_target_patch_request,
    },
    task_target_payloads::TargetItem,
};

pub(crate) async fn patch_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetPatchRequest>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin patch target transaction"))?;
    let operator_owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE targets, port_lists IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_target_write_db_error(error, "lock targets for patch"))?;
    let target_state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(target_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, target_state.internal_id, target_state.owner_id)
            .await?;
    }
    let port_list_internal_id = if let Some(port_list_id) = request.port_list_id.as_ref() {
        Some(
            load_assignable_target_port_list(&tx, port_list_id, operator_owner_id)
                .await?
                .internal_id,
        )
    } else {
        None
    };
    if request.changes_task_in_use_guarded_scan_settings() {
        ensure_target_not_in_use_for_scan_settings(&tx, target_state.internal_id).await?;
    }
    let record = execute_target_patch_transaction(
        &tx,
        target_state.internal_id,
        &request,
        &port_list_internal_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit patch target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
}

pub(crate) async fn execute_target_patch_transaction(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    request: &ValidatedTargetPatch,
    port_list_internal_id: &Option<i32>,
) -> Result<TargetWriteRecord, ApiError> {
    query_target_write_record(
        tx,
        target_update_metadata_sql(),
        &[
            &target_internal_id,
            &request.name,
            &request.comment,
            &request.alive_test,
            &request.allow_simultaneous_ips,
            &request.reverse_lookup_only,
            &request.reverse_lookup_unify,
            port_list_internal_id,
        ],
        "update target metadata",
    )
    .await
}
