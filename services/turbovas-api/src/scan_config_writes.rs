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
    scan_config_payloads::ScanConfigAssetDetail,
    scan_config_write_db::*,
    scan_config_write_sql::*,
    scan_config_write_validation::{
        ScanConfigPatchRequest, ValidatedScanConfigPatch, validate_scan_config_patch_request,
    },
    scan_configs::load_scan_config_asset_detail,
};

pub(crate) async fn delete_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin delete scan-config transaction")
    })?;
    resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, configs_trash, config_preferences, config_preferences_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for delete"))?;
    let config_state = load_scan_config_write_state(&tx, &scan_config_id).await?;
    ensure_scan_config_not_in_use_by_live_tasks(&tx, config_state.internal_id).await?;
    execute_scan_config_trash_transaction(&tx, config_state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit delete scan-config transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin restore scan-config transaction")
    })?;
    resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE configs, configs_trash, config_preferences, config_preferences_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "lock scan-config tables for restore"))?;
    let trash = load_scan_config_trash_state(&tx, &scan_config_id).await?;
    ensure_scan_config_trash_scanner_is_live(&trash)?;
    ensure_unique_live_scan_config_name(&tx, &trash.name).await?;
    ensure_scan_config_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_scan_config_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit restore scan-config transaction")
    })?;

    Ok(Json(
        load_scan_config_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn patch_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScanConfigPatchRequest>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let request = validate_scan_config_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin patch scan-config transaction")
    })?;
    resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE configs, configs_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "lock scan-config tables for patch")
        })?;
    let config_state = load_scan_config_write_state(&tx, &scan_config_id).await?;
    if config_state.predefined {
        return Err(ApiError::Conflict(
            "predefined scan configs cannot be patched".to_string(),
        ));
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scan_config_name(&tx, name, config_state.internal_id).await?;
    }
    let record =
        execute_scan_config_patch_transaction(&tx, config_state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit patch scan-config transaction")
    })?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn execute_scan_config_patch_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    request: &ValidatedScanConfigPatch,
) -> Result<ScanConfigWriteRecord, ApiError> {
    query_scan_config_write_record(
        tx,
        scan_config_update_metadata_sql(),
        &[&scan_config_internal_id, &request.name, &request.comment],
        "update scan-config metadata",
    )
    .await
}

pub(crate) async fn execute_scan_config_trash_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_trash_insert_sql(),
        &[&scan_config_internal_id],
        "move scan-config metadata to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_preferences_trash_insert_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move scan-config preferences to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_task_relink_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "relink tasks to trashed scan config",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move live scan-config tag links to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move trashed tag links to scan-config trash id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_preferences_sql(),
        &[&scan_config_internal_id],
        "delete live scan-config preferences after trash move",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_metadata_sql(),
        &[&scan_config_internal_id],
        "delete live scan config after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_restore_transaction(
    tx: &Transaction<'_>,
    trash_scan_config_internal_id: i32,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_restore_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "restore scan-config metadata from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_preferences_restore_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore scan-config preferences from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_task_relink_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "relink trash tasks to restored scan config",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_tag_locations_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore live scan-config tag links from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_locations_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore trashed tag links to scan-config live id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_preferences_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash preferences after restore",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash metadata after restore",
    )
    .await?;
    Ok(record)
}
