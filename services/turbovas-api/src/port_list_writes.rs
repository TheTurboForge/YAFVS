// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    port_list_payloads::PortListAssetDetail,
    port_list_write_sql::*,
    port_list_write_validation::{
        PortListCloneRequest, PortListCreateRequest, PortListPatchRequest, ValidatedPortListClone,
        ValidatedPortListCreate, ValidatedPortListPatch, validate_port_list_clone_request,
        validate_port_list_create_request, validate_port_list_patch_request,
    },
    port_lists::load_port_list_asset_detail,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListWriteRecord {
    internal_id: i32,
    uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListTrashWriteRecord {
    internal_id: i32,
    uuid: String,
}

pub(crate) async fn create_port_list(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListCreateRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let request = validate_port_list_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin create port list transaction")
    })?;
    let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for create"))?;
    ensure_unique_port_list_name(&tx, &request.name, -1).await?;
    let record = execute_port_list_create_transaction(&tx, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit create port list transaction")
    })?;
    Ok((
        StatusCode::CREATED,
        Json(load_port_list_asset_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn execute_port_list_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedPortListCreate,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_write_record(
        tx,
        port_list_create_metadata_sql(),
        &[&owner_id, &request.name, &request.comment],
        "insert port list metadata",
    )
    .await?;
    for range in &request.port_ranges {
        execute_port_list_write_sql(
            tx,
            port_list_create_range_sql(),
            &[
                &record.internal_id,
                &range.protocol_id,
                &range.start,
                &range.end,
                &range.comment,
            ],
            "insert port list range",
        )
        .await?;
    }
    Ok(record)
}

pub(crate) async fn clone_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListCloneRequest>,
) -> Result<(StatusCode, Json<PortListAssetDetail>), ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let request = validate_port_list_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin clone port list transaction")
    })?;
    let owner_id = resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for clone"))?;
    let source = load_port_list_write_state(&tx, &port_list_id).await?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_port_list_name(&tx, name, -1).await?;
    }
    let record =
        execute_port_list_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit clone port list transaction")
    })?;
    Ok((
        StatusCode::CREATED,
        Json(load_port_list_asset_detail(&client, &record.uuid).await?),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortListTrashWriteState {
    internal_id: i32,
    uuid: String,
    name: String,
    owner_id: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortListWriteState {
    internal_id: i32,
    predefined: bool,
}

pub(crate) async fn patch_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<PortListPatchRequest>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let request = validate_port_list_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin patch port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, targets, targets_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for patch"))?;
    let state = load_port_list_write_state(&tx, &port_list_id).await?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port lists cannot be patched".to_string(),
        ));
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_port_list_name(&tx, name, state.internal_id).await?;
    }
    if request.port_ranges.is_some() {
        ensure_port_list_not_in_use_by_live_targets(&tx, state.internal_id).await?;
        ensure_port_list_not_in_use_by_live_location_trash_targets(&tx, state.internal_id).await?;
    }
    let record = execute_port_list_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit patch port list transaction")
    })?;
    Ok(Json(
        load_port_list_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn delete_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin delete port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, port_ranges_trash, targets, targets_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for delete"))?;
    let state = load_port_list_write_state(&tx, &port_list_id).await?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port lists cannot be deleted".to_string(),
        ));
    }
    ensure_port_list_not_in_use_by_live_targets(&tx, state.internal_id).await?;
    execute_port_list_trash_transaction(&tx, state.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit delete port list transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin hard-delete port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists_trash, port_ranges_trash, targets_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list trash tables for hard delete"))?;
    let trash = load_port_list_trash_state(&tx, &port_list_id).await?;
    ensure_port_list_not_in_use_by_trash_targets(&tx, trash.internal_id).await?;
    execute_port_list_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit hard-delete port list transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_port_list(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let operator = require_port_list_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_port_list_write_db_error(error, "begin restore port list transaction")
    })?;
    resolve_port_list_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE port_lists, port_lists_trash, port_ranges, port_ranges_trash, targets_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "lock port list tables for restore"))?;
    let trash = load_port_list_trash_state(&tx, &port_list_id).await?;
    ensure_unique_live_port_list_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_port_list_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_port_list_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit restore port list transaction")
    })?;

    Ok(Json(
        load_port_list_asset_detail(&client, &record.uuid).await?,
    ))
}

fn require_port_list_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("port list write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

async fn resolve_port_list_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        port_list_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| map_port_list_write_db_error(error, "resolve port list write operator"))?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!("direct API port list write operator does not resolve to a database user");
        ApiError::Forbidden
    })
}

async fn load_port_list_write_state(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<PortListWriteState, ApiError> {
    let port_list_id = crate::path_ids::parse_uuid(port_list_id)?.to_string();
    tx.query_opt(port_list_write_state_sql(), &[&port_list_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "load port list write state"))?
        .map(|row| PortListWriteState {
            internal_id: row.get(0),
            predefined: row.get::<_, i32>(1) != 0,
        })
        .ok_or(ApiError::NotFound)
}

async fn load_port_list_trash_state(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<PortListTrashWriteState, ApiError> {
    let port_list_id = crate::path_ids::parse_uuid(port_list_id)?.to_string();
    tx.query_opt(port_list_trash_state_sql(), &[&port_list_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "load port list trash state"))?
        .map(|row| PortListTrashWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

async fn ensure_unique_port_list_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "check port list name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list with the same name already exists".to_string(),
        ))
    }
}

async fn ensure_unique_live_port_list_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_unique_live_owner_name_sql(), &[&name, &owner_id])
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check port list restore name conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list with the same owner and name already exists".to_string(),
        ))
    }
}

async fn ensure_port_list_uuid_not_live(
    tx: &Transaction<'_>,
    port_list_id: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_live_uuid_conflict_sql(), &[&port_list_id])
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check port list restore UUID conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "live port list with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn execute_port_list_patch_transaction(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
    request: &ValidatedPortListPatch,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_write_record(
        tx,
        port_list_update_metadata_sql(),
        &[&port_list_internal_id, &request.name, &request.comment],
        "update port list metadata",
    )
    .await?;
    if let Some(ranges) = request.port_ranges.as_ref() {
        execute_port_list_write_sql(
            tx,
            port_list_delete_ranges_sql(),
            &[&port_list_internal_id],
            "delete existing port list ranges before replacement",
        )
        .await?;
        for range in ranges {
            execute_port_list_write_sql(
                tx,
                port_list_create_range_sql(),
                &[
                    &port_list_internal_id,
                    &range.protocol_id,
                    &range.start,
                    &range.end,
                    &range.comment,
                ],
                "insert replacement port list range",
            )
            .await?;
        }
    }
    Ok(record)
}

pub(crate) async fn execute_port_list_trash_transaction(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<PortListTrashWriteRecord, ApiError> {
    let record = query_port_list_trash_write_record(
        tx,
        port_list_trash_insert_sql(),
        &[&port_list_internal_id],
        "move port list metadata to trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_ranges_insert_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "move port list ranges to trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_target_relink_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "relink trash targets to trashed port list",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_tag_locations_to_trash_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "move live port list tag links to trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "move trashed tag links to port list trash id",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_ranges_sql(),
        &[&port_list_internal_id],
        "delete live port list ranges after trash move",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_metadata_sql(),
        &[&port_list_internal_id],
        "delete live port list after trash move",
    )
    .await?;
    Ok(record)
}

async fn ensure_port_list_not_in_use_by_live_location_trash_targets(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            port_list_live_location_trash_target_count_sql(),
            &[&port_list_internal_id],
        )
        .await
        .map_err(|error| {
            map_port_list_write_db_error(error, "check live port list trash target usage")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list is still referenced by a trash target".to_string(),
        ))
    }
}

pub(crate) async fn execute_port_list_clone_transaction(
    tx: &Transaction<'_>,
    source_port_list_internal_id: i32,
    owner_id: i32,
    request: &ValidatedPortListClone,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_write_record(
        tx,
        port_list_clone_metadata_sql(),
        &[
            &source_port_list_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone port list metadata",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_clone_ranges_sql(),
        &[&source_port_list_internal_id, &record.internal_id],
        "clone port list ranges",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_clone_tags_sql(),
        &[
            &source_port_list_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone port list tags",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_port_list_restore_transaction(
    tx: &Transaction<'_>,
    trash_port_list_internal_id: i32,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_trash_write_record(
        tx,
        port_list_restore_metadata_sql(),
        &[&trash_port_list_internal_id],
        "restore port list metadata from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_restore_ranges_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "restore port list ranges from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_restore_target_relink_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "relink trash targets to restored port list",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_tag_locations_to_live_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "restore live tag links from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_locations_to_live_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "restore trashed tag links from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_ranges_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash ranges after restore",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_metadata_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash metadata after restore",
    )
    .await?;
    Ok(PortListWriteRecord {
        internal_id: record.internal_id,
        uuid: record.uuid,
    })
}

pub(crate) async fn execute_port_list_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_port_list_internal_id: i32,
) -> Result<(), ApiError> {
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_delete_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash tag links",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_trash_delete_sql(),
        &[&trash_port_list_internal_id],
        "delete trashed tag links to port list trash id",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_ranges_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash ranges for hard delete",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_metadata_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

async fn ensure_port_list_not_in_use_by_live_targets(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(port_list_live_target_count_sql(), &[&port_list_internal_id])
        .await
        .map_err(|error| map_port_list_write_db_error(error, "check port list target usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list is still referenced by a live target".to_string(),
        ))
    }
}

async fn ensure_port_list_not_in_use_by_trash_targets(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            port_list_trash_target_count_sql(),
            &[&port_list_internal_id],
        )
        .await
        .map_err(|error| map_port_list_write_db_error(error, "check port list trash target usage"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "port list is still referenced by a trash target".to_string(),
        ))
    }
}

async fn query_port_list_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<PortListWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_port_list_write_db_error(error, action))?
        .map(|row| PortListWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

async fn query_port_list_trash_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<PortListTrashWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_port_list_write_db_error(error, action))?
        .map(|row| PortListTrashWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

async fn execute_port_list_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_port_list_write_db_error(error, action))
}

fn map_port_list_write_db_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::warn!(%error, action, "port list write database operation failed");
    ApiError::Database
}

#[cfg(test)]
#[path = "port_list_writes_tests.rs"]
mod port_list_writes_tests;
