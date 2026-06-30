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
    filter_payloads::FilterAssetItem,
    filter_write_sql::*,
    filter_write_validation::{
        FilterPatchRequest, ValidatedFilterPatch, validate_filter_patch_request,
    },
    filters::load_filter_asset_detail,
    path_ids::parse_uuid,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterWriteRecord {
    uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilterTrashWriteRecord {
    internal_id: i32,
    uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FilterWriteState {
    internal_id: i32,
}

pub(crate) async fn delete_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let filter_uuid = parse_uuid(&filter_id)?.to_string();
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin delete filter transaction"))?;
    resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE filters, filters_trash, settings, alerts, alerts_trash, alert_condition_data, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_filter_write_db_error(error, "lock filter tables for delete"))?;
    let state = load_filter_write_state(&tx, &filter_uuid).await?;
    ensure_filter_not_in_use_by_alerts(&tx, state.internal_id).await?;
    execute_filter_trash_transaction(&tx, state.internal_id, &filter_uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit delete filter transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterWriteOperation {
    Create,
    Patch,
    Delete,
}

pub(crate) async fn execute_filter_trash_transaction(
    tx: &Transaction<'_>,
    filter_internal_id: i32,
    filter_uuid: &str,
) -> Result<FilterTrashWriteRecord, ApiError> {
    execute_filter_write_sql(
        tx,
        filter_settings_cleanup_sql(),
        &[&filter_uuid],
        "delete filter settings",
    )
    .await?;
    let record = query_filter_trash_write_record(
        tx,
        filter_trash_insert_sql(),
        &[&filter_internal_id],
        "move filter metadata to trash",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_trash_alert_relink_sql(),
        &[&record.internal_id, &filter_internal_id],
        "relink trash alerts to trashed filter",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_tag_locations_to_trash_sql(),
        &[&record.internal_id, &filter_internal_id],
        "move live filter tag links to trash",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &filter_internal_id],
        "move trashed tag links to filter trash id",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_delete_metadata_sql(),
        &[&filter_internal_id],
        "delete live filter after trash move",
    )
    .await?;
    Ok(record)
}

async fn ensure_filter_not_in_use_by_alerts(
    tx: &Transaction<'_>,
    filter_internal_id: i32,
) -> Result<(), ApiError> {
    let direct_count: i64 = tx
        .query_one(filter_live_alert_count_sql(), &[&filter_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check direct alert filter usage"))?
        .get(0);
    let condition_count: i64 = tx
        .query_one(filter_alert_condition_count_sql(), &[&filter_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check alert condition filter usage"))?
        .get(0);
    if direct_count == 0 && condition_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter is still referenced by an alert".to_string(),
        ))
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterWriteStep {
    ResolveOperatorOwner,
    NormalizeFilterType,
    ValidateFilterSubtype,
    CleanFilterTerm,
    VerifyUniqueLiveName,
    VerifyExistingFilterMutable,
    VerifyAlertLinkedTypeChangeAllowed,
    InsertFilter,
    UpdateFilterMetadata,
    MoveFilterToTrash,
    RelocatePermissionsAndTags,
    CleanupFilterSettings,
}

async fn query_filter_trash_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<FilterTrashWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))?
        .map(|row| FilterTrashWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

async fn execute_filter_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FilterWriteTransactionPlan {
    pub(crate) operation: FilterWriteOperation,
    pub(crate) steps: Vec<FilterWriteStep>,
}

pub(crate) async fn patch_filter(
    State(state): State<AppState>,
    Path(filter_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<FilterPatchRequest>,
) -> Result<Json<FilterAssetItem>, ApiError> {
    let operator = require_filter_write_operator(operator)?;
    let request = validate_filter_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_filter_write_db_error(error, "begin patch filter transaction"))?;
    resolve_filter_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE filters, filters_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_filter_write_db_error(error, "lock filters for patch"))?;
    let state = load_filter_write_state(&tx, &filter_id).await?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_filter_name(&tx, name, state.internal_id).await?;
    }
    let record = execute_filter_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_filter_write_db_error(error, "commit patch filter transaction"))?;
    Ok(Json(load_filter_asset_detail(&client, &record.uuid).await?))
}

fn require_filter_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("filter write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

async fn resolve_filter_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(filter_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_filter_write_db_error(error, "resolve filter write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API filter write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

async fn load_filter_write_state(
    tx: &Transaction<'_>,
    filter_id: &str,
) -> Result<FilterWriteState, ApiError> {
    let filter_id = parse_uuid(filter_id)?.to_string();
    tx.query_opt(filter_write_state_sql(), &[&filter_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "load filter write state"))?
        .map(|row| FilterWriteState {
            internal_id: row.get(0),
        })
        .ok_or(ApiError::NotFound)
}

async fn ensure_unique_filter_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(filter_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| map_filter_write_db_error(error, "check filter name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "filter with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn execute_filter_patch_transaction(
    tx: &Transaction<'_>,
    filter_internal_id: i32,
    request: &ValidatedFilterPatch,
) -> Result<FilterWriteRecord, ApiError> {
    query_filter_write_record(
        tx,
        filter_update_metadata_sql(),
        &[&filter_internal_id, &request.name, &request.comment],
        "update filter metadata",
    )
    .await
}

async fn query_filter_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<FilterWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_filter_write_db_error(error, action))?
        .map(|row| FilterWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

fn map_filter_write_db_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::warn!(%error, action, "filter write database operation failed");
    ApiError::Database
}

#[cfg(test)]
pub(crate) fn filter_create_transaction_plan() -> FilterWriteTransactionPlan {
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Create,
        steps: vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::NormalizeFilterType,
            FilterWriteStep::ValidateFilterSubtype,
            FilterWriteStep::CleanFilterTerm,
            FilterWriteStep::VerifyUniqueLiveName,
            FilterWriteStep::InsertFilter,
        ],
    }
}

#[cfg(test)]
pub(crate) fn filter_patch_transaction_plan(
    changes_filter_type: bool,
) -> FilterWriteTransactionPlan {
    let mut steps = vec![
        FilterWriteStep::ResolveOperatorOwner,
        FilterWriteStep::VerifyExistingFilterMutable,
        FilterWriteStep::NormalizeFilterType,
        FilterWriteStep::ValidateFilterSubtype,
        FilterWriteStep::CleanFilterTerm,
    ];
    if changes_filter_type {
        steps.push(FilterWriteStep::VerifyAlertLinkedTypeChangeAllowed);
    }
    steps.extend([
        FilterWriteStep::VerifyUniqueLiveName,
        FilterWriteStep::UpdateFilterMetadata,
    ]);
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Patch,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn filter_delete_transaction_plan() -> FilterWriteTransactionPlan {
    FilterWriteTransactionPlan {
        operation: FilterWriteOperation::Delete,
        steps: vec![
            FilterWriteStep::ResolveOperatorOwner,
            FilterWriteStep::VerifyExistingFilterMutable,
            FilterWriteStep::MoveFilterToTrash,
            FilterWriteStep::CleanupFilterSettings,
            FilterWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

#[cfg(test)]
#[path = "filter_writes_tests.rs"]
mod filter_writes_tests;
