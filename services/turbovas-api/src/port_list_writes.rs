// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use serde::Deserialize;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    port_lists::{PortListAssetDetail, load_port_list_asset_detail},
};

const MAX_PORT_LIST_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortListPatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedPortListPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortListWriteRecord {
    uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortListWriteState {
    internal_id: i32,
    predefined: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortListWriteOperation {
    Create,
    Patch,
    Delete,
    Restore,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortListWriteStep {
    ResolveOperatorOwner,
    VerifyExistingPortListMutable,
    VerifyExistingTrashedPortListRestorable,
    VerifyNotPredefined,
    ValidatePortRanges,
    VerifyUniqueLiveAndTrashName,
    VerifyTargetDeleteSafety,
    InsertPortList,
    ReplacePortRanges,
    UpdatePortListMetadata,
    MovePortListToTrash,
    MovePortRangesToTrash,
    RestorePortListFromTrash,
    RestorePortRangesFromTrash,
    RelocateTargets,
    RelocatePermissionsAndTags,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PortListWriteTransactionPlan {
    pub(crate) operation: PortListWriteOperation,
    pub(crate) steps: Vec<PortListWriteStep>,
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
    tx.batch_execute("LOCK TABLE port_lists, port_lists_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_port_list_write_db_error(error, "lock port lists for patch"))?;
    let state = load_port_list_write_state(&tx, &port_list_id).await?;
    if state.predefined {
        return Err(ApiError::Conflict(
            "predefined port lists cannot be patched".to_string(),
        ));
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_port_list_name(&tx, name, state.internal_id).await?;
    }
    let record = execute_port_list_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_port_list_write_db_error(error, "commit patch port list transaction")
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

pub(crate) fn validate_port_list_patch_request(
    request: PortListPatchRequest,
) -> Result<ValidatedPortListPatch, ApiError> {
    let validated = ValidatedPortListPatch {
        name: normalize_optional_required_port_list_text(request.name, "name")?,
        comment: normalize_optional_port_list_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "port list patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_optional_required_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_port_list_text(value, field_name))
        .transpose()
}

fn normalize_required_port_list_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_port_list_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_port_list_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_port_list_text_value(value, field_name))
        .transpose()
}

fn normalize_port_list_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_PORT_LIST_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_PORT_LIST_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
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

pub(crate) async fn execute_port_list_patch_transaction(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
    request: &ValidatedPortListPatch,
) -> Result<PortListWriteRecord, ApiError> {
    query_port_list_write_record(
        tx,
        port_list_update_metadata_sql(),
        &[&port_list_internal_id, &request.name, &request.comment],
        "update port list metadata",
    )
    .await
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
        .map(|row| PortListWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

fn map_port_list_write_db_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::warn!(%error, action, "port list write database operation failed");
    ApiError::Database
}

pub(crate) fn port_list_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn port_list_write_state_sql() -> &'static str {
    "SELECT id::integer, coalesce(predefined, 0)::integer
       FROM port_lists
      WHERE uuid = $1;"
}

pub(crate) fn port_list_unique_name_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM port_lists WHERE name = $1 AND id != $2)
        + (SELECT count(*) FROM port_lists_trash WHERE name = $1)
      )::bigint;"
}

pub(crate) fn port_list_update_metadata_sql() -> &'static str {
    "UPDATE port_lists
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

#[cfg(test)]
pub(crate) fn port_list_create_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Create,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::InsertPortList,
            PortListWriteStep::ReplacePortRanges,
        ],
    }
}

#[cfg(test)]
pub(crate) fn port_list_patch_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Patch,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyNotPredefined,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::UpdatePortListMetadata,
        ],
    }
}

#[cfg(test)]
pub(crate) fn port_list_delete_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Delete,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::MovePortListToTrash,
            PortListWriteStep::MovePortRangesToTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

#[cfg(test)]
pub(crate) fn port_list_restore_transaction_plan() -> PortListWriteTransactionPlan {
    PortListWriteTransactionPlan {
        operation: PortListWriteOperation::Restore,
        steps: vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::RestorePortListFromTrash,
            PortListWriteStep::RestorePortRangesFromTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

#[cfg(test)]
#[path = "port_list_writes_tests.rs"]
mod port_list_writes_tests;
