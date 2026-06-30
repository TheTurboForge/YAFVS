// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    tag_payloads::{TagAssetItem, tag_asset_from_row},
    tag_resource_helpers::{
        tag_resource_active_lookup_sql, tag_resource_direct_write_id_must_be_uuid,
        tag_resource_direct_write_type_is_supported,
    },
    tag_write_sql::*,
    tag_write_validation::{
        TagResourceUpdateAction, ValidatedTagClone, ValidatedTagCreate, ValidatedTagPatch,
        ValidatedTagResourceUpdate,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) resource_type: String,
    pub(crate) resource_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TagResourceWriteRecord {
    internal_id: i32,
    uuid: String,
}

pub(crate) fn require_tag_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("tag write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_tag_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(tag_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_tag_write_db_error(error, "resolve tag write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API tag write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_tag_write_detail<C>(
    client: &C,
    tag_id: &str,
) -> Result<TagAssetItem, ApiError>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let tag_id = parse_uuid(tag_id)?.to_string();
    let row = client
        .query_opt(tag_write_detail_sql(), &[&tag_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "load tag write detail"))?
        .ok_or(ApiError::NotFound)?;
    Ok(tag_asset_from_row(&row))
}

pub(crate) async fn load_tag_write_state(
    tx: &Transaction<'_>,
    tag_id: &str,
) -> Result<TagWriteState, ApiError> {
    let tag_id = parse_uuid(tag_id)?.to_string();
    let row = tx
        .query_opt(tag_write_state_sql(), &[&tag_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "load tag write state"))?
        .ok_or(ApiError::NotFound)?;
    Ok(TagWriteState {
        internal_id: row.get(0),
        uuid: row.get(1),
        resource_type: row.get(2),
        resource_count: row.get(3),
    })
}

pub(crate) async fn load_unassigned_tag_write_state(
    tx: &Transaction<'_>,
    tag_id: &str,
) -> Result<TagWriteState, ApiError> {
    let state = load_tag_write_state(tx, tag_id).await?;
    ensure_tag_is_unassigned(state.resource_count)?;
    Ok(state)
}

pub(crate) fn ensure_tag_resource_direct_write_type_is_supported(
    resource_type: &str,
) -> Result<(), ApiError> {
    if tag_resource_direct_write_type_is_supported(resource_type) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "tag resource type {resource_type} is not supported by direct resource writes"
        )))
    }
}

pub(crate) async fn execute_tag_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedTagCreate,
) -> Result<TagWriteRecord, ApiError> {
    query_tag_write_record(
        tx,
        tag_insert_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.value,
            &request.resource_type,
            &(request.active as i32),
        ],
        "insert tag metadata",
    )
    .await
}

pub(crate) async fn execute_tag_resource_update_transaction(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    request: &ValidatedTagResourceUpdate,
) -> Result<(), ApiError> {
    for resource_id in &request.resource_ids {
        let resource =
            resolve_tag_resource_write_record(tx, &state.resource_type, resource_id).await?;
        match request.action {
            TagResourceUpdateAction::Add => {
                tx.execute(
                    tag_resource_insert_sql(),
                    &[
                        &state.internal_id,
                        &state.resource_type,
                        &resource.internal_id,
                        &resource.uuid,
                    ],
                )
                .await
                .map_err(|error| map_tag_write_db_error(error, "insert tag resource"))?;
            }
            TagResourceUpdateAction::Remove => {
                let deleted = tx
                    .execute(
                        tag_resource_delete_sql(),
                        &[
                            &state.internal_id,
                            &state.resource_type,
                            &resource.internal_id,
                        ],
                    )
                    .await
                    .map_err(|error| map_tag_write_db_error(error, "delete tag resource"))?;
                if deleted == 0 {
                    return Err(ApiError::NotFound);
                }
            }
        }
    }
    tx.execute(tag_touch_metadata_sql(), &[&state.internal_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "touch tag metadata"))?;
    Ok(())
}

pub(crate) async fn execute_tag_clone_transaction(
    tx: &Transaction<'_>,
    source_tag_internal_id: i32,
    owner_id: i32,
    request: &ValidatedTagClone,
) -> Result<TagWriteRecord, ApiError> {
    let record = query_tag_write_record(
        tx,
        tag_clone_metadata_sql(),
        &[
            &source_tag_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone tag metadata",
    )
    .await?;
    tx.execute(
        tag_clone_resources_sql(),
        &[&source_tag_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "clone tag resources"))?;
    Ok(record)
}

pub(crate) async fn execute_tag_delete_transaction(
    tx: &Transaction<'_>,
    tag_internal_id: i32,
) -> Result<TagWriteRecord, ApiError> {
    query_tag_write_record(
        tx,
        tag_delete_metadata_sql(),
        &[&tag_internal_id],
        "delete tag metadata",
    )
    .await
}

pub(crate) async fn execute_tag_patch_transaction(
    tx: &Transaction<'_>,
    tag_id: &str,
    request: &ValidatedTagPatch,
) -> Result<TagWriteRecord, ApiError> {
    let tag_id = parse_uuid(tag_id)?.to_string();
    query_tag_write_record(
        tx,
        tag_update_metadata_sql(),
        &[
            &tag_id,
            &request.name,
            &request.comment,
            &request.value,
            &request.active.map(|value| value as i32),
        ],
        "update tag metadata",
    )
    .await
}

async fn resolve_tag_resource_write_record(
    tx: &Transaction<'_>,
    resource_type: &str,
    resource_id: &str,
) -> Result<TagResourceWriteRecord, ApiError> {
    let resource_id = if tag_resource_direct_write_id_must_be_uuid(resource_type) {
        parse_uuid(resource_id)?.to_string()
    } else {
        resource_id.to_string()
    };
    let sql = tag_resource_active_lookup_sql(resource_type)?;
    tx.query_opt(&sql, &[&resource_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "resolve tag resource"))?
        .map(|row| TagResourceWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn ensure_tag_is_unassigned(resource_count: i64) -> Result<(), ApiError> {
    if resource_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "tag with assigned resources cannot be deleted by this metadata-only direct API"
                .to_string(),
        ))
    }
}

async fn query_tag_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TagWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_tag_write_db_error(error, action))?
        .map(|row| tag_write_record_from_row(&row))
        .ok_or(ApiError::NotFound)
}

fn tag_write_record_from_row(row: &Row) -> TagWriteRecord {
    TagWriteRecord {
        internal_id: row.get(0),
        uuid: row.get(1),
    }
}

pub(crate) fn map_tag_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "tag write database operation failed");
    ApiError::Database
}
