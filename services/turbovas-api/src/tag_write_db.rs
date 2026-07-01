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
        tag_resource_direct_write_requires_owner_match,
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
    pub(crate) owner_id: i32,
    pub(crate) resource_type: String,
    pub(crate) resource_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagTrashWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: i32,
    pub(crate) resource_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TagResourceWriteRecord {
    internal_id: i32,
    uuid: String,
    owner_id: Option<i32>,
}

pub(crate) fn ensure_tag_owner_matches_operator(
    tag_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if tag_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!(
            tag_owner_id,
            operator_owner_id,
            "direct API tag write owner mismatch"
        );
        Err(ApiError::Forbidden)
    }
}

pub(crate) fn ensure_tag_resource_owner_matches_operator(
    resource_type: &str,
    resource_owner_id: Option<i32>,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if !tag_resource_direct_write_requires_owner_match(resource_type) {
        return Ok(());
    }
    match resource_owner_id {
        Some(owner_id) if owner_id == operator_owner_id => Ok(()),
        Some(owner_id) => {
            tracing::warn!(
                resource_type,
                resource_owner_id = owner_id,
                operator_owner_id,
                "direct API tag resource write owner mismatch"
            );
            Err(ApiError::Forbidden)
        }
        None => {
            tracing::warn!(
                resource_type,
                operator_owner_id,
                "direct API tag resource write missing owner on owner-bearing resource type"
            );
            Err(ApiError::Forbidden)
        }
    }
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
        owner_id: row.get(2),
        resource_type: row.get(3),
        resource_count: row.get(4),
    })
}

pub(crate) async fn load_tag_trash_state(
    tx: &Transaction<'_>,
    tag_id: &str,
) -> Result<TagTrashWriteState, ApiError> {
    let tag_id = parse_uuid(tag_id)?.to_string();
    let row = tx
        .query_opt(tag_trash_state_sql(), &[&tag_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "load tag trash state"))?
        .ok_or(ApiError::NotFound)?;
    Ok(TagTrashWriteState {
        internal_id: row.get(0),
        uuid: row.get(1),
        owner_id: row.get(2),
        resource_type: row.get(3),
    })
}

pub(crate) async fn ensure_tag_uuid_not_live(
    tx: &Transaction<'_>,
    tag_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(tag_live_uuid_conflict_sql(), &[&tag_uuid])
        .await
        .map_err(|error| map_tag_write_db_error(error, "check live tag uuid conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "tag with the same id already exists".to_string(),
        ))
    }
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

pub(crate) async fn execute_tag_trash_transaction(
    tx: &Transaction<'_>,
    tag_internal_id: i32,
) -> Result<TagWriteRecord, ApiError> {
    let record = query_tag_write_record(
        tx,
        tag_trash_insert_sql(),
        &[&tag_internal_id],
        "move tag metadata to trash",
    )
    .await?;
    tx.execute(
        tag_trash_resources_insert_sql(),
        &[&tag_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "move tag resources to trash"))?;
    tx.execute(
        tag_live_tag_locations_to_trash_sql(),
        &[&tag_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "move live tag-as-resource links to trash"))?;
    tx.execute(
        tag_trash_tag_locations_to_trash_sql(),
        &[&tag_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| {
        map_tag_write_db_error(error, "move trashed tag-as-resource links to trash")
    })?;
    tx.execute(tag_delete_live_resources_sql(), &[&tag_internal_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "delete live tag resources"))?;
    tx.execute(tag_delete_live_metadata_sql(), &[&tag_internal_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "delete live tag metadata"))?;
    Ok(record)
}

pub(crate) async fn execute_tag_restore_transaction(
    tx: &Transaction<'_>,
    tag_trash_internal_id: i32,
) -> Result<TagWriteRecord, ApiError> {
    let record = query_tag_write_record(
        tx,
        tag_restore_metadata_sql(),
        &[&tag_trash_internal_id],
        "restore tag metadata from trash",
    )
    .await?;
    tx.execute(
        tag_restore_resources_sql(),
        &[&tag_trash_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "restore tag resources from trash"))?;
    tx.execute(tag_delete_trash_resources_sql(), &[&tag_trash_internal_id])
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "delete tag trash resources after restore")
        })?;
    tx.execute(
        tag_live_tag_locations_to_live_sql(),
        &[&tag_trash_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "restore live tag-as-resource links"))?;
    tx.execute(
        tag_trash_tag_locations_to_live_sql(),
        &[&tag_trash_internal_id, &record.internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "restore trashed tag-as-resource links"))?;
    tx.execute(tag_delete_trash_metadata_sql(), &[&tag_trash_internal_id])
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "delete tag trash metadata after restore")
        })?;
    Ok(record)
}

pub(crate) async fn execute_tag_hard_delete_transaction(
    tx: &Transaction<'_>,
    tag_trash_internal_id: i32,
) -> Result<(), ApiError> {
    tx.execute(tag_delete_trash_resources_sql(), &[&tag_trash_internal_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "delete tag trash resources"))?;
    tx.execute(
        tag_delete_live_tag_trash_links_sql(),
        &[&tag_trash_internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "delete live tag-as-trash-resource links"))?;
    tx.execute(
        tag_delete_trash_tag_trash_links_sql(),
        &[&tag_trash_internal_id],
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "delete trashed tag-as-trash-resource links"))?;
    tx.execute(tag_delete_trash_metadata_sql(), &[&tag_trash_internal_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "delete tag trash metadata"))?;
    Ok(())
}

pub(crate) async fn execute_tag_resource_update_transaction(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    operator_owner_id: i32,
    request: &ValidatedTagResourceUpdate,
) -> Result<(), ApiError> {
    for resource_id in &request.resource_ids {
        let resource =
            resolve_tag_resource_write_record(tx, &state.resource_type, resource_id).await?;
        ensure_tag_resource_owner_matches_operator(
            &state.resource_type,
            resource.owner_id,
            operator_owner_id,
        )?;
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

pub(crate) async fn execute_tag_patch_transaction(
    tx: &Transaction<'_>,
    tag_internal_id: i32,
    request: &ValidatedTagPatch,
) -> Result<TagWriteRecord, ApiError> {
    query_tag_write_record(
        tx,
        tag_update_metadata_sql(),
        &[
            &tag_internal_id,
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
            owner_id: row.get(2),
        })
        .ok_or(ApiError::NotFound)
}

#[cfg(test)]
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
