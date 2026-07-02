// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    errors::ApiError,
    path_ids::parse_uuid,
    tag_resource_helpers::{
        tag_resource_active_lookup_sql, tag_resource_direct_write_id_must_be_uuid,
    },
    tag_write_db::{
        TagWriteRecord, TagWriteState, ensure_tag_resource_owner_matches_operator,
        map_tag_write_db_error,
    },
    tag_write_sql::*,
    tag_write_validation::{
        TagResourceUpdateAction, ValidatedTagClone, ValidatedTagCreate, ValidatedTagPatch,
        ValidatedTagResourceUpdate,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct TagResourceWriteRecord {
    internal_id: i32,
    uuid: String,
    owner_id: Option<i32>,
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
