// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    credential_query_sql::tag_credential_selection_sql,
    errors::ApiError,
    path_ids::parse_uuid,
    port_list_query_sql::tag_port_list_selection_sql,
    scanner_asset_query_sql::tag_scanner_selection_sql,
    tag_resource_helpers::{
        tag_resource_active_lookup_sql, tag_resource_direct_write_id_must_be_uuid,
    },
    tag_write_db::{
        TagWriteRecord, TagWriteState, ensure_tag_resource_is_team_assignable,
        map_tag_write_db_error,
    },
    tag_write_sql::*,
    tag_write_validation::{
        MAX_TAG_RESOURCE_SELECTION_MATCHES, TagResourceUpdateAction, ValidatedTagClone,
        ValidatedTagCreate, ValidatedTagPatch, ValidatedTagResourceSelection,
        ValidatedTagResourceUpdate,
    },
    target_query_sql::tag_target_selection_sql,
    user_management_query_sql::tag_user_selection_sql,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagResourceWriteRecord {
    internal_id: i32,
    uuid: String,
    owner_id: Option<i32>,
}

pub(crate) async fn execute_tag_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedTagCreate,
) -> Result<TagWriteRecord, ApiError> {
    let record = query_tag_write_record(
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
    .await?;
    for resource_id in &request.resource_ids {
        let resource =
            resolve_tag_resource_write_record(tx, &request.resource_type, resource_id).await?;
        ensure_tag_resource_is_team_assignable(&request.resource_type, resource.owner_id)?;
        tx.execute(
            tag_resource_insert_sql(),
            &[
                &record.internal_id,
                &request.resource_type,
                &resource.internal_id,
                &resource.uuid,
            ],
        )
        .await
        .map_err(|error| map_tag_write_db_error(error, "insert tag resource on create"))?;
    }
    Ok(record)
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
    request: &ValidatedTagResourceUpdate,
) -> Result<(), ApiError> {
    let resources = resolve_tag_resource_update_records(tx, state, request).await?;
    apply_tag_resource_update_transaction(tx, state, request, resources).await
}

async fn resolve_tag_resource_update_records(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    request: &ValidatedTagResourceUpdate,
) -> Result<Vec<TagResourceWriteRecord>, ApiError> {
    if let Some(selection) = request.resource_selection.as_ref() {
        return match selection {
            ValidatedTagResourceSelection::PortList { .. } => {
                resolve_tag_port_list_selection_records(tx, state, selection).await
            }
            ValidatedTagResourceSelection::Credential { .. } => Err(ApiError::Config),
            ValidatedTagResourceSelection::Scanner { .. } => {
                resolve_tag_scanner_selection_records(tx, state, selection).await
            }
            ValidatedTagResourceSelection::Target { .. } => {
                resolve_tag_target_selection_records(tx, state, selection).await
            }
            ValidatedTagResourceSelection::User { .. } => Err(ApiError::Config),
        };
    }
    let mut resources = Vec::new();
    for resource_id in &request.resource_ids {
        let resource =
            resolve_tag_resource_write_record(tx, &state.resource_type, resource_id).await?;
        ensure_tag_resource_is_team_assignable(&state.resource_type, resource.owner_id)?;
        resources.push(resource);
    }
    Ok(resources)
}

async fn resolve_tag_target_selection_records(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    selection: &ValidatedTagResourceSelection,
) -> Result<Vec<TagResourceWriteRecord>, ApiError> {
    let ValidatedTagResourceSelection::Target {
        search,
        expected_count,
    } = selection
    else {
        return Err(ApiError::BadRequest(
            "resource_selection requires a target tag".to_string(),
        ));
    };
    if state.resource_type != "target" {
        return Err(ApiError::BadRequest(
            "resource_selection requires a target tag".to_string(),
        ));
    }
    let search = search.as_deref().unwrap_or("");
    let selection_limit = i64::from(MAX_TAG_RESOURCE_SELECTION_MATCHES) + 1;
    let rows = tx
        .query(&tag_target_selection_sql(), &[&search, &selection_limit])
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "select targets for tag resource selection")
        })?;
    if rows.len() > MAX_TAG_RESOURCE_SELECTION_MATCHES as usize
        || rows.len() as i64 != *expected_count
    {
        return Err(ApiError::Conflict(
            "tag resource selection no longer matches expected_count".to_string(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let resource = TagResourceWriteRecord {
                internal_id: row.get(0),
                uuid: row.get(1),
                owner_id: row.get(2),
            };
            ensure_tag_resource_is_team_assignable("target", resource.owner_id)?;
            Ok(resource)
        })
        .collect()
}

async fn resolve_tag_port_list_selection_records(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    selection: &ValidatedTagResourceSelection,
) -> Result<Vec<TagResourceWriteRecord>, ApiError> {
    let ValidatedTagResourceSelection::PortList {
        search,
        predefined,
        expected_count,
    } = selection
    else {
        return Err(ApiError::BadRequest(
            "resource_selection requires a port_list tag".to_string(),
        ));
    };
    if state.resource_type != "port_list" {
        return Err(ApiError::BadRequest(
            "resource_selection requires a port_list tag".to_string(),
        ));
    }
    let search = search.as_deref().unwrap_or("");
    let predefined = predefined
        .map(|value| if value { "1" } else { "0" })
        .unwrap_or("");
    let selection_limit = i64::from(MAX_TAG_RESOURCE_SELECTION_MATCHES) + 1;
    let rows = tx
        .query(
            &tag_port_list_selection_sql(),
            &[&search, &predefined, &selection_limit],
        )
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "select port lists for tag resource selection")
        })?;
    if rows.len() > MAX_TAG_RESOURCE_SELECTION_MATCHES as usize
        || rows.len() as i64 != *expected_count
    {
        return Err(ApiError::Conflict(
            "tag resource selection no longer matches expected_count".to_string(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let resource = TagResourceWriteRecord {
                internal_id: row.get(0),
                uuid: row.get(1),
                owner_id: row.get(2),
            };
            ensure_tag_resource_is_team_assignable("port_list", resource.owner_id)?;
            Ok(resource)
        })
        .collect()
}

async fn resolve_tag_scanner_selection_records(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    selection: &ValidatedTagResourceSelection,
) -> Result<Vec<TagResourceWriteRecord>, ApiError> {
    let ValidatedTagResourceSelection::Scanner {
        search,
        expected_count,
    } = selection
    else {
        return Err(ApiError::BadRequest(
            "resource_selection requires a scanner tag".to_string(),
        ));
    };
    if state.resource_type != "scanner" {
        return Err(ApiError::BadRequest(
            "resource_selection requires a scanner tag".to_string(),
        ));
    }
    let search = search.as_deref().unwrap_or("");
    let selection_limit = i64::from(MAX_TAG_RESOURCE_SELECTION_MATCHES) + 1;
    let rows = tx
        .query(&tag_scanner_selection_sql(), &[&search, &selection_limit])
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "select scanners for tag resource selection")
        })?;
    if rows.len() > MAX_TAG_RESOURCE_SELECTION_MATCHES as usize
        || rows.len() as i64 != *expected_count
    {
        return Err(ApiError::Conflict(
            "tag resource selection no longer matches expected_count".to_string(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let resource = TagResourceWriteRecord {
                internal_id: row.get(0),
                uuid: row.get(1),
                owner_id: row.get(2),
            };
            ensure_tag_resource_is_team_assignable("scanner", resource.owner_id)?;
            Ok(resource)
        })
        .collect()
}

pub(crate) async fn resolve_tag_credential_selection_records(
    tx: &Transaction<'_>,
    selection: &ValidatedTagResourceSelection,
) -> Result<Vec<TagResourceWriteRecord>, ApiError> {
    let ValidatedTagResourceSelection::Credential {
        search,
        credential_type,
        expected_count,
    } = selection
    else {
        return Err(ApiError::BadRequest(
            "resource_selection requires a credential tag".to_string(),
        ));
    };
    let search = search.as_deref().unwrap_or("");
    let credential_type = credential_type.as_deref().unwrap_or("");
    let selection_limit = i64::from(MAX_TAG_RESOURCE_SELECTION_MATCHES) + 1;
    let rows = tx
        .query(
            &tag_credential_selection_sql(),
            &[&search, &credential_type, &selection_limit],
        )
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "select credentials for tag resource selection")
        })?;
    if rows.len() > MAX_TAG_RESOURCE_SELECTION_MATCHES as usize
        || rows.len() as i64 != *expected_count
    {
        return Err(ApiError::Conflict(
            "tag resource selection no longer matches expected_count".to_string(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let resource = TagResourceWriteRecord {
                internal_id: row.get(0),
                uuid: row.get(1),
                owner_id: row.get(2),
            };
            ensure_tag_resource_is_team_assignable("credential", resource.owner_id)?;
            Ok(resource)
        })
        .collect()
}

pub(crate) async fn resolve_tag_user_selection_records(
    tx: &Transaction<'_>,
    selection: &ValidatedTagResourceSelection,
) -> Result<Vec<TagResourceWriteRecord>, ApiError> {
    let ValidatedTagResourceSelection::User {
        search,
        expected_count,
    } = selection
    else {
        return Err(ApiError::BadRequest(
            "resource_selection requires a user tag".to_string(),
        ));
    };
    let search = search.as_deref().unwrap_or("");
    let selection_limit = i64::from(MAX_TAG_RESOURCE_SELECTION_MATCHES) + 1;
    let rows = tx
        .query(&tag_user_selection_sql(), &[&search, &selection_limit])
        .await
        .map_err(|error| {
            map_tag_write_db_error(error, "select users for tag resource selection")
        })?;
    if rows.len() > MAX_TAG_RESOURCE_SELECTION_MATCHES as usize
        || rows.len() as i64 != *expected_count
    {
        return Err(ApiError::Conflict(
            "tag resource selection no longer matches expected_count".to_string(),
        ));
    }
    rows.into_iter()
        .map(|row| {
            let resource = TagResourceWriteRecord {
                internal_id: row.get(0),
                uuid: row.get(1),
                owner_id: row.get(2),
            };
            ensure_tag_resource_is_team_assignable("user", resource.owner_id)?;
            Ok(resource)
        })
        .collect()
}

pub(crate) async fn apply_tag_resource_update_transaction(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    request: &ValidatedTagResourceUpdate,
    resources: Vec<TagResourceWriteRecord>,
) -> Result<(), ApiError> {
    if request.action == TagResourceUpdateAction::Set {
        tx.execute(tag_resource_clear_sql(), &[&state.internal_id])
            .await
            .map_err(|error| map_tag_write_db_error(error, "clear tag resources"))?;
    }

    for resource in resources {
        match request.action {
            TagResourceUpdateAction::Add | TagResourceUpdateAction::Set => {
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
    state: &TagWriteState,
    request: &ValidatedTagPatch,
) -> Result<TagWriteRecord, ApiError> {
    let effective_resource_type = request
        .resource_type
        .as_deref()
        .unwrap_or(&state.resource_type);
    let effective_state = TagWriteState {
        internal_id: state.internal_id,
        uuid: state.uuid.clone(),
        owner_id: state.owner_id,
        resource_type: effective_resource_type.to_string(),
        resource_count: state.resource_count,
    };
    let resources = if let Some(update) = request.resources.as_ref() {
        Some(resolve_tag_resource_update_records(tx, &effective_state, update).await?)
    } else {
        None
    };
    execute_tag_patch_with_resolved_resources(tx, state, request, resources).await
}

pub(crate) async fn execute_tag_patch_with_resolved_resources(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    request: &ValidatedTagPatch,
    resources: Option<Vec<TagResourceWriteRecord>>,
) -> Result<TagWriteRecord, ApiError> {
    let effective_resource_type = request
        .resource_type
        .as_deref()
        .unwrap_or(&state.resource_type);
    let effective_state = TagWriteState {
        internal_id: state.internal_id,
        uuid: state.uuid.clone(),
        owner_id: state.owner_id,
        resource_type: effective_resource_type.to_string(),
        resource_count: state.resource_count,
    };
    let record = query_tag_write_record(
        tx,
        tag_update_metadata_sql(),
        &[
            &state.internal_id,
            &request.name,
            &request.comment,
            &request.value,
            &request.active.map(|value| value as i32),
            &request.resource_type,
        ],
        "update tag metadata",
    )
    .await?;
    if let Some((update, resources)) = request.resources.as_ref().zip(resources) {
        apply_tag_resource_update_transaction(tx, &effective_state, update, resources).await?;
    }
    Ok(record)
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
