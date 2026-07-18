// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    filter_write_db::{
        FilterTrashWriteRecord, FilterWriteRecord, execute_filter_write_sql,
        query_filter_clone_write_record, query_filter_trash_write_record,
        query_filter_write_record,
    },
    filter_write_sql::*,
    filter_write_validation::{ValidatedFilterClone, ValidatedFilterCreate, ValidatedFilterPatch},
};

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

pub(crate) async fn execute_filter_restore_transaction(
    tx: &Transaction<'_>,
    filter_trash_internal_id: i32,
) -> Result<FilterWriteRecord, ApiError> {
    let record = query_filter_trash_write_record(
        tx,
        filter_restore_metadata_sql(),
        &[&filter_trash_internal_id],
        "restore filter metadata from trash",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_trash_alert_relink_to_live_sql(),
        &[&filter_trash_internal_id, &record.internal_id],
        "relink trash alerts to restored filter",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_tag_locations_to_live_sql(),
        &[&filter_trash_internal_id, &record.internal_id],
        "move filter tag links to live",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_trash_tag_locations_to_live_sql(),
        &[&filter_trash_internal_id, &record.internal_id],
        "move trashed tag links to restored filter",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_delete_trash_metadata_sql(),
        &[&filter_trash_internal_id],
        "delete filter trash metadata after restore",
    )
    .await?;
    Ok(FilterWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_filter_hard_delete_transaction(
    tx: &Transaction<'_>,
    filter_trash_internal_id: i32,
) -> Result<(), ApiError> {
    execute_filter_write_sql(
        tx,
        filter_trash_tag_delete_sql(),
        &[&filter_trash_internal_id],
        "delete filter trash tag links",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_trash_tag_trash_delete_sql(),
        &[&filter_trash_internal_id],
        "delete trashed tag links to filter trash id",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_delete_trash_metadata_sql(),
        &[&filter_trash_internal_id],
        "delete filter trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_filter_clone_transaction(
    tx: &Transaction<'_>,
    source_filter_internal_id: i32,
    owner_id: i32,
    request: &ValidatedFilterClone,
) -> Result<FilterWriteRecord, ApiError> {
    let record = query_filter_clone_write_record(
        tx,
        filter_clone_metadata_sql(),
        &[
            &source_filter_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone filter metadata",
    )
    .await?;
    execute_filter_write_sql(
        tx,
        filter_clone_tags_sql(),
        &[
            &source_filter_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone filter tags",
    )
    .await?;
    Ok(FilterWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_filter_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedFilterCreate,
) -> Result<FilterWriteRecord, ApiError> {
    query_filter_write_record(
        tx,
        filter_insert_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.filter_type,
            &request.term,
        ],
        "insert filter metadata",
    )
    .await
}

pub(crate) async fn execute_filter_patch_transaction(
    tx: &Transaction<'_>,
    filter_internal_id: i32,
    request: &ValidatedFilterPatch,
) -> Result<FilterWriteRecord, ApiError> {
    query_filter_write_record(
        tx,
        filter_update_metadata_sql(),
        &[
            &filter_internal_id,
            &request.name,
            &request.comment,
            &request.filter_type,
            &request.term,
        ],
        "update filter metadata",
    )
    .await
}
