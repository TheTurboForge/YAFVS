// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    target_write_db::{
        TargetWriteRecord, TargetWriteRecordWithInternalId, execute_target_write_sql,
        query_target_write_record_with_internal_id,
    },
    target_write_sql::*,
    target_write_validation::{ValidatedTargetClone, ValidatedTargetCreate},
};

pub(crate) async fn execute_target_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    port_list_internal_id: i32,
    request: &ValidatedTargetCreate,
) -> Result<TargetWriteRecord, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_create_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.hosts,
            &request.exclude_hosts,
            &request.reverse_lookup_only,
            &request.reverse_lookup_unify,
            &request.comment,
            &port_list_internal_id,
            &request.alive_test,
            &request.allow_simultaneous_ips,
        ],
        "create target metadata",
    )
    .await?;
    Ok(TargetWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_target_clone_transaction(
    tx: &Transaction<'_>,
    source_internal_id: i32,
    owner_id: i32,
    request: &ValidatedTargetClone,
) -> Result<TargetWriteRecord, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_clone_metadata_sql(),
        &[
            &source_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone target metadata",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_login_data_sql(),
        &[&source_internal_id, &record.internal_id],
        "clone target credential references",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_tags_sql(),
        &[&source_internal_id, &record.internal_id, &record.uuid],
        "clone target tag links",
    )
    .await?;
    Ok(TargetWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_target_trash_transaction(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_trash_insert_sql(),
        &[&target_internal_id],
        "move target metadata to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_login_data_insert_sql(),
        &[&record.internal_id, &target_internal_id],
        "move target credential references to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_task_relink_sql(),
        &[&record.internal_id, &target_internal_id],
        "relink trash tasks to trashed target",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_tag_locations_to_trash_sql(),
        &[&record.internal_id, &target_internal_id],
        "move target tag links to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &target_internal_id],
        "move trashed tag links to target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_login_data_sql(),
        &[&target_internal_id],
        "delete live target credential references after trash move",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_metadata_sql(),
        &[&target_internal_id],
        "delete live target after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_target_restore_transaction(
    tx: &Transaction<'_>,
    trash_target_internal_id: i32,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_restore_metadata_sql(),
        &[&trash_target_internal_id],
        "restore target metadata from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_restore_login_data_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore target credential references from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_restore_task_relink_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "relink trash tasks to restored target",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_tag_locations_to_live_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore target tag links from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_locations_to_live_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore trashed tag links from target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_login_data_sql(),
        &[&trash_target_internal_id],
        "delete target trash credential references after restore",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_metadata_sql(),
        &[&trash_target_internal_id],
        "delete target trash metadata after restore",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_target_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_target_internal_id: i32,
) -> Result<(), ApiError> {
    execute_target_write_sql(
        tx,
        target_trash_tag_delete_sql(),
        &[&trash_target_internal_id],
        "delete target trash tag links",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_trash_delete_sql(),
        &[&trash_target_internal_id],
        "delete trashed tag links to target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_login_data_sql(),
        &[&trash_target_internal_id],
        "delete target trash credential references for hard delete",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_metadata_sql(),
        &[&trash_target_internal_id],
        "delete target trash metadata for hard delete",
    )
    .await?;
    Ok(())
}
