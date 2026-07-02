// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    schedule_write_db::{
        ScheduleTrashWriteRecord, ScheduleWriteRecord, execute_schedule_write_sql,
        query_schedule_trash_write_record, query_schedule_write_record,
    },
    schedule_write_sql::*,
    schedule_write_validation::{ValidatedScheduleClone, ValidatedSchedulePatch},
};

pub(crate) async fn execute_schedule_trash_transaction(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
) -> Result<ScheduleTrashWriteRecord, ApiError> {
    let record = query_schedule_trash_write_record(
        tx,
        schedule_trash_insert_sql(),
        &[&schedule_internal_id],
        "move schedule metadata to trash",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_task_relink_sql(),
        &[&record.internal_id, &schedule_internal_id],
        "relink tasks to trashed schedule",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_tag_locations_to_trash_sql(),
        &[&record.internal_id, &schedule_internal_id],
        "move live schedule tag links to trash",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &schedule_internal_id],
        "move trashed tag links to schedule trash id",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_delete_metadata_sql(),
        &[&schedule_internal_id],
        "delete live schedule after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_schedule_patch_transaction(
    tx: &Transaction<'_>,
    schedule_internal_id: i32,
    request: &ValidatedSchedulePatch,
) -> Result<ScheduleWriteRecord, ApiError> {
    query_schedule_write_record(
        tx,
        schedule_update_metadata_sql(),
        &[&schedule_internal_id, &request.name, &request.comment],
        "update schedule metadata",
    )
    .await
}

pub(crate) async fn execute_schedule_clone_transaction(
    tx: &Transaction<'_>,
    source_schedule_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScheduleClone,
) -> Result<ScheduleWriteRecord, ApiError> {
    let record = query_schedule_trash_write_record(
        tx,
        schedule_clone_metadata_sql(),
        &[
            &source_schedule_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone schedule metadata",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_clone_tags_sql(),
        &[
            &source_schedule_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone schedule tags",
    )
    .await?;
    Ok(ScheduleWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_schedule_restore_transaction(
    tx: &Transaction<'_>,
    schedule_trash_internal_id: i32,
) -> Result<ScheduleWriteRecord, ApiError> {
    let record = query_schedule_trash_write_record(
        tx,
        schedule_restore_metadata_sql(),
        &[&schedule_trash_internal_id],
        "restore schedule metadata",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_task_relink_to_live_sql(),
        &[&schedule_trash_internal_id, &record.internal_id],
        "relink trash tasks to restored schedule",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_tag_locations_to_live_sql(),
        &[&schedule_trash_internal_id, &record.internal_id],
        "move schedule tag links to live",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_locations_to_live_sql(),
        &[&schedule_trash_internal_id, &record.internal_id],
        "move trashed tag links to restored schedule",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_delete_trash_metadata_sql(),
        &[&schedule_trash_internal_id],
        "delete schedule trash metadata after restore",
    )
    .await?;
    Ok(ScheduleWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_schedule_hard_delete_transaction(
    tx: &Transaction<'_>,
    schedule_trash_internal_id: i32,
) -> Result<(), ApiError> {
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_delete_sql(),
        &[&schedule_trash_internal_id],
        "delete schedule trash tag links",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_trash_tag_trash_delete_sql(),
        &[&schedule_trash_internal_id],
        "delete trashed tag links to schedule trash id",
    )
    .await?;
    execute_schedule_write_sql(
        tx,
        schedule_delete_trash_metadata_sql(),
        &[&schedule_trash_internal_id],
        "delete schedule trash metadata for hard delete",
    )
    .await?;
    Ok(())
}
