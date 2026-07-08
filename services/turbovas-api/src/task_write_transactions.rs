// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    task_write_db::{TaskWriteRecord, execute_task_write_sql, query_task_write_record},
    task_write_sql::*,
    task_write_validation::ValidatedTaskPatch,
};

pub(crate) async fn execute_task_patch_transaction(
    tx: &Transaction<'_>,
    task_internal_id: i32,
    request: &ValidatedTaskPatch,
) -> Result<TaskWriteRecord, ApiError> {
    query_task_write_record(
        tx,
        task_update_metadata_sql(),
        &[&task_internal_id, &request.name, &request.comment],
        "update task metadata",
    )
    .await
}

pub(crate) async fn execute_task_trash_transaction(
    tx: &Transaction<'_>,
    task_internal_id: i32,
) -> Result<TaskWriteRecord, ApiError> {
    for (sql, action) in [
        (
            task_trash_task_tag_locations_sql(),
            "move task tag links to trash location",
        ),
        (
            task_trash_task_trash_tag_locations_sql(),
            "move trashed task tag links to trash location",
        ),
        (
            task_trash_report_tag_locations_sql(),
            "move report tag links to trash location",
        ),
        (
            task_trash_report_trash_tag_locations_sql(),
            "move trashed report tag links to trash location",
        ),
        (
            task_trash_result_tag_locations_sql(),
            "move result tag links to trash location",
        ),
        (
            task_trash_result_trash_tag_locations_sql(),
            "move trashed result tag links to trash location",
        ),
        (
            task_trash_results_insert_sql(),
            "copy live results to trash",
        ),
        (
            task_delete_live_results_sql(),
            "delete live results after trash move",
        ),
        (
            task_delete_report_counts_sql(),
            "delete report counts after task trash move",
        ),
    ] {
        execute_task_write_sql(tx, sql, &[&task_internal_id], action).await?;
    }

    query_task_write_record(
        tx,
        task_mark_hidden_trash_sql(),
        &[&task_internal_id],
        "mark task as trash",
    )
    .await
}
