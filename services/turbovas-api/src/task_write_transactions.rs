// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    task_write_db::{
        TaskWriteRecord, TaskWriteRecordWithInternalId, execute_task_write_sql,
        query_task_write_record, query_task_write_record_with_internal_id,
    },
    task_write_sql::*,
    task_write_validation::{ValidatedTaskCreate, ValidatedTaskPatch},
};

pub(crate) async fn execute_task_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    target_internal_id: i32,
    config_internal_id: i32,
    scanner_internal_id: i32,
    schedule_internal_id: i32,
    schedule_next_time: i32,
    alert_internal_ids: &[i32],
    request: &ValidatedTaskCreate,
) -> Result<TaskWriteRecordWithInternalId, ApiError> {
    let record = query_task_write_record_with_internal_id(
        tx,
        task_create_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &config_internal_id,
            &target_internal_id,
            &scanner_internal_id,
            &schedule_internal_id,
            &schedule_next_time,
        ],
        "create task metadata",
    )
    .await?;
    for (name, value) in [
        ("in_assets", "yes"),
        ("assets_apply_overrides", "yes"),
        ("assets_min_qod", "70"),
        ("auto_delete", "keep"),
        ("auto_delete_data", "10"),
    ] {
        execute_task_write_sql(
            tx,
            task_insert_preference_sql(),
            &[&record.internal_id, &name, &value],
            "create task default preference",
        )
        .await?;
    }
    if let Some(hosts_ordering) = request.hosts_ordering.as_deref() {
        execute_task_write_sql(
            tx,
            task_insert_preference_sql(),
            &[&record.internal_id, &"hosts_ordering", &hosts_ordering],
            "create task host ordering preference",
        )
        .await?;
    }
    for alert_internal_id in alert_internal_ids {
        execute_task_write_sql(
            tx,
            task_insert_alert_sql(),
            &[&record.internal_id, alert_internal_id],
            "attach task alert",
        )
        .await?;
    }
    Ok(record)
}

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
