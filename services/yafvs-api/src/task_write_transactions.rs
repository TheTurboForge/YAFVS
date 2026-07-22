// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    task_status::TaskStatus,
    task_write_db::{
        TaskWriteRecord, TaskWriteRecordWithInternalId, execute_task_write_sql,
        query_task_write_record, query_task_write_record_with_internal_id,
    },
    task_write_sql::*,
    task_write_validation::{ValidatedTaskCreate, ValidatedTaskPatch, ValidatedTaskReplace},
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
    tag_internal_id: Option<i32>,
    request: &ValidatedTaskCreate,
) -> Result<TaskWriteRecordWithInternalId, ApiError> {
    let new_status = TaskStatus::New.as_i32();
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
            &request.schedule_periods,
            &new_status,
        ],
        "create task metadata",
    )
    .await?;
    for (name, value) in [
        ("in_assets", "yes"),
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
    for (name, value) in task_mutable_preference_values(
        request.apply_overrides,
        request.max_checks,
        request.max_hosts,
        request.min_qod,
        &request.hosts_ordering,
    ) {
        execute_task_write_sql(
            tx,
            task_insert_preference_sql(),
            &[&record.internal_id, &name, &value],
            "create task preference",
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
    if let Some(tag_internal_id) = tag_internal_id {
        execute_task_write_sql(
            tx,
            task_insert_tag_resource_sql(),
            &[&tag_internal_id, &record.internal_id, &record.uuid],
            "attach task tag",
        )
        .await?;
    }
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_task_replace_transaction(
    tx: &Transaction<'_>,
    task_internal_id: i32,
    target_internal_id: i32,
    config_internal_id: i32,
    scanner_internal_id: i32,
    schedule_internal_id: i32,
    schedule_next_time: i32,
    alert_internal_ids: &[i32],
    request: &ValidatedTaskReplace,
) -> Result<TaskWriteRecord, ApiError> {
    let record = query_task_write_record(
        tx,
        task_replace_configuration_sql(),
        &[
            &task_internal_id,
            &request.name,
            &request.comment,
            &target_internal_id,
            &config_internal_id,
            &scanner_internal_id,
            &schedule_internal_id,
            &schedule_next_time,
            &request.schedule_periods,
        ],
        "replace task configuration",
    )
    .await?;
    execute_task_write_sql(
        tx,
        task_delete_alerts_sql(),
        &[&task_internal_id],
        "replace task alerts",
    )
    .await?;
    for alert_internal_id in alert_internal_ids {
        execute_task_write_sql(
            tx,
            task_insert_alert_sql(),
            &[&task_internal_id, alert_internal_id],
            "attach replacement task alert",
        )
        .await?;
    }
    execute_task_write_sql(
        tx,
        task_delete_managed_preferences_sql(),
        &[&task_internal_id],
        "replace task preferences",
    )
    .await?;
    for (name, value) in task_mutable_preference_values(
        request.apply_overrides,
        request.max_checks,
        request.max_hosts,
        request.min_qod,
        &request.hosts_ordering,
    ) {
        execute_task_write_sql(
            tx,
            task_insert_preference_sql(),
            &[&task_internal_id, &name, &value],
            "write replacement task preference",
        )
        .await?;
    }
    Ok(record)
}

fn task_mutable_preference_values(
    apply_overrides: bool,
    max_checks: i32,
    max_hosts: i32,
    min_qod: i32,
    hosts_ordering: &str,
) -> [(&'static str, String); 5] {
    [
        (
            "assets_apply_overrides",
            if apply_overrides { "yes" } else { "no" }.to_string(),
        ),
        ("assets_min_qod", min_qod.to_string()),
        ("max_checks", max_checks.to_string()),
        ("max_hosts", max_hosts.to_string()),
        ("hosts_ordering", hosts_ordering.to_string()),
    ]
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
