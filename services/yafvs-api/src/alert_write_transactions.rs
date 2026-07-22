// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    alert_write_db::{AlertWriteRecord, execute_alert_write_sql, query_alert_write_record},
    alert_write_sql::*,
    alert_write_validation::{ValidatedAlertClone, ValidatedAlertPatch},
    errors::ApiError,
};

pub(crate) async fn execute_alert_patch_transaction(
    tx: &Transaction<'_>,
    alert_internal_id: i32,
    request: &ValidatedAlertPatch,
) -> Result<AlertWriteRecord, ApiError> {
    query_alert_write_record(
        tx,
        alert_update_metadata_sql(),
        &[&alert_internal_id, &request.name, &request.comment],
        "update alert metadata",
    )
    .await
}

pub(crate) async fn execute_alert_clone_transaction(
    tx: &Transaction<'_>,
    source_alert_internal_id: i32,
    owner_id: i32,
    request: &ValidatedAlertClone,
) -> Result<AlertWriteRecord, ApiError> {
    let record = query_alert_write_record(
        tx,
        alert_clone_metadata_sql(),
        &[
            &source_alert_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone alert metadata",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_clone_condition_data_sql(),
        &[&source_alert_internal_id, &record.internal_id],
        "clone alert condition data",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_clone_event_data_sql(),
        &[&source_alert_internal_id, &record.internal_id],
        "clone alert event data",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_clone_method_data_sql(),
        &[&source_alert_internal_id, &record.internal_id],
        "clone alert method data",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_clone_tags_sql(),
        &[&source_alert_internal_id, &record.internal_id, &record.uuid],
        "clone alert tags",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_alert_trash_transaction(
    tx: &Transaction<'_>,
    alert_internal_id: i32,
) -> Result<AlertWriteRecord, ApiError> {
    let record = query_alert_write_record(
        tx,
        alert_trash_insert_sql(),
        &[&alert_internal_id],
        "move alert metadata to trash",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_condition_data_trash_insert_sql(),
        &[&record.internal_id, &alert_internal_id],
        "move alert condition data to trash",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_event_data_trash_insert_sql(),
        &[&record.internal_id, &alert_internal_id],
        "move alert event data to trash",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_method_data_trash_insert_sql(),
        &[&record.internal_id, &alert_internal_id],
        "move alert method data to trash",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_task_relink_to_trash_sql(),
        &[&record.internal_id, &alert_internal_id],
        "relink tasks to trashed alert",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_tag_locations_to_trash_sql(),
        &[&record.internal_id, &alert_internal_id],
        "move live alert tag links to trash",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &alert_internal_id],
        "move trashed tag links to alert trash id",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_delete_condition_data_sql(),
        &[&alert_internal_id],
        "delete live alert condition data after trash move",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_delete_event_data_sql(),
        &[&alert_internal_id],
        "delete live alert event data after trash move",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_delete_method_data_sql(),
        &[&alert_internal_id],
        "delete live alert method data after trash move",
    )
    .await?;
    execute_alert_write_sql(
        tx,
        alert_delete_metadata_sql(),
        &[&alert_internal_id],
        "delete live alert metadata after trash move",
    )
    .await?;
    Ok(record)
}
