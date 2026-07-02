// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    scan_config_write_db::{
        ScanConfigWriteRecord, execute_scan_config_write_sql, query_scan_config_write_record,
    },
    scan_config_write_sql::*,
    scan_config_write_validation::{
        ValidatedScanConfigClone, ValidatedScanConfigCreate, ValidatedScanConfigPatch,
    },
};

pub(crate) async fn execute_scan_config_create_from_base_transaction(
    tx: &Transaction<'_>,
    source_scan_config_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScanConfigCreate,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_create_from_base_metadata_sql(),
        &[
            &source_scan_config_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "create scan-config metadata from base",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_preferences_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "create scan-config preferences from base",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_selectors_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "create scan-config selectors from base",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_tags_sql(),
        &[
            &source_scan_config_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "create scan-config tag links from base",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_clone_transaction(
    tx: &Transaction<'_>,
    source_scan_config_internal_id: i32,
    owner_id: i32,
    request: &ValidatedScanConfigClone,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_clone_metadata_sql(),
        &[
            &source_scan_config_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone scan-config metadata",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_preferences_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "clone scan-config preferences",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_selectors_sql(),
        &[&source_scan_config_internal_id, &record.internal_id],
        "clone scan-config selectors",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_clone_tags_sql(),
        &[
            &source_scan_config_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone scan-config tags",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_metadata_patch_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    request: &ValidatedScanConfigPatch,
) -> Result<ScanConfigWriteRecord, ApiError> {
    query_scan_config_write_record(
        tx,
        scan_config_update_metadata_sql(),
        &[&scan_config_internal_id, &request.name, &request.comment],
        "update scan-config metadata",
    )
    .await
}

pub(crate) async fn execute_scan_config_trash_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_trash_insert_sql(),
        &[&scan_config_internal_id],
        "move scan-config metadata to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_preferences_trash_insert_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move scan-config preferences to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_task_relink_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "relink tasks to trashed scan config",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move live scan-config tag links to trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &scan_config_internal_id],
        "move trashed tag links to scan-config trash id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_preferences_sql(),
        &[&scan_config_internal_id],
        "delete live scan-config preferences after trash move",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_metadata_sql(),
        &[&scan_config_internal_id],
        "delete live scan config after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scan_config_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_scan_config_internal_id: i32,
) -> Result<(), ApiError> {
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_delete_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash tag links",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_trash_delete_sql(),
        &[&trash_scan_config_internal_id],
        "delete trashed tag links to scan-config trash id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_selector_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash NVT selector for hard delete",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_preferences_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash preferences for hard delete",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_scan_config_restore_transaction(
    tx: &Transaction<'_>,
    trash_scan_config_internal_id: i32,
) -> Result<ScanConfigWriteRecord, ApiError> {
    let record = query_scan_config_write_record(
        tx,
        scan_config_restore_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "restore scan-config metadata from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_preferences_restore_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore scan-config preferences from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_task_relink_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "relink trash tasks to restored scan config",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_tag_locations_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore live scan-config tag links from trash",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_trash_tag_locations_to_live_sql(),
        &[&trash_scan_config_internal_id, &record.internal_id],
        "restore trashed tag links to scan-config live id",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_preferences_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash preferences after restore",
    )
    .await?;
    execute_scan_config_write_sql(
        tx,
        scan_config_delete_trash_metadata_sql(),
        &[&trash_scan_config_internal_id],
        "delete scan-config trash metadata after restore",
    )
    .await?;
    Ok(record)
}
