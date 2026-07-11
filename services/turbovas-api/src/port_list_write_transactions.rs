// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    port_list_write_db::{
        PortListTrashWriteRecord, PortListWriteRecord, execute_port_list_write_sql,
        query_port_list_trash_write_record, query_port_list_write_record,
    },
    port_list_write_sql::*,
    port_list_write_validation::{
        ValidatedPortListClone, ValidatedPortListCreate, ValidatedPortListCreateRange,
        ValidatedPortListPatch,
    },
};

pub(crate) async fn execute_port_list_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedPortListCreate,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_write_record(
        tx,
        port_list_create_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.imported_id,
        ],
        "insert port list metadata",
    )
    .await?;
    for range in &request.port_ranges {
        execute_port_list_write_sql(
            tx,
            port_list_create_range_sql(),
            &[
                &record.internal_id,
                &range.protocol_id,
                &range.start,
                &range.end,
                &range.comment,
            ],
            "insert port list range",
        )
        .await?;
    }
    Ok(record)
}

pub(crate) async fn execute_port_list_range_create_transaction(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
    range: &ValidatedPortListCreateRange,
) -> Result<(), ApiError> {
    execute_port_list_write_sql(
        tx,
        port_list_create_range_sql(),
        &[
            &port_list_internal_id,
            &range.protocol_id,
            &range.start,
            &range.end,
            &range.comment,
        ],
        "insert port list range",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_port_list_range_delete_transaction(
    tx: &Transaction<'_>,
    port_range_internal_id: i32,
) -> Result<(), ApiError> {
    execute_port_list_write_sql(
        tx,
        port_list_delete_range_sql(),
        &[&port_range_internal_id],
        "delete port list range",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_port_list_patch_transaction(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
    request: &ValidatedPortListPatch,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_write_record(
        tx,
        port_list_update_metadata_sql(),
        &[&port_list_internal_id, &request.name, &request.comment],
        "update port list metadata",
    )
    .await?;
    if let Some(ranges) = request.port_ranges.as_ref() {
        execute_port_list_write_sql(
            tx,
            port_list_delete_ranges_sql(),
            &[&port_list_internal_id],
            "delete existing port list ranges before replacement",
        )
        .await?;
        for range in ranges {
            execute_port_list_write_sql(
                tx,
                port_list_create_range_sql(),
                &[
                    &port_list_internal_id,
                    &range.protocol_id,
                    &range.start,
                    &range.end,
                    &range.comment,
                ],
                "insert replacement port list range",
            )
            .await?;
        }
    }
    Ok(record)
}

pub(crate) async fn execute_port_list_trash_transaction(
    tx: &Transaction<'_>,
    port_list_internal_id: i32,
) -> Result<PortListTrashWriteRecord, ApiError> {
    let record = query_port_list_trash_write_record(
        tx,
        port_list_trash_insert_sql(),
        &[&port_list_internal_id],
        "move port list metadata to trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_ranges_insert_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "move port list ranges to trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_target_relink_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "relink trash targets to trashed port list",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_tag_locations_to_trash_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "move live port list tag links to trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &port_list_internal_id],
        "move trashed tag links to port list trash id",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_ranges_sql(),
        &[&port_list_internal_id],
        "delete live port list ranges after trash move",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_metadata_sql(),
        &[&port_list_internal_id],
        "delete live port list after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_port_list_clone_transaction(
    tx: &Transaction<'_>,
    source_port_list_internal_id: i32,
    owner_id: i32,
    request: &ValidatedPortListClone,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_write_record(
        tx,
        port_list_clone_metadata_sql(),
        &[
            &source_port_list_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone port list metadata",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_clone_ranges_sql(),
        &[&source_port_list_internal_id, &record.internal_id],
        "clone port list ranges",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_clone_tags_sql(),
        &[
            &source_port_list_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone port list tags",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_port_list_restore_transaction(
    tx: &Transaction<'_>,
    trash_port_list_internal_id: i32,
) -> Result<PortListWriteRecord, ApiError> {
    let record = query_port_list_trash_write_record(
        tx,
        port_list_restore_metadata_sql(),
        &[&trash_port_list_internal_id],
        "restore port list metadata from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_restore_ranges_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "restore port list ranges from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_restore_target_relink_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "relink trash targets to restored port list",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_tag_locations_to_live_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "restore live tag links from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_locations_to_live_sql(),
        &[&trash_port_list_internal_id, &record.internal_id],
        "restore trashed tag links from trash",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_ranges_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash ranges after restore",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_metadata_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash metadata after restore",
    )
    .await?;
    Ok(PortListWriteRecord {
        internal_id: record.internal_id,
        uuid: record.uuid,
    })
}

pub(crate) async fn execute_port_list_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_port_list_internal_id: i32,
) -> Result<(), ApiError> {
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_delete_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash tag links",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_trash_tag_trash_delete_sql(),
        &[&trash_port_list_internal_id],
        "delete trashed tag links to port list trash id",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_ranges_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash ranges for hard delete",
    )
    .await?;
    execute_port_list_write_sql(
        tx,
        port_list_delete_trash_metadata_sql(),
        &[&trash_port_list_internal_id],
        "delete port list trash metadata for hard delete",
    )
    .await?;
    Ok(())
}
