// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    host_write_db::{
        HostWriteRecord, execute_host_write_sql, query_host_create_record, query_host_write_record,
    },
    host_write_sql::{
        host_create_ip_identifier_sql, host_create_sql, host_delete_details_sql,
        host_delete_host_sql, host_delete_identifier_sql, host_delete_identifiers_sql,
        host_delete_max_severities_sql, host_delete_operating_system_links_sql,
        host_delete_tags_sql, host_update_comment_sql,
    },
    host_write_validation::{ValidatedHostCreate, ValidatedHostPatch},
};

pub(crate) async fn execute_host_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    operator_uuid: &str,
    request: &ValidatedHostCreate,
) -> Result<HostWriteRecord, ApiError> {
    let record = query_host_create_record(
        tx,
        host_create_sql(),
        &[&owner_id, &request.name, &request.comment],
        "create host row",
    )
    .await?;
    execute_host_write_sql(
        tx,
        host_create_ip_identifier_sql(),
        &[
            &record.internal_id,
            &owner_id,
            &request.name,
            &operator_uuid,
        ],
        "create host ip identifier",
    )
    .await?;
    Ok(HostWriteRecord { uuid: record.uuid })
}

pub(crate) async fn execute_host_patch_transaction(
    tx: &Transaction<'_>,
    host_internal_id: i32,
    request: &ValidatedHostPatch,
) -> Result<HostWriteRecord, ApiError> {
    query_host_write_record(
        tx,
        host_update_comment_sql(),
        &[&host_internal_id, &request.comment],
        "patch host comment",
    )
    .await
}

pub(crate) async fn execute_host_delete_transaction(
    tx: &Transaction<'_>,
    host_internal_id: i32,
) -> Result<(), ApiError> {
    for (sql, action) in [
        (host_delete_identifiers_sql(), "delete host identifiers"),
        (
            host_delete_operating_system_links_sql(),
            "delete host operating system links",
        ),
        (
            host_delete_max_severities_sql(),
            "delete host severity state",
        ),
        (host_delete_details_sql(), "delete host details"),
        (host_delete_host_sql(), "delete host row"),
        (host_delete_tags_sql(), "delete host tag links"),
    ] {
        execute_host_write_sql(tx, sql, &[&host_internal_id], action).await?;
    }
    Ok(())
}

pub(crate) async fn execute_host_identifier_delete_transaction(
    tx: &Transaction<'_>,
    identifier_internal_id: i32,
) -> Result<(), ApiError> {
    execute_host_write_sql(
        tx,
        host_delete_identifier_sql(),
        &[&identifier_internal_id],
        "delete host identifier",
    )
    .await?;
    Ok(())
}
