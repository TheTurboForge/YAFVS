// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    errors::ApiError,
    scope_write_db::{ScopeWriteRecord, map_scope_write_db_error},
    scope_write_sql::*,
    scope_write_validation::{ValidatedScopeCreate, ValidatedScopePatch},
};

pub(crate) async fn execute_scope_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedScopeCreate,
) -> Result<ScopeWriteRecord, ApiError> {
    let record = query_scope_write_record(
        tx,
        scope_insert_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.protection_requirement,
        ],
        "insert scope",
    )
    .await?;
    replace_scope_membership(
        tx,
        record.internal_id,
        &request.target_ids,
        scope_delete_targets_sql(),
        scope_insert_target_sql(),
        "target_ids",
    )
    .await?;
    replace_scope_membership(
        tx,
        record.internal_id,
        &request.host_ids,
        scope_delete_hosts_sql(),
        scope_insert_host_sql(),
        "host_ids",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scope_patch_transaction(
    tx: &Transaction<'_>,
    scope_internal_id: i32,
    request: &ValidatedScopePatch,
) -> Result<ScopeWriteRecord, ApiError> {
    let record = if request.name.is_some()
        || request.comment.is_some()
        || request.protection_requirement.is_some()
    {
        query_scope_write_record(
            tx,
            scope_update_metadata_sql(),
            &[
                &scope_internal_id,
                &request.name,
                &request.comment,
                &request.protection_requirement,
            ],
            "update scope metadata",
        )
        .await?
    } else {
        query_scope_write_record(
            tx,
            scope_by_internal_id_sql(),
            &[&scope_internal_id],
            "load scope after membership-only patch",
        )
        .await?
    };

    if let Some(target_ids) = request.target_ids.as_ref() {
        replace_scope_membership(
            tx,
            record.internal_id,
            target_ids,
            scope_delete_targets_sql(),
            scope_insert_target_sql(),
            "target_ids",
        )
        .await?;
    }
    if let Some(host_ids) = request.host_ids.as_ref() {
        replace_scope_membership(
            tx,
            record.internal_id,
            host_ids,
            scope_delete_hosts_sql(),
            scope_insert_host_sql(),
            "host_ids",
        )
        .await?;
    }
    Ok(record)
}

pub(crate) async fn execute_scope_delete_transaction(
    tx: &Transaction<'_>,
    scope_internal_id: i32,
) -> Result<(), ApiError> {
    execute_scope_write_sql(
        tx,
        scope_delete_targets_sql(),
        &[&scope_internal_id],
        "delete scope target membership",
    )
    .await?;
    execute_scope_write_sql(
        tx,
        scope_delete_hosts_sql(),
        &[&scope_internal_id],
        "delete scope host membership",
    )
    .await?;
    let deleted = execute_scope_write_sql(
        tx,
        scope_delete_sql(),
        &[&scope_internal_id],
        "delete scope",
    )
    .await?;
    if deleted == 0 {
        Err(ApiError::NotFound)
    } else {
        Ok(())
    }
}

async fn query_scope_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScopeWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))?
        .map(|row| scope_write_record_from_row(&row))
        .ok_or(ApiError::NotFound)
}

async fn execute_scope_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))
}

async fn replace_scope_membership(
    tx: &Transaction<'_>,
    scope_internal_id: i32,
    requested_ids: &[String],
    delete_sql: &str,
    insert_sql: &str,
    field_name: &'static str,
) -> Result<(), ApiError> {
    execute_scope_write_sql(
        tx,
        delete_sql,
        &[&scope_internal_id],
        "delete scope membership",
    )
    .await?;
    for requested_id in requested_ids {
        let inserted = execute_scope_write_sql(
            tx,
            insert_sql,
            &[&scope_internal_id, requested_id],
            "insert scope membership",
        )
        .await?;
        if inserted == 0 {
            tracing::warn!(
                field = field_name,
                "scope write reference disappeared before insert"
            );
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

fn scope_write_record_from_row(row: &Row) -> ScopeWriteRecord {
    ScopeWriteRecord {
        internal_id: row.get(0),
        uuid: row.get(1),
    }
}
