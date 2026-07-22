// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeSet;

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    override_write_db::{
        OverrideTrashRecord, OverrideWriteRecord, OverrideWriteState, execute_override_write_sql,
        load_override_affected_reports, query_override_trash_record, query_override_write_record,
    },
    override_write_sql::*,
    override_write_validation::{PatchField, ValidatedOverrideCreate, ValidatedOverridePatch},
};

pub(crate) async fn execute_override_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedOverrideCreate,
    task_id: i32,
    result_id: i32,
) -> Result<OverrideWriteRecord, ApiError> {
    let record = query_override_write_record(
        tx,
        override_insert_sql(),
        &[
            &owner_id,
            &request.nvt_id,
            &request.text,
            &request.hosts,
            &request.port,
            &request.severity,
            &request.new_severity,
            &task_id,
            &result_id,
            &request.active_days,
        ],
        "create override metadata",
    )
    .await?;
    let state = OverrideWriteState {
        internal_id: record.internal_id,
        owner_id: Some(owner_id),
        nvt: request.nvt_id.clone(),
        task_id,
        result_id,
    };
    clear_override_report_count_caches(tx, load_override_affected_reports(tx, &state).await?)
        .await?;
    Ok(record)
}

pub(crate) async fn execute_override_restore_transaction(
    tx: &Transaction<'_>,
    trash: &OverrideWriteState,
) -> Result<OverrideWriteRecord, ApiError> {
    let record = query_override_write_record(
        tx,
        override_restore_sql(),
        &[&trash.internal_id],
        "restore override metadata",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_tag_locations_to_live_sql(),
        &[&trash.internal_id, &record.internal_id],
        "restore override tag links",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_trash_tag_locations_to_live_sql(),
        &[&trash.internal_id, &record.internal_id],
        "restore trashed override tag links",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_delete_trash_sql(),
        &[&trash.internal_id],
        "delete restored override trash metadata",
    )
    .await?;
    let restored_state = OverrideWriteState {
        internal_id: record.internal_id,
        owner_id: trash.owner_id,
        nvt: trash.nvt.clone(),
        task_id: trash.task_id,
        result_id: trash.result_id,
    };
    clear_override_report_count_caches(
        tx,
        load_override_affected_reports(tx, &restored_state).await?,
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_override_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_internal_id: i32,
) -> Result<(), ApiError> {
    execute_override_write_sql(
        tx,
        override_delete_trash_tags_sql(),
        &[&trash_internal_id],
        "delete override trash tag links",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_delete_trash_trash_tags_sql(),
        &[&trash_internal_id],
        "delete override trashed tag links",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_delete_trash_sql(),
        &[&trash_internal_id],
        "hard-delete override trash metadata",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_override_patch_transaction(
    tx: &Transaction<'_>,
    state: &OverrideWriteState,
    request: &ValidatedOverridePatch,
    final_task_id: i32,
    final_result_id: i32,
) -> Result<OverrideWriteRecord, ApiError> {
    let old_reports = load_override_affected_reports(tx, state).await?;
    let nvt_set = request.nvt_id.is_some();
    let nvt = request.nvt_id.as_deref();
    let text_set = request.text.is_some();
    let text = request.text.as_deref();
    let (hosts_set, hosts) = string_patch_parts(&request.hosts);
    let (port_set, port) = string_patch_parts(&request.port);
    let (severity_set, severity) = float_patch_parts(&request.severity);
    let new_severity_set = request.new_severity.is_some();
    let task_set = request.task_id != PatchField::Missing;
    let result_set = request.result_id != PatchField::Missing;
    let active_set = request.active_days.is_some();
    let active_days = request.active_days.unwrap_or(-1);
    let record = query_override_write_record(
        tx,
        override_patch_sql(),
        &[
            &state.internal_id,
            &nvt_set,
            &nvt,
            &text_set,
            &text,
            &hosts_set,
            &hosts,
            &port_set,
            &port,
            &severity_set,
            &severity,
            &new_severity_set,
            &request.new_severity,
            &task_set,
            &final_task_id,
            &result_set,
            &final_result_id,
            &active_set,
            &active_days,
        ],
        "patch override metadata",
    )
    .await?;
    let new_state = OverrideWriteState {
        internal_id: record.internal_id,
        owner_id: state.owner_id,
        nvt: request.nvt_id.clone().unwrap_or_else(|| state.nvt.clone()),
        task_id: final_task_id,
        result_id: final_result_id,
    };
    let mut affected_reports: BTreeSet<i32> = old_reports.into_iter().collect();
    affected_reports.extend(load_override_affected_reports(tx, &new_state).await?);
    clear_override_report_count_caches(tx, affected_reports.into_iter().collect()).await?;
    Ok(record)
}

pub(crate) async fn execute_override_clone_transaction(
    tx: &Transaction<'_>,
    source: &OverrideWriteState,
    owner_id: i32,
) -> Result<OverrideWriteRecord, ApiError> {
    let record = query_override_write_record(
        tx,
        override_clone_sql(),
        &[&source.internal_id, &owner_id],
        "clone override metadata",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_clone_tags_sql(),
        &[&source.internal_id, &record.internal_id, &record.uuid],
        "clone override tag links",
    )
    .await?;
    let state = OverrideWriteState {
        internal_id: record.internal_id,
        owner_id: Some(owner_id),
        nvt: source.nvt.clone(),
        task_id: source.task_id,
        result_id: source.result_id,
    };
    clear_override_report_count_caches(tx, load_override_affected_reports(tx, &state).await?)
        .await?;
    Ok(record)
}

pub(crate) async fn execute_override_trash_transaction(
    tx: &Transaction<'_>,
    state: &OverrideWriteState,
) -> Result<(OverrideTrashRecord, usize), ApiError> {
    let affected_reports = load_override_affected_reports(tx, state).await?;
    let record = query_override_trash_record(tx, state.internal_id).await?;
    execute_override_write_sql(
        tx,
        override_tag_locations_to_trash_sql(),
        &[&record.internal_id, &state.internal_id],
        "move live override tag links to trash",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &state.internal_id],
        "move trashed tag links to override trash id",
    )
    .await?;
    execute_override_write_sql(
        tx,
        override_delete_live_sql(),
        &[&state.internal_id],
        "delete live override metadata after trash move",
    )
    .await?;
    if !affected_reports.is_empty() {
        execute_override_write_sql(
            tx,
            override_clear_overridden_report_counts_sql(),
            &[&affected_reports],
            "clear affected overridden report count caches",
        )
        .await?;
    }
    let affected_count = affected_reports.len();
    Ok((record, affected_count))
}

fn string_patch_parts(value: &PatchField<String>) -> (bool, Option<&str>) {
    match value {
        PatchField::Missing => (false, None),
        PatchField::Null => (true, None),
        PatchField::Value(value) => (true, Some(value.as_str())),
    }
}

fn float_patch_parts(value: &PatchField<f64>) -> (bool, Option<f64>) {
    match value {
        PatchField::Missing => (false, None),
        PatchField::Null => (true, None),
        PatchField::Value(value) => (true, Some(*value)),
    }
}

async fn clear_override_report_count_caches(
    tx: &Transaction<'_>,
    affected_reports: Vec<i32>,
) -> Result<(), ApiError> {
    if !affected_reports.is_empty() {
        execute_override_write_sql(
            tx,
            override_clear_overridden_report_counts_sql(),
            &[&affected_reports],
            "clear affected overridden report count caches",
        )
        .await?;
    }
    Ok(())
}
