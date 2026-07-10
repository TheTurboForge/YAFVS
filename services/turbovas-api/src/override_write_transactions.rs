// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    override_write_db::{
        OverrideTrashRecord, OverrideWriteState, execute_override_write_sql,
        load_override_affected_reports, query_override_trash_record,
    },
    override_write_sql::*,
};

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
