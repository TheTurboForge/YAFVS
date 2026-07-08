// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    report_format_payloads::ReportFormatAssetItem,
    report_format_write_db::*,
    report_format_write_transactions::execute_report_format_patch_transaction,
    report_format_write_validation::{
        ReportFormatPatchRequest, validate_report_format_patch_request,
    },
    report_formats::load_report_format_asset_detail,
};

pub(crate) async fn patch_report_format(
    State(state): State<AppState>,
    Path(report_format_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ReportFormatPatchRequest>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    let operator = require_report_format_write_operator(operator)?;
    let request = validate_report_format_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_format_write_db_error(error, "begin patch report format transaction")
    })?;
    let operator_owner_id = resolve_report_format_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_formats IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_format_write_db_error(error, "lock report formats for patch")
        })?;
    let state = load_report_format_write_state(&tx, &report_format_id).await?;
    ensure_report_format_metadata_patch_allowed(&state, operator_owner_id)?;
    let record = execute_report_format_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_report_format_write_db_error(error, "commit patch report format transaction")
    })?;

    Ok(Json(
        load_report_format_asset_detail(&client, &record.uuid).await?,
    ))
}
