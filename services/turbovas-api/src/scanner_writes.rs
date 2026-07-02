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
    scanner_asset_payloads::ScannerAssetDetail,
    scanner_assets::scanner_asset_detail,
    scanner_write_db::*,
    scanner_write_transactions::execute_scanner_patch_transaction,
    scanner_write_validation::{ScannerPatchRequest, validate_scanner_patch_request},
};

pub(crate) async fn patch_scanner(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScannerPatchRequest>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let request = validate_scanner_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "begin patch scanner transaction"))?;
    let operator_owner_id = resolve_scanner_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE scanners IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_scanner_write_db_error(error, "lock scanners for patch"))?;
    let scanner_state = load_scanner_write_state(&tx, &scanner_id).await?;
    ensure_scanner_metadata_patch_allowed(&scanner_state, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scanner_name(&tx, name, scanner_state.internal_id).await?;
    }
    let record =
        execute_scanner_patch_transaction(&tx, scanner_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit patch scanner transaction"))?;

    scanner_asset_detail(State(state), Path(record.uuid)).await
}
