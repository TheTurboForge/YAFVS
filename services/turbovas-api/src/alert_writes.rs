// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};

use crate::{
    alert_payloads::AlertAssetItem,
    alert_write_db::*,
    alert_write_transactions::execute_alert_patch_transaction,
    alert_write_validation::{AlertPatchRequest, validate_alert_patch_request},
    alerts::load_alert_asset_detail,
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
};

pub(crate) async fn patch_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<AlertPatchRequest>,
) -> Result<Json<AlertAssetItem>, ApiError> {
    let operator = require_alert_write_operator(operator)?;
    let request = validate_alert_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_alert_write_db_error(error, "begin patch alert transaction"))?;
    let operator_owner_id = resolve_alert_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE alerts IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_alert_write_db_error(error, "lock alerts for patch"))?;
    let alert_state = load_alert_write_state(&tx, &alert_id).await?;
    ensure_alert_owner_matches_operator(alert_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_alert_name(&tx, name, alert_state.internal_id).await?;
    }
    let record = execute_alert_patch_transaction(&tx, alert_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_alert_write_db_error(error, "commit patch alert transaction"))?;

    Ok(Json(load_alert_asset_detail(&client, &record.uuid).await?))
}
