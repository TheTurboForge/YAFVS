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
    credential_payloads::CredentialAssetItem,
    credential_write_db::*,
    credential_write_transactions::execute_credential_patch_transaction,
    credential_write_validation::{CredentialPatchRequest, validate_credential_patch_request},
    credentials::load_credential_asset_detail,
    errors::ApiError,
};

pub(crate) async fn patch_credential(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<CredentialPatchRequest>,
) -> Result<Json<CredentialAssetItem>, ApiError> {
    let operator = require_credential_write_operator(operator)?;
    let request = validate_credential_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_credential_write_db_error(error, "begin patch credential transaction")
    })?;
    let operator_owner_id = resolve_credential_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE credentials IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_credential_write_db_error(error, "lock credentials for patch"))?;
    let credential_state = load_credential_write_state(&tx, &credential_id).await?;
    ensure_credential_owner_matches_operator(credential_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_credential_name(
            &tx,
            name,
            credential_state.internal_id,
            credential_state.owner_id,
        )
        .await?;
    }
    let record =
        execute_credential_patch_transaction(&tx, credential_state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_credential_write_db_error(error, "commit patch credential transaction")
    })?;

    Ok(Json(
        load_credential_asset_detail(&client, &record.uuid).await?,
    ))
}
