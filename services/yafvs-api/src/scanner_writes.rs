// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::{ApiError, mutation_committed_response_unavailable},
    scanner_asset_payloads::ScannerAssetDetail,
    scanner_assets::scanner_asset_detail,
    scanner_write_db::*,
    scanner_write_transactions::{
        execute_scanner_clone_transaction, execute_scanner_create_transaction,
        execute_scanner_hard_delete_transaction, execute_scanner_patch_transaction,
        execute_scanner_replace_transaction, execute_scanner_restore_transaction,
        execute_scanner_trash_transaction,
    },
    scanner_write_validation::{
        ScannerCloneRequest, ScannerConfigurationRequest, ScannerPatchRequest,
        ValidatedScannerConfiguration, validate_scanner_clone_request,
        validate_scanner_configuration_request, validate_scanner_patch_request,
    },
};

pub(crate) async fn create_scanner(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScannerConfigurationRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScannerAssetDetail>), ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let request = validate_scanner_configuration_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "begin create scanner transaction"))?;
    tx.batch_execute("LOCK TABLE users, credentials, scanners IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_scanner_write_db_error(error, "lock scanner create tables"))?;
    let owner_id = resolve_scanner_write_operator_owner(&tx, &operator).await?;
    ensure_unique_scanner_name(&tx, &request.name, -1).await?;
    let credential_internal_id = resolve_scanner_credential(&tx, &request).await?;
    let record =
        execute_scanner_create_transaction(&tx, owner_id, credential_internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit create scanner transaction"))?;
    let detail = scanner_asset_detail(State(state), Path(record.uuid.clone()))
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "create scanner response reload")
        })?;

    Ok((
        StatusCode::CREATED,
        scanner_write_location_headers(&record.uuid).map_err(|error| {
            mutation_committed_response_unavailable(error, "create scanner response header")
        })?,
        detail,
    ))
}

pub(crate) async fn clone_scanner(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScannerCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScannerAssetDetail>), ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let request = validate_scanner_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "begin clone scanner transaction"))?;
    tx.batch_execute(
        "LOCK TABLE users, scanners, scanners_trash, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scanner_write_db_error(error, "lock scanner tables for clone"))?;
    let owner_id = resolve_scanner_write_operator_owner(&tx, &operator).await?;
    let source = load_scanner_write_state(&tx, &scanner_id).await?;
    ensure_scanner_clone_source_allowed(&source)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scanner_name(&tx, name, -1).await?;
    }
    let record =
        execute_scanner_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit clone scanner transaction"))?;
    let detail = scanner_asset_detail(State(state), Path(record.uuid.clone()))
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "clone scanner response reload")
        })?;
    Ok((
        StatusCode::CREATED,
        scanner_write_location_headers(&record.uuid).map_err(|error| {
            mutation_committed_response_unavailable(error, "clone scanner response header")
        })?,
        detail,
    ))
}

pub(crate) async fn delete_scanner(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "begin delete scanner transaction"))?;
    resolve_scanner_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE scanners, scanners_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scanner_write_db_error(error, "lock scanner tables for delete"))?;
    let scanner = load_scanner_write_state(&tx, &scanner_id).await?;
    ensure_scanner_metadata_patch_allowed(&scanner)?;
    ensure_scanner_not_in_use_for_delete(&tx, scanner.internal_id).await?;
    execute_scanner_trash_transaction(&tx, scanner.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit delete scanner transaction"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_scanner(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "begin restore scanner transaction"))?;
    resolve_scanner_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE scanners, scanners_trash, credentials, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scanner_write_db_error(error, "lock scanner tables for restore"))?;
    let trash = load_scanner_trash_state(&tx, &scanner_id).await?;
    ensure_scanner_is_human_owned(trash.owner_id)?;
    ensure_scanner_uuid_not_live(&tx, &trash.uuid).await?;
    if let Some(name) = trash.name.as_ref() {
        ensure_unique_scanner_name(&tx, name, -1).await?;
    }
    ensure_trash_scanner_credential_is_live(&tx, &trash).await?;
    let record = execute_scanner_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit restore scanner transaction"))?;
    scanner_asset_detail(State(state), Path(record.uuid))
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "restore scanner response reload")
        })
}

pub(crate) async fn hard_delete_scanner(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scanner_write_db_error(error, "begin hard-delete scanner transaction")
    })?;
    resolve_scanner_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE scanners_trash, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_scanner_write_db_error(error, "lock scanner trash tables for hard delete"))?;
    let trash = load_scanner_trash_state(&tx, &scanner_id).await?;
    ensure_scanner_is_human_owned(trash.owner_id)?;
    ensure_trash_scanner_not_in_use(&tx, trash.internal_id).await?;
    execute_scanner_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_scanner_write_db_error(error, "commit hard-delete scanner transaction")
    })?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn replace_scanner_configuration(
    State(state): State<AppState>,
    Path(scanner_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScannerConfigurationRequest>,
) -> Result<Json<ScannerAssetDetail>, ApiError> {
    let operator = require_scanner_write_operator(operator)?;
    let request = validate_scanner_configuration_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "begin replace scanner transaction"))?;
    tx.batch_execute("LOCK TABLE users, credentials, scanners, tasks IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_scanner_write_db_error(error, "lock scanner replace tables"))?;
    resolve_scanner_write_operator_owner(&tx, &operator).await?;
    let scanner_state = load_scanner_write_state(&tx, &scanner_id).await?;
    ensure_scanner_metadata_patch_allowed(&scanner_state)?;
    ensure_scanner_not_in_use_for_configuration_replace(&tx, scanner_state.internal_id).await?;
    ensure_unique_scanner_name(&tx, &request.name, scanner_state.internal_id).await?;
    let credential_internal_id = resolve_scanner_credential(&tx, &request).await?;
    let record = execute_scanner_replace_transaction(
        &tx,
        scanner_state.internal_id,
        credential_internal_id,
        &request,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit replace scanner transaction"))?;

    scanner_asset_detail(State(state), Path(record.uuid))
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "replace scanner response reload")
        })
}

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
    resolve_scanner_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE scanners IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_scanner_write_db_error(error, "lock scanners for patch"))?;
    let scanner_state = load_scanner_write_state(&tx, &scanner_id).await?;
    ensure_scanner_metadata_patch_allowed(&scanner_state)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scanner_name(&tx, name, scanner_state.internal_id).await?;
    }
    let record =
        execute_scanner_patch_transaction(&tx, scanner_state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scanner_write_db_error(error, "commit patch scanner transaction"))?;

    scanner_asset_detail(State(state), Path(record.uuid))
        .await
        .map_err(|error| {
            mutation_committed_response_unavailable(error, "patch scanner response reload")
        })
}

async fn resolve_scanner_credential(
    tx: &tokio_postgres::Transaction<'_>,
    request: &ValidatedScannerConfiguration,
) -> Result<Option<i32>, ApiError> {
    if request.unix_socket {
        return Ok(None);
    }
    match request.credential_id.as_deref() {
        Some(credential_id) => Ok(Some(
            load_human_owned_scanner_credential(tx, credential_id).await?,
        )),
        None => Ok(None),
    }
}

fn scanner_write_location_headers(scanner_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/scanners/{scanner_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}
