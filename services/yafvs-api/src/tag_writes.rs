// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
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
    errors::ApiError,
    path_ids::parse_uuid,
    tag_payloads::TagAssetItem,
    tag_write_db::*,
    tag_write_transactions::*,
    tag_write_validation::{
        TagCloneRequest, TagCreateRequest, TagPatchRequest, TagResourceUpdateRequest,
        ValidatedTagResourceSelection, validate_tag_clone_request, validate_tag_create_request,
        validate_tag_patch_request, validate_tag_resource_update_request,
    },
};

pub(crate) async fn create_tag(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin create tag transaction"))?;
    let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    let record = execute_tag_create_transaction(&tx, owner_id, &request).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit create tag transaction"))?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn restore_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin restore tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags, tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag tables for restore"))?;
    let trash = load_tag_trash_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(trash.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;
    ensure_tag_uuid_not_live(&tx, &trash.uuid).await?;
    let record = execute_tag_restore_transaction(&tx, trash.internal_id).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit restore tag transaction"))?;

    Ok(Json(tag))
}

pub(crate) async fn hard_delete_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin hard-delete tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag trash tables for hard delete"))?;
    let trash = load_tag_trash_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(trash.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&trash.resource_type)?;
    execute_tag_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit hard-delete tag transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn patch_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagPatchRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_patch_request(request)?;
    parse_uuid(&tag_id)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin patch tag transaction"))?;
    let selection = request
        .resources
        .as_ref()
        .and_then(|value| value.resource_selection.as_ref());
    if let Some(
        prelocked_selection @ (ValidatedTagResourceSelection::Credential { .. }
        | ValidatedTagResourceSelection::User { .. }),
    ) = selection
    {
        if matches!(
            prelocked_selection,
            ValidatedTagResourceSelection::Credential { .. }
        ) {
            // Stabilize credential owner-name search without taking an
            // incompatible credentials table lock.
            tx.batch_execute("LOCK TABLE users IN SHARE MODE;")
                .await
                .map_err(|error| {
                    map_tag_write_db_error(error, "lock credential owners for tag patch")
                })?;
        }
        resolve_tag_write_operator_owner(&tx, &operator).await?;
        // Credential and User rows must be locked before tag tables to match
        // inherited deletion order. User selection deliberately takes no
        // stronger users table lock than SELECT FOR UPDATE requires.
        let resources = match prelocked_selection {
            ValidatedTagResourceSelection::Credential { .. } => {
                resolve_tag_credential_selection_records(&tx, prelocked_selection).await?
            }
            ValidatedTagResourceSelection::User { .. } => {
                resolve_tag_user_selection_records(&tx, prelocked_selection).await?
            }
            _ => unreachable!(),
        };
        tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
            .await
            .map_err(|error| map_tag_write_db_error(error, "lock tag tables for patch"))?;
        let state = load_tag_write_state(&tx, &tag_id).await?;
        ensure_tag_is_human_owned(state.owner_id)?;
        let effective_resource_type = request
            .resource_type
            .as_deref()
            .unwrap_or(&state.resource_type);
        ensure_tag_resource_direct_write_type_is_supported(effective_resource_type)?;
        let required_type = prelocked_selection.resource_type();
        if state.resource_type != required_type || effective_resource_type != required_type {
            return Err(ApiError::BadRequest(format!(
                "resource_selection requires a {required_type} tag"
            )));
        }
        let record =
            execute_tag_patch_with_resolved_resources(&tx, &state, &request, Some(resources))
                .await?;
        let tag = load_tag_write_detail(&tx, &record.uuid).await?;
        tx.commit()
            .await
            .map_err(|error| map_tag_commit_error(error, "commit patch tag transaction"))?;
        return Ok(Json(tag));
    }
    tx.batch_execute(tag_resource_update_lock_sql(selection))
        .await
        .map_err(|error| map_tag_write_db_error(error, "lock tag tables for patch"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(state.owner_id)?;
    let effective_resource_type = request
        .resource_type
        .as_deref()
        .unwrap_or(&state.resource_type);
    ensure_tag_resource_direct_write_type_is_supported(effective_resource_type)?;
    if let Some(selection) = selection {
        let required_type = selection.resource_type();
        if state.resource_type != required_type || effective_resource_type != required_type {
            return Err(ApiError::BadRequest(format!(
                "resource_selection requires a {required_type} tag"
            )));
        }
    }
    let record = execute_tag_patch_transaction(&tx, &state, &request).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit patch tag transaction"))?;

    Ok(Json(tag))
}

fn tag_resource_update_lock_sql(selection: Option<&ValidatedTagResourceSelection>) -> &'static str {
    match selection {
        Some(ValidatedTagResourceSelection::PortList { .. }) => {
            // Port-list writers acquire port_lists before tag_resources. Keep
            // the same global order here so concurrent lifecycle and selection
            // writes cannot form a table-lock cycle.
            "LOCK TABLE port_lists, tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;"
        }
        Some(ValidatedTagResourceSelection::Credential { .. }) => {
            unreachable!("credential selections use row locks before tag tables")
        }
        Some(ValidatedTagResourceSelection::User { .. }) => {
            unreachable!("user selections use row locks before tag tables")
        }
        Some(ValidatedTagResourceSelection::Scanner { .. }) => {
            // Scanner writers acquire scanners before tag resources. Keep the
            // same global order and stabilize the selected collection.
            "LOCK TABLE scanners, tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;"
        }
        Some(ValidatedTagResourceSelection::Target { .. }) => {
            // Target create/patch and port-list lifecycle writers acquire
            // port_lists before targets. Preserve that order, stabilize the
            // joined port-list-name predicate, then acquire tag tables.
            "LOCK TABLE port_lists, targets, tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;"
        }
        None => "LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    }
}

pub(crate) async fn clone_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TagAssetItem>), ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin clone tag transaction"))?;
    let owner_id = resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_tag_write_db_error(error, "lock tag tables for clone"))?;
    let source = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(source.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&source.resource_type)?;
    let record = execute_tag_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    let tag = load_tag_write_detail(&tx, &record.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit clone tag transaction"))?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn delete_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin delete tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE tags, tags_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag tables for delete"))?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(state.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    execute_tag_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit delete tag transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn update_tag_resources(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagResourceUpdateRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_resource_update_request(request)?;
    parse_uuid(&tag_id)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin tag resource transaction"))?;
    if let Some(
        prelocked_selection @ (ValidatedTagResourceSelection::Credential { .. }
        | ValidatedTagResourceSelection::User { .. }),
    ) = request.resource_selection.as_ref()
    {
        if matches!(
            prelocked_selection,
            ValidatedTagResourceSelection::Credential { .. }
        ) {
            tx.batch_execute("LOCK TABLE users IN SHARE MODE;")
                .await
                .map_err(|error| {
                    map_tag_write_db_error(error, "lock credential owners for tag resource update")
                })?;
        }
        resolve_tag_write_operator_owner(&tx, &operator).await?;
        let resources = match prelocked_selection {
            ValidatedTagResourceSelection::Credential { .. } => {
                resolve_tag_credential_selection_records(&tx, prelocked_selection).await?
            }
            ValidatedTagResourceSelection::User { .. } => {
                resolve_tag_user_selection_records(&tx, prelocked_selection).await?
            }
            _ => unreachable!(),
        };
        tx.batch_execute("LOCK TABLE tags, tag_resources IN SHARE ROW EXCLUSIVE MODE;")
            .await
            .map_err(|error| map_tag_write_db_error(error, "lock tag resource tables"))?;
        let state = load_tag_write_state(&tx, &tag_id).await?;
        ensure_tag_is_human_owned(state.owner_id)?;
        ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
        let required_type = prelocked_selection.resource_type();
        if state.resource_type != required_type {
            return Err(ApiError::BadRequest(format!(
                "resource_selection requires a {required_type} tag"
            )));
        }
        apply_tag_resource_update_transaction(&tx, &state, &request, resources).await?;
        let tag = load_tag_write_detail(&tx, &state.uuid).await?;
        tx.commit()
            .await
            .map_err(|error| map_tag_commit_error(error, "commit tag resource transaction"))?;
        return Ok(Json(tag));
    }
    tx.batch_execute(tag_resource_update_lock_sql(
        request.resource_selection.as_ref(),
    ))
    .await
    .map_err(|error| map_tag_write_db_error(error, "lock tag resource tables"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_is_human_owned(state.owner_id)?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    if let Some(selection) = request.resource_selection.as_ref() {
        let required_type = selection.resource_type();
        if state.resource_type != required_type {
            return Err(ApiError::BadRequest(format!(
                "resource_selection requires a {required_type} tag"
            )));
        }
    }
    execute_tag_resource_update_transaction(&tx, &state, &request).await?;
    let tag = load_tag_write_detail(&tx, &state.uuid).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_commit_error(error, "commit tag resource transaction"))?;

    Ok(Json(tag))
}

fn tag_write_location_headers(tag_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/tags/{tag_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

#[cfg(test)]
#[path = "tag_writes_tests.rs"]
mod tag_writes_tests;
