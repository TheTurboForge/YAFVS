// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use serde::Deserialize;
use std::collections::BTreeSet;
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    tag_payloads::{TagAssetItem, tag_asset_from_row},
    tag_resource_helpers::{
        tag_resource_active_lookup_sql, tag_resource_direct_write_type_is_supported,
        tag_resource_type_is_supported,
    },
};

const MAX_TAG_TEXT_BYTES: usize = 4096;
const MAX_TAG_RESOURCE_WRITE_IDS: usize = 100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagCreateRequest {
    name: String,
    resource_type: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default = "default_tag_active")]
    active: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagPatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    active: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TagResourceUpdateAction {
    Add,
    Remove,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TagResourceUpdateRequest {
    action: TagResourceUpdateAction,
    resource_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagCreate {
    pub(crate) name: String,
    pub(crate) resource_type: String,
    pub(crate) comment: Option<String>,
    pub(crate) value: Option<String>,
    pub(crate) active: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) value: Option<String>,
    pub(crate) active: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTagResourceUpdate {
    pub(crate) action: TagResourceUpdateAction,
    pub(crate) resource_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TagWriteState {
    internal_id: i32,
    uuid: String,
    resource_type: String,
    resource_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TagResourceWriteRecord {
    internal_id: i32,
    uuid: String,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteOperation {
    CreateMetadata,
    PatchMetadata,
    DeleteMetadata,
    UpdateResourceAssignments,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteStep {
    ResolveOperatorOwner,
    VerifyResourceTypeSupported,
    VerifyTagExists,
    VerifyTagUnassigned,
    VerifyResourceExists,
    InsertMetadata,
    UpdateMetadata,
    DeleteMetadata,
    InsertResourceAssignment,
    DeleteResourceAssignment,
    TouchMetadata,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TagWriteTransactionPlan {
    pub(crate) operation: TagWriteOperation,
    pub(crate) steps: Vec<TagWriteStep>,
}

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
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit create tag transaction"))?;

    let tag = load_tag_write_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        tag_write_location_headers(&record.uuid)?,
        Json(tag),
    ))
}

pub(crate) async fn patch_tag(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TagPatchRequest>,
) -> Result<Json<TagAssetItem>, ApiError> {
    let operator = require_tag_write_operator(operator)?;
    let request = validate_tag_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin patch tag transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    let record = execute_tag_patch_transaction(&tx, &tag_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit patch tag transaction"))?;

    Ok(Json(load_tag_write_detail(&client, &record.uuid).await?))
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
    let state = load_unassigned_tag_write_state(&tx, &tag_id).await?;
    execute_tag_delete_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit delete tag transaction"))?;

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
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_tag_write_db_error(error, "begin tag resource transaction"))?;
    resolve_tag_write_operator_owner(&tx, &operator).await?;
    let state = load_tag_write_state(&tx, &tag_id).await?;
    ensure_tag_resource_direct_write_type_is_supported(&state.resource_type)?;
    execute_tag_resource_update_transaction(&tx, &state, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_tag_write_db_error(error, "commit tag resource transaction"))?;

    Ok(Json(load_tag_write_detail(&client, &state.uuid).await?))
}

fn default_tag_active() -> bool {
    true
}

pub(crate) fn validate_tag_resource_update_request(
    request: TagResourceUpdateRequest,
) -> Result<ValidatedTagResourceUpdate, ApiError> {
    if request.resource_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "resource_ids must contain at least one resource id".to_string(),
        ));
    }

    if request.resource_ids.len() > MAX_TAG_RESOURCE_WRITE_IDS {
        return Err(ApiError::BadRequest(format!(
            "resource_ids must contain at most {MAX_TAG_RESOURCE_WRITE_IDS} ids"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut resource_ids = Vec::new();
    for resource_id in request.resource_ids {
        let parsed = parse_uuid(&resource_id)?.to_string();
        if seen.insert(parsed.clone()) {
            resource_ids.push(parsed);
        }
    }
    Ok(ValidatedTagResourceUpdate {
        action: request.action,
        resource_ids,
    })
}

fn require_tag_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("tag write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) fn validate_tag_create_request(
    request: TagCreateRequest,
) -> Result<ValidatedTagCreate, ApiError> {
    Ok(ValidatedTagCreate {
        name: normalize_required_tag_text(request.name, "name")?,
        resource_type: normalize_tag_write_resource_type(request.resource_type)?,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
        value: normalize_optional_tag_text(request.value, "value")?,
        active: request.active,
    })
}

pub(crate) fn validate_tag_patch_request(
    request: TagPatchRequest,
) -> Result<ValidatedTagPatch, ApiError> {
    let validated = ValidatedTagPatch {
        name: normalize_optional_required_tag_text(request.name, "name")?,
        comment: normalize_optional_tag_text(request.comment, "comment")?,
        value: normalize_optional_tag_text(request.value, "value")?,
        active: request.active,
    };
    if validated.name.is_none()
        && validated.comment.is_none()
        && validated.value.is_none()
        && validated.active.is_none()
    {
        Err(ApiError::BadRequest(
            "at least one tag metadata field must be provided".to_string(),
        ))
    } else {
        Ok(validated)
    }
}

#[cfg(test)]
pub(crate) fn tag_resource_update_transaction_plan(
    request: &ValidatedTagResourceUpdate,
) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::UpdateResourceAssignments,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::VerifyResourceExists,
            match request.action {
                TagResourceUpdateAction::Add => TagWriteStep::InsertResourceAssignment,
                TagResourceUpdateAction::Remove => TagWriteStep::DeleteResourceAssignment,
            },
            TagWriteStep::TouchMetadata,
        ],
    }
}

#[cfg(test)]
pub(crate) fn tag_create_transaction_plan(
    _request: &ValidatedTagCreate,
) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::CreateMetadata,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyResourceTypeSupported,
            TagWriteStep::InsertMetadata,
        ],
    }
}

#[cfg(test)]
pub(crate) fn tag_patch_transaction_plan(_request: &ValidatedTagPatch) -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::PatchMetadata,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::UpdateMetadata,
        ],
    }
}

#[cfg(test)]
pub(crate) fn tag_delete_transaction_plan() -> TagWriteTransactionPlan {
    TagWriteTransactionPlan {
        operation: TagWriteOperation::DeleteMetadata,
        steps: vec![
            TagWriteStep::ResolveOperatorOwner,
            TagWriteStep::VerifyTagExists,
            TagWriteStep::VerifyTagUnassigned,
            TagWriteStep::DeleteMetadata,
        ],
    }
}

pub(crate) async fn execute_tag_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedTagCreate,
) -> Result<TagWriteRecord, ApiError> {
    query_tag_write_record(
        tx,
        tag_insert_metadata_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.value,
            &request.resource_type,
            &(request.active as i32),
        ],
        "insert tag metadata",
    )
    .await
}

async fn execute_tag_resource_update_transaction(
    tx: &Transaction<'_>,
    state: &TagWriteState,
    request: &ValidatedTagResourceUpdate,
) -> Result<(), ApiError> {
    for resource_id in &request.resource_ids {
        let resource =
            resolve_tag_resource_write_record(tx, &state.resource_type, resource_id).await?;
        match request.action {
            TagResourceUpdateAction::Add => {
                tx.execute(
                    tag_resource_insert_sql(),
                    &[
                        &state.internal_id,
                        &state.resource_type,
                        &resource.internal_id,
                        &resource.uuid,
                    ],
                )
                .await
                .map_err(|error| map_tag_write_db_error(error, "insert tag resource"))?;
            }
            TagResourceUpdateAction::Remove => {
                let deleted = tx
                    .execute(
                        tag_resource_delete_sql(),
                        &[
                            &state.internal_id,
                            &state.resource_type,
                            &resource.internal_id,
                        ],
                    )
                    .await
                    .map_err(|error| map_tag_write_db_error(error, "delete tag resource"))?;
                if deleted == 0 {
                    return Err(ApiError::NotFound);
                }
            }
        }
    }
    tx.execute(tag_touch_metadata_sql(), &[&state.internal_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "touch tag metadata"))?;
    Ok(())
}

pub(crate) async fn execute_tag_delete_transaction(
    tx: &Transaction<'_>,
    tag_internal_id: i32,
) -> Result<TagWriteRecord, ApiError> {
    query_tag_write_record(
        tx,
        tag_delete_metadata_sql(),
        &[&tag_internal_id],
        "delete tag metadata",
    )
    .await
}

pub(crate) async fn execute_tag_patch_transaction(
    tx: &Transaction<'_>,
    tag_id: &str,
    request: &ValidatedTagPatch,
) -> Result<TagWriteRecord, ApiError> {
    let tag_id = parse_uuid(tag_id)?.to_string();
    query_tag_write_record(
        tx,
        tag_update_metadata_sql(),
        &[
            &tag_id,
            &request.name,
            &request.comment,
            &request.value,
            &request.active.map(|value| value as i32),
        ],
        "update tag metadata",
    )
    .await
}

async fn resolve_tag_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(tag_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_tag_write_db_error(error, "resolve tag write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API tag write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

async fn query_tag_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TagWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_tag_write_db_error(error, action))?
        .map(|row| tag_write_record_from_row(&row))
        .ok_or(ApiError::NotFound)
}

async fn load_tag_write_detail<C>(client: &C, tag_id: &str) -> Result<TagAssetItem, ApiError>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let tag_id = parse_uuid(tag_id)?.to_string();
    let row = client
        .query_opt(tag_write_detail_sql(), &[&tag_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "load tag write detail"))?
        .ok_or(ApiError::NotFound)?;
    Ok(tag_asset_from_row(&row))
}

async fn load_tag_write_state(
    tx: &Transaction<'_>,
    tag_id: &str,
) -> Result<TagWriteState, ApiError> {
    let tag_id = parse_uuid(tag_id)?.to_string();
    let row = tx
        .query_opt(tag_write_state_sql(), &[&tag_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "load tag write state"))?
        .ok_or(ApiError::NotFound)?;
    Ok(TagWriteState {
        internal_id: row.get(0),
        uuid: row.get(1),
        resource_type: row.get(2),
        resource_count: row.get(3),
    })
}

async fn load_unassigned_tag_write_state(
    tx: &Transaction<'_>,
    tag_id: &str,
) -> Result<TagWriteState, ApiError> {
    let state = load_tag_write_state(tx, tag_id).await?;
    ensure_tag_is_unassigned(state.resource_count)?;
    Ok(state)
}

async fn resolve_tag_resource_write_record(
    tx: &Transaction<'_>,
    resource_type: &str,
    resource_id: &str,
) -> Result<TagResourceWriteRecord, ApiError> {
    let resource_id = parse_uuid(resource_id)?.to_string();
    let sql = tag_resource_active_lookup_sql(resource_type)?;
    tx.query_opt(&sql, &[&resource_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "resolve tag resource"))?
        .map(|row| TagResourceWriteRecord {
            internal_id: row.get(0),
            uuid: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

fn ensure_tag_resource_direct_write_type_is_supported(resource_type: &str) -> Result<(), ApiError> {
    if tag_resource_direct_write_type_is_supported(resource_type) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "tag resource type {resource_type} is not supported by direct resource writes"
        )))
    }
}

fn ensure_tag_is_unassigned(resource_count: i64) -> Result<(), ApiError> {
    if resource_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "tag with assigned resources cannot be deleted by this metadata-only direct API"
                .to_string(),
        ))
    }
}

fn tag_write_record_from_row(row: &Row) -> TagWriteRecord {
    TagWriteRecord {
        internal_id: row.get(0),
        uuid: row.get(1),
    }
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

fn normalize_required_tag_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_tag_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_tag_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_tag_text_value(value, field_name))
        .transpose()
}

fn normalize_optional_required_tag_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_tag_text(value, field_name))
        .transpose()
}

fn normalize_tag_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_TAG_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_TAG_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_tag_write_resource_type(value: String) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(ApiError::BadRequest(
            "resource_type is required".to_string(),
        ));
    }
    if tag_resource_type_is_supported(&value) {
        Ok(value)
    } else {
        Err(ApiError::BadRequest(format!(
            "unsupported tag resource type: {value}"
        )))
    }
}

fn map_tag_write_db_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::warn!(%error, action, "tag write database operation failed");
    ApiError::Database
}

pub(crate) fn tag_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn tag_insert_metadata_sql() -> &'static str {
    "INSERT INTO tags
        (uuid, owner, name, comment, value, resource_type, active, creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, coalesce($3, ''), coalesce($4, ''), $5, $6, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn tag_update_metadata_sql() -> &'static str {
    "UPDATE tags
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            value = coalesce($4, value),
            active = coalesce($5, active),
            modification_time = m_now()
      WHERE uuid = $1
      RETURNING id::integer, uuid::text;"
}

#[cfg(test)]
pub(crate) fn tag_write_unassigned_state_sql() -> &'static str {
    tag_write_state_sql()
}

pub(crate) fn tag_write_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            coalesce(resource_type, '')::text,
            coalesce(tag_resources_count(id, resource_type), 0)::bigint AS resource_count
       FROM tags
      WHERE uuid = $1;"
}

pub(crate) fn tag_resource_insert_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT $1, $2, $3, $4, 0
      WHERE NOT EXISTS (
            SELECT 1 FROM tag_resources
             WHERE tag = $1
               AND resource_type = $2
               AND resource = $3
               AND resource_location = 0
      );"
}

pub(crate) fn tag_resource_delete_sql() -> &'static str {
    "DELETE FROM tag_resources
      WHERE tag = $1
        AND resource_type = $2
        AND resource = $3
        AND resource_location = 0;"
}

pub(crate) fn tag_touch_metadata_sql() -> &'static str {
    "UPDATE tags SET modification_time = m_now() WHERE id = $1;"
}

pub(crate) fn tag_delete_metadata_sql() -> &'static str {
    "DELETE FROM tags
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn tag_write_detail_sql() -> &'static str {
    "SELECT t.uuid AS id,
            coalesce(t.name, '') AS name,
            coalesce(t.comment, '') AS comment,
            coalesce(u.name, '') AS owner_name,
            coalesce(t.resource_type, '') AS resource_type,
            coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
            coalesce(t.active, 0)::integer AS active_int,
            coalesce(t.value, '') AS value,
            coalesce(t.creation_time, 0)::bigint AS created_at_unix,
            coalesce(t.modification_time, 0)::bigint AS modified_at_unix
       FROM tags t
  LEFT JOIN users u ON u.id = t.owner
      WHERE t.uuid = $1
      LIMIT 1;"
}

#[cfg(test)]
#[path = "tag_writes_tests.rs"]
mod tag_writes_tests;
