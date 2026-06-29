// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use serde::Deserialize;
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    tag_resource_helpers::tag_resource_type_is_supported,
    tags::{TagAssetItem, tag_asset_from_row},
};

const MAX_TAG_TEXT_BYTES: usize = 4096;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagWriteRecord {
    pub(crate) internal_id: i64,
    pub(crate) uuid: String,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteOperation {
    CreateMetadata,
    PatchMetadata,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagWriteStep {
    ResolveOperatorOwner,
    VerifyResourceTypeSupported,
    VerifyTagExists,
    InsertMetadata,
    UpdateMetadata,
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

fn default_tag_active() -> bool {
    true
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

pub(crate) async fn execute_tag_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i64,
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
) -> Result<i64, ApiError> {
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
    "SELECT id::bigint, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn tag_insert_metadata_sql() -> &'static str {
    "INSERT INTO tags
        (uuid, owner, name, comment, value, resource_type, active, creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, coalesce($3, ''), coalesce($4, ''), $5, $6, m_now(), m_now())
     RETURNING id::bigint, uuid::text;"
}

pub(crate) fn tag_update_metadata_sql() -> &'static str {
    "UPDATE tags
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            value = coalesce($4, value),
            active = coalesce($5, active),
            modification_time = m_now()
      WHERE uuid = $1
      RETURNING id::bigint, uuid::text;"
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
mod tests {
    use super::*;

    #[test]
    fn tag_create_request_normalizes_metadata_only_contract() {
        let request: TagCreateRequest = serde_json::from_str(
            r#"{"name":"  owner:critical  ","resource_type":" TASK ","comment":" note ","value":" yes ","active":false}"#,
        )
        .expect("valid tag create request");
        let validated = validate_tag_create_request(request).expect("valid create request");
        assert_eq!(validated.name, "owner:critical");
        assert_eq!(validated.resource_type, "task");
        assert_eq!(validated.comment.as_deref(), Some("note"));
        assert_eq!(validated.value.as_deref(), Some("yes"));
        assert!(!validated.active);

        let default_active = validate_tag_create_request(TagCreateRequest {
            name: "owner:default".to_string(),
            resource_type: "target".to_string(),
            comment: None,
            value: None,
            active: default_tag_active(),
        })
        .expect("default active create request");
        assert!(default_active.active);
    }

    #[test]
    fn tag_create_request_rejects_unknown_fields_bad_text_and_unsupported_types() {
        assert!(
            serde_json::from_str::<TagCreateRequest>(
                r#"{"name":"x","resource_type":"task","resource_ids":[]}"#
            )
            .is_err()
        );

        let empty_name = TagCreateRequest {
            name: " ".to_string(),
            resource_type: "task".to_string(),
            comment: None,
            value: None,
            active: true,
        };
        assert!(matches!(
            validate_tag_create_request(empty_name),
            Err(ApiError::BadRequest(_))
        ));

        let bad_type = TagCreateRequest {
            name: "owner:x".to_string(),
            resource_type: "credential".to_string(),
            comment: None,
            value: None,
            active: true,
        };
        assert!(matches!(
            validate_tag_create_request(bad_type),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn tag_patch_request_is_metadata_only_and_requires_a_field() {
        let patch: TagPatchRequest = serde_json::from_str(
            r#"{"name":"  owner:patched ","comment":"","value":" v ","active":true}"#,
        )
        .expect("valid tag patch request");
        let validated = validate_tag_patch_request(patch).expect("valid patch request");
        assert_eq!(validated.name.as_deref(), Some("owner:patched"));
        assert_eq!(validated.comment.as_deref(), Some(""));
        assert_eq!(validated.value.as_deref(), Some("v"));
        assert_eq!(validated.active, Some(true));

        assert!(serde_json::from_str::<TagPatchRequest>(r#"{"resource_type":"target"}"#).is_err());
        let empty = TagPatchRequest {
            name: None,
            comment: None,
            value: None,
            active: None,
        };
        assert!(matches!(
            validate_tag_patch_request(empty),
            Err(ApiError::BadRequest(_))
        ));

        let empty_name = TagPatchRequest {
            name: Some(" ".to_string()),
            comment: None,
            value: None,
            active: None,
        };
        assert!(matches!(
            validate_tag_patch_request(empty_name),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn tag_write_plans_are_metadata_only() {
        let create = ValidatedTagCreate {
            name: "owner:x".to_string(),
            resource_type: "task".to_string(),
            comment: None,
            value: None,
            active: true,
        };
        assert_eq!(
            tag_create_transaction_plan(&create),
            TagWriteTransactionPlan {
                operation: TagWriteOperation::CreateMetadata,
                steps: vec![
                    TagWriteStep::ResolveOperatorOwner,
                    TagWriteStep::VerifyResourceTypeSupported,
                    TagWriteStep::InsertMetadata,
                ],
            }
        );

        let patch = ValidatedTagPatch {
            name: Some("owner:y".to_string()),
            comment: None,
            value: None,
            active: None,
        };
        assert_eq!(
            tag_patch_transaction_plan(&patch),
            TagWriteTransactionPlan {
                operation: TagWriteOperation::PatchMetadata,
                steps: vec![
                    TagWriteStep::ResolveOperatorOwner,
                    TagWriteStep::VerifyTagExists,
                    TagWriteStep::UpdateMetadata,
                ],
            }
        );
    }

    #[test]
    fn tag_write_sql_uses_parameterized_metadata_queries_only() {
        let insert = tag_insert_metadata_sql();
        assert!(insert.contains("INSERT INTO tags"));
        assert!(insert.contains("$1"));
        assert!(!insert.contains("tag_resources"));

        let update = tag_update_metadata_sql();
        assert!(update.contains("UPDATE tags"));
        assert!(update.contains("coalesce($2, name)"));
        assert!(!update.contains("resource_type ="));
        assert!(!update.contains("tag_resources"));
    }
}
