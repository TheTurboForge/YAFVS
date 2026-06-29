// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

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
    scope_payloads::{ScopeItem, load_scope_detail},
};

const MAX_SCOPE_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeCreateRequest {
    name: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    protection_requirement: Option<String>,
    #[serde(default)]
    target_ids: Vec<String>,
    #[serde(default)]
    host_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopePatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    protection_requirement: Option<String>,
    #[serde(default)]
    target_ids: Option<Vec<String>>,
    #[serde(default)]
    host_ids: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScopeCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) protection_requirement: String,
    pub(crate) target_ids: Vec<String>,
    pub(crate) host_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedScopePatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) protection_requirement: Option<String>,
    pub(crate) target_ids: Option<Vec<String>>,
    pub(crate) host_ids: Option<Vec<String>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeWriteOperation {
    Create,
    Patch,
    Delete,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeWriteStep {
    ResolveOperatorOwner,
    VerifyScopeMutable,
    VerifyReferenceVisibility,
    InsertScope,
    UpdateScopeMetadata,
    ReplaceTargetMembership,
    ReplaceHostMembership,
    VerifyNoScopeReportHistory,
    DeleteScopeMembership,
    DeleteScope,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScopeWriteTransactionPlan {
    pub(crate) operation: ScopeWriteOperation,
    pub(crate) steps: Vec<ScopeWriteStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeWriteRecord {
    pub(crate) internal_id: i64,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeWriteState {
    internal_id: i64,
    uuid: String,
}

pub(crate) async fn create_scope(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScopeCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ScopeItem>), ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let request = validate_scope_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scope_write_db_error(error, "begin create scope transaction"))?;
    let owner_id = resolve_scope_write_operator_owner(&tx, &operator).await?;
    verify_scope_write_references_visible(&tx, &request.target_ids, &request.host_ids).await?;
    let record = execute_scope_create_transaction(&tx, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scope_write_db_error(error, "commit create scope transaction"))?;

    let scope = load_scope_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        scope_write_location_headers(&record.uuid)?,
        Json(scope),
    ))
}

pub(crate) async fn patch_scope(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScopePatchRequest>,
) -> Result<Json<ScopeItem>, ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let request = validate_scope_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scope_write_db_error(error, "begin patch scope transaction"))?;
    resolve_scope_write_operator_owner(&tx, &operator).await?;
    let state = load_mutable_scope_write_state(&tx, &scope_id).await?;
    verify_scope_write_references_visible(
        &tx,
        request.target_ids.as_deref().unwrap_or(&[]),
        request.host_ids.as_deref().unwrap_or(&[]),
    )
    .await?;
    let record = execute_scope_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_scope_write_db_error(error, "commit patch scope transaction"))?;

    Ok(Json(load_scope_detail(&client, &record.uuid).await?))
}

pub(crate) async fn delete_scope(
    State(state): State<AppState>,
    Path(scope_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_scope_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_scope_write_db_error(error, "begin delete scope transaction"))?;
    resolve_scope_write_operator_owner(&tx, &operator).await?;
    let state = load_mutable_scope_write_state(&tx, &scope_id).await?;
    ensure_scope_has_no_report_history(&tx, &state.uuid).await?;
    execute_scope_delete_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_scope_write_db_error(error, "commit delete scope transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

fn require_scope_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("scope write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) fn validate_scope_create_request(
    request: ScopeCreateRequest,
) -> Result<ValidatedScopeCreate, ApiError> {
    Ok(ValidatedScopeCreate {
        name: normalize_required_scope_text(request.name, "name")?,
        comment: normalize_optional_scope_text(request.comment, "comment")?,
        protection_requirement: normalize_protection_requirement(
            request.protection_requirement.as_deref(),
        )?
        .unwrap_or_else(|| "normal".to_string()),
        target_ids: normalize_membership_ids(request.target_ids, "target_ids")?,
        host_ids: normalize_membership_ids(request.host_ids, "host_ids")?,
    })
}

#[cfg(test)]
pub(crate) fn scope_create_transaction_plan(
    request: &ValidatedScopeCreate,
) -> ScopeWriteTransactionPlan {
    let mut steps = vec![ScopeWriteStep::ResolveOperatorOwner];
    if !request.target_ids.is_empty() || !request.host_ids.is_empty() {
        steps.push(ScopeWriteStep::VerifyReferenceVisibility);
    }
    steps.extend([
        ScopeWriteStep::InsertScope,
        ScopeWriteStep::ReplaceTargetMembership,
        ScopeWriteStep::ReplaceHostMembership,
    ]);
    ScopeWriteTransactionPlan {
        operation: ScopeWriteOperation::Create,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn scope_patch_transaction_plan(
    request: &ValidatedScopePatch,
) -> ScopeWriteTransactionPlan {
    let mut steps = vec![
        ScopeWriteStep::ResolveOperatorOwner,
        ScopeWriteStep::VerifyScopeMutable,
    ];
    if request.target_ids.is_some() || request.host_ids.is_some() {
        steps.push(ScopeWriteStep::VerifyReferenceVisibility);
    }
    if request.name.is_some()
        || request.comment.is_some()
        || request.protection_requirement.is_some()
    {
        steps.push(ScopeWriteStep::UpdateScopeMetadata);
    }
    if request.target_ids.is_some() {
        steps.push(ScopeWriteStep::ReplaceTargetMembership);
    }
    if request.host_ids.is_some() {
        steps.push(ScopeWriteStep::ReplaceHostMembership);
    }
    ScopeWriteTransactionPlan {
        operation: ScopeWriteOperation::Patch,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn scope_delete_transaction_plan() -> ScopeWriteTransactionPlan {
    ScopeWriteTransactionPlan {
        operation: ScopeWriteOperation::Delete,
        steps: vec![
            ScopeWriteStep::ResolveOperatorOwner,
            ScopeWriteStep::VerifyScopeMutable,
            ScopeWriteStep::VerifyNoScopeReportHistory,
            ScopeWriteStep::DeleteScopeMembership,
            ScopeWriteStep::DeleteScope,
        ],
    }
}

pub(crate) fn validate_scope_patch_request(
    request: ScopePatchRequest,
) -> Result<ValidatedScopePatch, ApiError> {
    Ok(ValidatedScopePatch {
        name: normalize_optional_scope_text(request.name, "name")?,
        comment: normalize_optional_scope_text(request.comment, "comment")?,
        protection_requirement: normalize_protection_requirement(
            request.protection_requirement.as_deref(),
        )?,
        target_ids: normalize_optional_membership_ids(request.target_ids, "target_ids")?,
        host_ids: normalize_optional_membership_ids(request.host_ids, "host_ids")?,
    })
}

pub(crate) fn ensure_scope_is_mutable(is_global: bool, predefined: bool) -> Result<(), ApiError> {
    if is_global || predefined {
        Err(ApiError::Conflict("scope is immutable".to_string()))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_scope_write_references_visible(
    field_name: &str,
    requested_ids: &[String],
    visible_ids: &[String],
) -> Result<(), ApiError> {
    let visible = visible_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if requested_ids.iter().all(|id| visible.contains(id.as_str())) {
        return Ok(());
    }
    tracing::warn!(
        field = field_name,
        "scope write references are not visible to operator"
    );
    Err(ApiError::Forbidden)
}

pub(crate) async fn execute_scope_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i64,
    request: &ValidatedScopeCreate,
) -> Result<ScopeWriteRecord, ApiError> {
    let record = query_scope_write_record(
        tx,
        scope_insert_sql(),
        &[
            &owner_id,
            &request.name,
            &request.comment,
            &request.protection_requirement,
        ],
        "insert scope",
    )
    .await?;
    replace_scope_membership(
        tx,
        record.internal_id,
        &request.target_ids,
        scope_delete_targets_sql(),
        scope_insert_target_sql(),
        "target_ids",
    )
    .await?;
    replace_scope_membership(
        tx,
        record.internal_id,
        &request.host_ids,
        scope_delete_hosts_sql(),
        scope_insert_host_sql(),
        "host_ids",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_scope_patch_transaction(
    tx: &Transaction<'_>,
    scope_internal_id: i64,
    request: &ValidatedScopePatch,
) -> Result<ScopeWriteRecord, ApiError> {
    let record = if request.name.is_some()
        || request.comment.is_some()
        || request.protection_requirement.is_some()
    {
        query_scope_write_record(
            tx,
            scope_update_metadata_sql(),
            &[
                &scope_internal_id,
                &request.name,
                &request.comment,
                &request.protection_requirement,
            ],
            "update scope metadata",
        )
        .await?
    } else {
        query_scope_write_record(
            tx,
            scope_by_internal_id_sql(),
            &[&scope_internal_id],
            "load scope after membership-only patch",
        )
        .await?
    };

    if let Some(target_ids) = request.target_ids.as_ref() {
        replace_scope_membership(
            tx,
            record.internal_id,
            target_ids,
            scope_delete_targets_sql(),
            scope_insert_target_sql(),
            "target_ids",
        )
        .await?;
    }
    if let Some(host_ids) = request.host_ids.as_ref() {
        replace_scope_membership(
            tx,
            record.internal_id,
            host_ids,
            scope_delete_hosts_sql(),
            scope_insert_host_sql(),
            "host_ids",
        )
        .await?;
    }
    Ok(record)
}

pub(crate) async fn execute_scope_delete_transaction(
    tx: &Transaction<'_>,
    scope_internal_id: i64,
) -> Result<(), ApiError> {
    execute_scope_write_sql(
        tx,
        scope_delete_targets_sql(),
        &[&scope_internal_id],
        "delete scope target membership",
    )
    .await?;
    execute_scope_write_sql(
        tx,
        scope_delete_hosts_sql(),
        &[&scope_internal_id],
        "delete scope host membership",
    )
    .await?;
    let deleted = execute_scope_write_sql(
        tx,
        scope_delete_sql(),
        &[&scope_internal_id],
        "delete scope",
    )
    .await?;
    if deleted == 0 {
        Err(ApiError::NotFound)
    } else {
        Ok(())
    }
}

fn scope_write_location_headers(scope_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/scopes/{scope_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

async fn resolve_scope_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i64, ApiError> {
    tx.query_opt(scope_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_scope_write_db_error(error, "resolve scope write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API scope write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

async fn load_mutable_scope_write_state(
    tx: &Transaction<'_>,
    scope_id: &str,
) -> Result<ScopeWriteState, ApiError> {
    let scope_id = parse_uuid(scope_id)?.to_string();
    let row = tx
        .query_opt(scope_write_mutability_sql(), &[&scope_id])
        .await
        .map_err(|error| map_scope_write_db_error(error, "load scope write state"))?
        .ok_or(ApiError::NotFound)?;
    let state = ScopeWriteState {
        internal_id: row.get(0),
        uuid: scope_id,
    };
    let predefined: i32 = row.get(1);
    let global: i32 = row.get(2);
    ensure_scope_is_mutable(global != 0, predefined != 0)?;
    Ok(state)
}

async fn ensure_scope_has_no_report_history(
    tx: &Transaction<'_>,
    scope_id: &str,
) -> Result<(), ApiError> {
    let row = tx
        .query_one(scope_write_report_history_sql(), &[&scope_id])
        .await
        .map_err(|error| map_scope_write_db_error(error, "check scope report history"))?;
    let report_count: i64 = row.get(0);
    if report_count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scope with report history cannot be deleted".to_string(),
        ))
    }
}

async fn verify_scope_write_references_visible(
    tx: &Transaction<'_>,
    target_ids: &[String],
    host_ids: &[String],
) -> Result<(), ApiError> {
    let visible_target_ids = visible_scope_reference_ids(
        tx,
        scope_write_visible_targets_sql(),
        target_ids,
        "load visible scope targets",
    )
    .await?;
    ensure_scope_write_references_visible("target_ids", target_ids, &visible_target_ids)?;

    let visible_host_ids = visible_scope_reference_ids(
        tx,
        scope_write_visible_hosts_sql(),
        host_ids,
        "load visible scope hosts",
    )
    .await?;
    ensure_scope_write_references_visible("host_ids", host_ids, &visible_host_ids)
}

async fn visible_scope_reference_ids(
    tx: &Transaction<'_>,
    sql: &str,
    requested_ids: &[String],
    action: &'static str,
) -> Result<Vec<String>, ApiError> {
    if requested_ids.is_empty() {
        return Ok(Vec::new());
    }
    let requested_ids = requested_ids.to_vec();
    let rows = tx
        .query(sql, &[&requested_ids])
        .await
        .map_err(|error| map_scope_write_db_error(error, action))?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

async fn query_scope_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScopeWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))?
        .map(|row| scope_write_record_from_row(&row))
        .ok_or(ApiError::NotFound)
}

async fn execute_scope_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_scope_write_db_error(error, action))
}

async fn replace_scope_membership(
    tx: &Transaction<'_>,
    scope_internal_id: i64,
    requested_ids: &[String],
    delete_sql: &str,
    insert_sql: &str,
    field_name: &'static str,
) -> Result<(), ApiError> {
    execute_scope_write_sql(
        tx,
        delete_sql,
        &[&scope_internal_id],
        "delete scope membership",
    )
    .await?;
    for requested_id in requested_ids {
        let inserted = execute_scope_write_sql(
            tx,
            insert_sql,
            &[&scope_internal_id, requested_id],
            "insert scope membership",
        )
        .await?;
        if inserted == 0 {
            tracing::warn!(
                field = field_name,
                "scope write reference disappeared before insert"
            );
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

fn scope_write_record_from_row(row: &Row) -> ScopeWriteRecord {
    ScopeWriteRecord {
        internal_id: row.get(0),
        uuid: row.get(1),
    }
}

fn map_scope_write_db_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::warn!(%error, action, "scope write database operation failed");
    ApiError::Database
}

pub(crate) fn scope_write_operator_owner_sql() -> &'static str {
    "SELECT id::bigint, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_mutability_sql() -> &'static str {
    "SELECT id::bigint, coalesce(predefined, 0)::integer, coalesce(is_global, 0)::integer
       FROM scopes
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_report_history_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM scope_reports
      WHERE scope_uuid = $1;"
}

pub(crate) fn scope_write_visible_targets_sql() -> &'static str {
    "SELECT uuid::text
       FROM targets
      WHERE uuid = ANY($1::text[]);"
}

pub(crate) fn scope_write_visible_hosts_sql() -> &'static str {
    "SELECT uuid::text
       FROM hosts
      WHERE uuid = ANY($1::text[]);"
}

pub(crate) fn scope_by_internal_id_sql() -> &'static str {
    "SELECT id::bigint, uuid::text
       FROM scopes
      WHERE id = $1;"
}

pub(crate) fn scope_insert_sql() -> &'static str {
    "INSERT INTO scopes
        (uuid, owner, name, comment, protection_requirement, predefined, is_global,
         creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, $3, $4, 0, 0, m_now(), m_now())
     RETURNING id::bigint, uuid::text;"
}

pub(crate) fn scope_update_metadata_sql() -> &'static str {
    "UPDATE scopes
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            protection_requirement = coalesce($4, protection_requirement),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::bigint, uuid::text;"
}

pub(crate) fn scope_delete_targets_sql() -> &'static str {
    "DELETE FROM scope_targets WHERE scope = $1;"
}

pub(crate) fn scope_insert_target_sql() -> &'static str {
    "INSERT INTO scope_targets (scope, target, target_uuid, target_name, added_time)
     SELECT $1, id, uuid, name, m_now()
       FROM targets
      WHERE uuid = $2
     ON CONFLICT (scope, target) DO NOTHING;"
}

pub(crate) fn scope_delete_hosts_sql() -> &'static str {
    "DELETE FROM scope_hosts WHERE scope = $1;"
}

pub(crate) fn scope_insert_host_sql() -> &'static str {
    "INSERT INTO scope_hosts (scope, host, host_uuid, host_name, added_time)
     SELECT $1, id, uuid, name, m_now()
       FROM hosts
      WHERE uuid = $2
     ON CONFLICT (scope, host) DO NOTHING;"
}

pub(crate) fn scope_delete_sql() -> &'static str {
    "DELETE FROM scopes WHERE id = $1;"
}

fn normalize_required_scope_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_scope_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_scope_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_scope_text_value(value, field_name))
        .transpose()
}

fn normalize_scope_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCOPE_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCOPE_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_protection_requirement(value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    match normalized.as_str() {
        "" => Ok(None),
        "normal" | "high" | "very_high" => Ok(Some(normalized)),
        _ => Err(ApiError::BadRequest(
            "protection_requirement must be normal, high, or very_high".to_string(),
        )),
    }
}

fn normalize_optional_membership_ids(
    values: Option<Vec<String>>,
    field_name: &str,
) -> Result<Option<Vec<String>>, ApiError> {
    values
        .map(|values| normalize_membership_ids(values, field_name))
        .transpose()
}

fn normalize_membership_ids(
    values: Vec<String>,
    field_name: &str,
) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let parsed = parse_uuid(value.trim())?.to_string();
        if !seen.insert(parsed.clone()) {
            return Err(ApiError::Conflict(format!(
                "{field_name} contains duplicate ids"
            )));
        }
        normalized.push(parsed);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_create_request_normalizes_defaults_and_membership_ids() {
        let request: ScopeCreateRequest = serde_json::from_str(
            r#"{
                "name": "  Example scope  ",
                "comment": "  retained  ",
                "protection_requirement": "Very High",
                "target_ids": ["12345678-1234-1234-1234-123456789ABC"],
                "host_ids": []
            }"#,
        )
        .expect("valid create DTO");

        let validated = validate_scope_create_request(request).expect("valid create request");

        assert_eq!(validated.name, "Example scope");
        assert_eq!(validated.comment.as_deref(), Some("retained"));
        assert_eq!(validated.protection_requirement, "very_high");
        assert_eq!(
            validated.target_ids,
            vec!["12345678-1234-1234-1234-123456789abc"]
        );
        assert!(validated.host_ids.is_empty());

        let defaulted = validate_scope_create_request(ScopeCreateRequest {
            name: "Defaulted".to_string(),
            comment: None,
            protection_requirement: None,
            target_ids: vec![],
            host_ids: vec![],
        })
        .expect("defaulted create request");
        assert_eq!(defaulted.protection_requirement, "normal");
    }

    #[test]
    fn scope_write_dtos_reject_unknown_fields_bad_text_and_bad_enums() {
        assert!(serde_json::from_str::<ScopeCreateRequest>(r#"{"name":"x","extra":1}"#).is_err());

        let empty_name = ScopeCreateRequest {
            name: "   ".to_string(),
            comment: None,
            protection_requirement: None,
            target_ids: vec![],
            host_ids: vec![],
        };
        assert!(matches!(
            validate_scope_create_request(empty_name),
            Err(ApiError::BadRequest(_))
        ));

        let bad_enum = ScopeCreateRequest {
            name: "scope".to_string(),
            comment: None,
            protection_requirement: Some("critical".to_string()),
            target_ids: vec![],
            host_ids: vec![],
        };
        assert!(matches!(
            validate_scope_create_request(bad_enum),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn scope_membership_validation_rejects_invalid_and_duplicate_uuids() {
        let duplicate = ScopeCreateRequest {
            name: "scope".to_string(),
            comment: None,
            protection_requirement: None,
            target_ids: vec![
                "12345678-1234-1234-1234-123456789abc".to_string(),
                "12345678-1234-1234-1234-123456789ABC".to_string(),
            ],
            host_ids: vec![],
        };
        assert!(matches!(
            validate_scope_create_request(duplicate),
            Err(ApiError::Conflict(_))
        ));

        let invalid = ScopePatchRequest {
            name: None,
            comment: None,
            protection_requirement: None,
            target_ids: None,
            host_ids: Some(vec!["not-a-uuid".to_string()]),
        };
        assert!(matches!(
            validate_scope_patch_request(invalid),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn scope_patch_request_distinguishes_preserve_and_replace_membership() {
        let preserve = validate_scope_patch_request(ScopePatchRequest {
            name: None,
            comment: None,
            protection_requirement: None,
            target_ids: None,
            host_ids: None,
        })
        .expect("preserve-only patch");
        assert_eq!(preserve.target_ids, None);
        assert_eq!(preserve.host_ids, None);

        let replace = validate_scope_patch_request(ScopePatchRequest {
            name: Some("renamed".to_string()),
            comment: None,
            protection_requirement: Some("high".to_string()),
            target_ids: Some(vec![]),
            host_ids: Some(vec!["12345678-1234-1234-1234-123456789abc".to_string()]),
        })
        .expect("replace-membership patch");
        assert_eq!(replace.name.as_deref(), Some("renamed"));
        assert_eq!(replace.protection_requirement.as_deref(), Some("high"));
        assert_eq!(replace.target_ids, Some(vec![]));
        assert_eq!(
            replace.host_ids,
            Some(vec!["12345678-1234-1234-1234-123456789abc".to_string()])
        );
    }

    #[test]
    fn scope_mutability_guard_blocks_global_or_predefined_scopes() {
        assert!(ensure_scope_is_mutable(false, false).is_ok());
        for (is_global, predefined) in [(true, false), (false, true), (true, true)] {
            assert!(matches!(
                ensure_scope_is_mutable(is_global, predefined),
                Err(ApiError::Conflict(_))
            ));
        }
    }

    #[test]
    fn scope_reference_visibility_rejects_missing_or_unauthorized_membership() {
        let requested = vec![
            "12345678-1234-1234-1234-123456789abc".to_string(),
            "22345678-1234-1234-1234-123456789abc".to_string(),
        ];
        let visible = vec![
            "12345678-1234-1234-1234-123456789abc".to_string(),
            "22345678-1234-1234-1234-123456789abc".to_string(),
        ];
        assert!(ensure_scope_write_references_visible("target_ids", &requested, &visible).is_ok());

        let partial_visible = vec!["12345678-1234-1234-1234-123456789abc".to_string()];
        assert!(matches!(
            ensure_scope_write_references_visible("target_ids", &requested, &partial_visible),
            Err(ApiError::Forbidden)
        ));

        let empty: Vec<String> = vec![];
        assert!(
            ensure_scope_write_references_visible("host_ids", &empty, &partial_visible).is_ok()
        );
    }

    #[test]
    fn scope_write_transaction_plans_keep_validation_before_mutations() {
        let create = ValidatedScopeCreate {
            name: "scope".to_string(),
            comment: None,
            protection_requirement: "normal".to_string(),
            target_ids: vec!["12345678-1234-1234-1234-123456789abc".to_string()],
            host_ids: vec![],
        };
        assert_eq!(
            scope_create_transaction_plan(&create),
            ScopeWriteTransactionPlan {
                operation: ScopeWriteOperation::Create,
                steps: vec![
                    ScopeWriteStep::ResolveOperatorOwner,
                    ScopeWriteStep::VerifyReferenceVisibility,
                    ScopeWriteStep::InsertScope,
                    ScopeWriteStep::ReplaceTargetMembership,
                    ScopeWriteStep::ReplaceHostMembership,
                ],
            }
        );

        let patch = ValidatedScopePatch {
            name: Some("renamed".to_string()),
            comment: None,
            protection_requirement: None,
            target_ids: Some(vec![]),
            host_ids: None,
        };
        assert_eq!(
            scope_patch_transaction_plan(&patch),
            ScopeWriteTransactionPlan {
                operation: ScopeWriteOperation::Patch,
                steps: vec![
                    ScopeWriteStep::ResolveOperatorOwner,
                    ScopeWriteStep::VerifyScopeMutable,
                    ScopeWriteStep::VerifyReferenceVisibility,
                    ScopeWriteStep::UpdateScopeMetadata,
                    ScopeWriteStep::ReplaceTargetMembership,
                ],
            }
        );

        assert_eq!(
            scope_delete_transaction_plan(),
            ScopeWriteTransactionPlan {
                operation: ScopeWriteOperation::Delete,
                steps: vec![
                    ScopeWriteStep::ResolveOperatorOwner,
                    ScopeWriteStep::VerifyScopeMutable,
                    ScopeWriteStep::VerifyNoScopeReportHistory,
                    ScopeWriteStep::DeleteScopeMembership,
                    ScopeWriteStep::DeleteScope,
                ],
            }
        );
    }

    #[test]
    fn scope_write_scaffold_sql_is_read_only_and_targets_expected_tables() {
        for sql in [
            scope_write_operator_owner_sql(),
            scope_write_mutability_sql(),
            scope_write_report_history_sql(),
            scope_write_visible_targets_sql(),
            scope_write_visible_hosts_sql(),
        ] {
            let upper_sql = sql.to_ascii_uppercase();
            assert!(upper_sql.contains("SELECT"));
            for forbidden in ["INSERT", "UPDATE", "DELETE", "TRUNCATE"] {
                assert!(!upper_sql.contains(forbidden), "{forbidden} in {sql}");
            }
        }
        assert!(scope_write_operator_owner_sql().contains("FROM users"));
        assert!(scope_write_mutability_sql().contains("FROM scopes"));
        assert!(scope_write_report_history_sql().contains("FROM scope_reports"));
        assert!(scope_write_visible_targets_sql().contains("FROM targets"));
        assert!(scope_write_visible_hosts_sql().contains("FROM hosts"));
    }

    #[test]
    fn scope_write_mutation_sql_is_parameterized_and_scope_bounded() {
        assert!(scope_by_internal_id_sql().contains("WHERE id = $1"));

        let insert = scope_insert_sql();
        assert!(insert.contains("INSERT INTO scopes"));
        assert!(insert.contains("VALUES (make_uuid(), $1, $2, $3, $4, 0, 0"));
        assert!(insert.contains("RETURNING id::bigint, uuid::text"));

        let update = scope_update_metadata_sql();
        assert!(update.contains("UPDATE scopes"));
        assert!(update.contains("name = coalesce($2, name)"));
        assert!(update.contains("comment = coalesce($3, comment)"));
        assert!(update.contains("protection_requirement = coalesce($4, protection_requirement)"));
        assert!(update.contains("WHERE id = $1"));

        for (delete_sql, insert_sql, table, source_table) in [
            (
                scope_delete_targets_sql(),
                scope_insert_target_sql(),
                "scope_targets",
                "targets",
            ),
            (
                scope_delete_hosts_sql(),
                scope_insert_host_sql(),
                "scope_hosts",
                "hosts",
            ),
        ] {
            assert_eq!(delete_sql, format!("DELETE FROM {table} WHERE scope = $1;"));
            assert!(insert_sql.contains(table));
            assert!(insert_sql.contains(source_table));
            assert!(insert_sql.contains("WHERE uuid = $2"));
            assert!(insert_sql.contains("ON CONFLICT"));
        }

        assert_eq!(scope_delete_sql(), "DELETE FROM scopes WHERE id = $1;");
    }

    #[test]
    fn scope_write_execution_helpers_stay_private_transaction_scaffold() {
        let _create = execute_scope_create_transaction;
        let _patch = execute_scope_patch_transaction;
        let _delete = execute_scope_delete_transaction;

        let source = include_str!("scope_writes.rs");
        let create_body = source
            .split_once("pub(crate) async fn execute_scope_create_transaction")
            .expect("create executor must exist")
            .1
            .split_once("pub(crate) async fn execute_scope_patch_transaction")
            .expect("create executor must precede patch executor")
            .0;
        let patch_body = source
            .split_once("pub(crate) async fn execute_scope_patch_transaction")
            .expect("patch executor must exist")
            .1
            .split_once("pub(crate) async fn execute_scope_delete_transaction")
            .expect("patch executor must precede delete executor")
            .0;
        let delete_body = source
            .split_once("pub(crate) async fn execute_scope_delete_transaction")
            .expect("delete executor must exist")
            .1
            .split_once("async fn query_scope_write_record")
            .expect("delete executor must precede shared query helper")
            .0;

        assert!(create_body.contains("scope_insert_sql()"));
        assert!(create_body.contains("replace_scope_membership"));
        assert!(patch_body.contains("scope_update_metadata_sql()"));
        assert!(patch_body.contains("scope_by_internal_id_sql()"));
        assert!(delete_body.contains("scope_delete_targets_sql()"));
        assert!(delete_body.contains("scope_delete_hosts_sql()"));
        assert!(delete_body.contains("scope_delete_sql()"));
        for body in [create_body, patch_body, delete_body] {
            assert!(body.contains("tx,"));
            assert!(!body.contains("state.pool"));
            assert!(!body.contains("transaction().await"));
            assert!(!body.contains("commit().await"));
        }
    }

    #[test]
    fn scope_write_location_header_points_to_native_scope_detail() {
        let headers = scope_write_location_headers("12345678-1234-1234-1234-123456789abc")
            .expect("valid location header");

        assert_eq!(
            headers
                .get(header::LOCATION)
                .expect("location header")
                .to_str()
                .expect("ascii location"),
            "/api/v1/scopes/12345678-1234-1234-1234-123456789abc"
        );
    }

    #[test]
    fn scope_write_operator_guard_fails_closed_without_direct_context() {
        assert!(matches!(
            require_scope_write_operator(None),
            Err(ApiError::Forbidden)
        ));

        let operator = DirectApiOperator::new(
            "12345678-1234-1234-1234-123456789abc",
            Some("operator".to_string()),
        )
        .expect("valid direct operator");
        assert_eq!(
            require_scope_write_operator(Some(Extension(operator.clone()))).expect("operator"),
            operator
        );
    }

    #[test]
    fn scope_write_handlers_require_operator_transactions_and_payload_reload() {
        let _create = create_scope;
        let _patch = patch_scope;
        let _delete = delete_scope;

        let source = include_str!("scope_writes.rs");
        let create_body = source
            .split_once("pub(crate) async fn create_scope")
            .expect("create handler must exist")
            .1
            .split_once("pub(crate) async fn patch_scope")
            .expect("create handler must precede patch handler")
            .0;
        let patch_body = source
            .split_once("pub(crate) async fn patch_scope")
            .expect("patch handler must exist")
            .1
            .split_once("pub(crate) async fn delete_scope")
            .expect("patch handler must precede delete handler")
            .0;
        let delete_body = source
            .split_once("pub(crate) async fn delete_scope")
            .expect("delete handler must exist")
            .1
            .split_once("pub(crate) fn validate_scope_create_request")
            .expect("delete handler must precede DTO validation")
            .0;

        for body in [create_body, patch_body, delete_body] {
            assert!(body.contains("operator: Option<Extension<DirectApiOperator>>"));
            assert!(body.contains("let operator = require_scope_write_operator(operator)?;"));
            assert!(body.contains("state.pool.get()"));
            assert!(body.contains("client"));
            assert!(body.contains(".transaction()"));
            assert!(body.contains("resolve_scope_write_operator_owner(&tx, &operator).await?"));
            assert!(body.contains("tx.commit()"));
        }
        assert!(create_body.contains("verify_scope_write_references_visible"));
        assert!(patch_body.contains("load_mutable_scope_write_state"));
        assert!(patch_body.contains("verify_scope_write_references_visible"));
        assert!(delete_body.contains("ensure_scope_has_no_report_history"));
        for body in [create_body, patch_body] {
            assert!(body.contains("load_scope_detail(&client"));
        }
    }

    #[test]
    fn scope_write_scaffold_is_not_registered_as_a_live_route() {
        let main_source = include_str!("main.rs");
        let router_block = main_source
            .split_once("fn native_api_router() -> Router<AppState> {\n    Router::new()")
            .expect("router setup must exist")
            .1
            .split_once("\n}\n\nfn direct_native_api_router")
            .expect("base router setup must end before direct router")
            .0;

        assert!(main_source.contains("mod scope_writes;"));
        for forbidden in [
            "post(scope",
            "put(scope",
            "patch(scope",
            "delete(scope",
            "route(\"/api/v1/scopes\", post",
            "route(\"/api/v1/scopes/:scope_id\", patch",
            "route(\"/api/v1/scopes/:scope_id\", delete",
        ] {
            assert!(
                !router_block.contains(forbidden),
                "live scope write route: {forbidden}"
            );
        }
    }
}
