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
    app_state::AppState, auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid,
    scope_payload_rows::ScopeItem, scope_payloads::load_scope_detail,
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
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeWriteState {
    internal_id: i32,
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
    owner_id: i32,
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
    scope_internal_id: i32,
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
    scope_internal_id: i32,
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
) -> Result<i32, ApiError> {
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
    scope_internal_id: i32,
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
    "SELECT id::integer, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn scope_write_mutability_sql() -> &'static str {
    "SELECT id::integer, coalesce(predefined, 0)::integer, coalesce(is_global, 0)::integer
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
    "SELECT id::integer, uuid::text
       FROM scopes
      WHERE id = $1;"
}

pub(crate) fn scope_insert_sql() -> &'static str {
    "INSERT INTO scopes
        (uuid, owner, name, comment, protection_requirement, predefined, is_global,
         creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, $3, $4, 0, 0, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn scope_update_metadata_sql() -> &'static str {
    "UPDATE scopes
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            protection_requirement = coalesce($4, protection_requirement),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
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
#[path = "scope_writes_tests.rs"]
mod scope_writes_tests;
