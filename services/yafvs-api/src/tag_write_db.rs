// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::Transaction;

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    tag_payloads::{TagAssetItem, tag_asset_from_row},
    tag_resource_helpers::{
        tag_resource_direct_write_requires_owner_match, tag_resource_direct_write_type_is_supported,
    },
    tag_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
    pub(crate) resource_type: String,
    pub(crate) resource_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TagTrashWriteState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) owner_id: Option<i32>,
    pub(crate) resource_type: String,
}

pub(crate) fn ensure_tag_is_human_owned(tag_owner_id: Option<i32>) -> Result<i32, ApiError> {
    tag_owner_id.ok_or_else(|| {
        tracing::warn!("direct API tag write rejected an ownerless tag");
        ApiError::Forbidden
    })
}

pub(crate) fn ensure_tag_resource_is_team_assignable(
    resource_type: &str,
    resource_owner_id: Option<i32>,
) -> Result<(), ApiError> {
    if !tag_resource_direct_write_requires_owner_match(resource_type) {
        return Ok(());
    }
    match resource_owner_id {
        Some(_) => Ok(()),
        None => {
            tracing::warn!(
                resource_type,
                "direct API tag resource write missing owner on owner-bearing resource type"
            );
            Err(ApiError::Forbidden)
        }
    }
}

pub(crate) fn require_tag_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("tag write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_tag_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    let sql = format!(
        "{} FOR KEY SHARE;",
        tag_write_operator_owner_sql().trim_end_matches(';')
    );
    tx.query_opt(&sql, &[&operator.user_uuid()])
        .await
        .map_err(|error| map_tag_write_db_error(error, "resolve tag write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API tag write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_tag_write_detail<C>(
    client: &C,
    tag_id: &str,
) -> Result<TagAssetItem, ApiError>
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

pub(crate) async fn load_tag_write_state(
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
        owner_id: row.get(2),
        resource_type: row.get(3),
        resource_count: row.get(4),
    })
}

pub(crate) async fn load_tag_trash_state(
    tx: &Transaction<'_>,
    tag_id: &str,
) -> Result<TagTrashWriteState, ApiError> {
    let tag_id = parse_uuid(tag_id)?.to_string();
    let row = tx
        .query_opt(tag_trash_state_sql(), &[&tag_id])
        .await
        .map_err(|error| map_tag_write_db_error(error, "load tag trash state"))?
        .ok_or(ApiError::NotFound)?;
    Ok(TagTrashWriteState {
        internal_id: row.get(0),
        uuid: row.get(1),
        owner_id: row.get(2),
        resource_type: row.get(3),
    })
}

pub(crate) async fn ensure_tag_uuid_not_live(
    tx: &Transaction<'_>,
    tag_uuid: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(tag_live_uuid_conflict_sql(), &[&tag_uuid])
        .await
        .map_err(|error| map_tag_write_db_error(error, "check live tag uuid conflict"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "tag with the same id already exists".to_string(),
        ))
    }
}

pub(crate) fn ensure_tag_resource_direct_write_type_is_supported(
    resource_type: &str,
) -> Result<(), ApiError> {
    if tag_resource_direct_write_type_is_supported(resource_type) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "tag resource type {resource_type} is not supported by direct resource writes"
        )))
    }
}

pub(crate) fn map_tag_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "tag write database operation failed");
    ApiError::Database
}

pub(crate) fn map_tag_commit_error(error: tokio_postgres::Error, action: &'static str) -> ApiError {
    tracing::error!(%error, action, "tag transaction commit outcome is indeterminate");
    ApiError::MutationOutcomeIndeterminate
}
