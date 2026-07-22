// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Client;

use crate::errors::ApiError;

#[derive(Debug, Serialize)]
pub(crate) struct ReportUserTag {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) comment: String,
}

pub(crate) fn catalog_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
        WHERE (lower(tr.resource_uuid) = ANY($1::text[])
               OR ($3::integer IS NOT NULL AND tr.resource = $3))
          AND tr.resource_type = $2
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

pub(crate) async fn catalog_user_tags(
    client: &Client,
    resource_type: &str,
    resource_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let resource_ids = vec![resource_id.to_string()];
    catalog_user_tags_for_aliases_and_row_id(client, resource_type, &resource_ids, None).await
}

pub(crate) async fn catalog_user_tags_for_aliases_and_row_id(
    client: &Client,
    resource_type: &str,
    resource_ids: &[String],
    resource_row_id: Option<i32>,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let normalized_ids: Vec<String> = resource_ids
        .iter()
        .map(|resource_id| resource_id.trim())
        .filter(|resource_id| !resource_id.is_empty())
        .map(|resource_id| resource_id.to_ascii_lowercase())
        .collect();
    if normalized_ids.is_empty() && resource_row_id.is_none() {
        return Ok(Vec::new());
    }
    let rows = client
        .query(
            catalog_user_tags_sql(),
            &[&normalized_ids, &resource_type, &resource_row_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, resource_type, "catalog user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}
