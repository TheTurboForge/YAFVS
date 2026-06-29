// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    collections::{PORT_LIST_DEFAULT_SORT, PORT_LIST_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    user_tags::ReportUserTag,
};

#[derive(Serialize)]
pub(crate) struct PortRangeItem {
    id: String,
    protocol: String,
    start: i64,
    end: i64,
    comment: String,
}

#[derive(Serialize)]
struct PortCountItem {
    all: i64,
    tcp: i64,
    udp: i64,
}

#[derive(Serialize)]
pub(crate) struct PortListTargetReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct PortListAssetItem {
    id: String,
    name: String,
    comment: String,
    port_count: PortCountItem,
    port_ranges: Vec<PortRangeItem>,
    targets: Vec<PortListTargetReference>,
    predefined: bool,
    deprecated: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct PortListAssetDetail {
    #[serde(flatten)]
    asset: PortListAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

pub(crate) fn port_range_from_row(row: &Row) -> PortRangeItem {
    PortRangeItem {
        id: row.get("id"),
        protocol: row.get("protocol"),
        start: row.get("start"),
        end: row.get("end"),
        comment: row.get("comment"),
    }
}

pub(crate) fn port_list_target_from_row(row: &Row) -> PortListTargetReference {
    PortListTargetReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

pub(crate) fn port_list_asset_from_row(
    row: &Row,
    port_ranges: Vec<PortRangeItem>,
    targets: Vec<PortListTargetReference>,
) -> PortListAssetItem {
    PortListAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        port_count: PortCountItem {
            all: row.get("port_count_all"),
            tcp: row.get("port_count_tcp"),
            udp: row.get("port_count_udp"),
        },
        port_ranges,
        targets,
        predefined: row.get::<_, i32>("predefined_int") != 0,
        deprecated: row.get::<_, i32>("deprecated_int") != 0,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn port_list_asset_detail_payload(
    asset: PortListAssetItem,
    user_tags: Vec<ReportUserTag>,
) -> PortListAssetDetail {
    PortListAssetDetail { asset, user_tags }
}

pub(crate) async fn port_list_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<PortListAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, PORT_LIST_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, PORT_LIST_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH port_list_rows AS (
             SELECT pl.id AS internal_id,
                    pl.uuid AS id,
                    coalesce(pl.name, '') AS name,
                    coalesce(pl.comment, '') AS comment,
                    coalesce(pl.predefined, 0)::integer AS predefined_int,
                    0::integer AS deprecated_int,
                    coalesce(pl.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(pl.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                    ), 0)::bigint AS port_count_all,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                         AND pr.type = 0
                    ), 0)::bigint AS port_count_tcp,
                    coalesce((
                      SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                        FROM port_ranges pr
                       WHERE pr.port_list = pl.id
                         AND pr.type = 1
                    ), 0)::bigint AS port_count_udp
               FROM port_lists pl
         ),
         filtered AS (
             SELECT * FROM port_list_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| port_list_asset_from_row(row, Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn port_list_asset_detail(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    parse_uuid(&port_list_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT pl.id AS internal_id,
                      pl.uuid AS id,
                      coalesce(pl.name, '') AS name,
                      coalesce(pl.comment, '') AS comment,
                      coalesce(pl.predefined, 0)::integer AS predefined_int,
                      0::integer AS deprecated_int,
                      coalesce(pl.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(pl.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce((
                        SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                          FROM port_ranges pr
                         WHERE pr.port_list = pl.id
                      ), 0)::bigint AS port_count_all,
                      coalesce((
                        SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                          FROM port_ranges pr
                         WHERE pr.port_list = pl.id
                           AND pr.type = 0
                      ), 0)::bigint AS port_count_tcp,
                      coalesce((
                        SELECT sum((CASE WHEN pr."end" IS NULL THEN pr.start ELSE pr."end" END) - pr.start + 1)::bigint
                          FROM port_ranges pr
                         WHERE pr.port_list = pl.id
                           AND pr.type = 1
                      ), 0)::bigint AS port_count_udp
                 FROM port_lists pl
                WHERE pl.uuid = $1
                LIMIT 1;"#,
            &[&port_list_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let ranges = client
        .query(
            r#"SELECT pr.uuid AS id,
                      CASE WHEN pr.type = 1 THEN 'udp' ELSE 'tcp' END AS protocol,
                      coalesce(pr.start, 0)::bigint AS start,
                      coalesce(pr."end", pr.start, 0)::bigint AS "end",
                      coalesce(pr.comment, '') AS comment
                 FROM port_ranges pr
                WHERE pr.port_list = $1
                ORDER BY pr.type ASC, pr.start ASC, pr."end" ASC, pr.uuid ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list range query failed");
            ApiError::Database
        })?
        .iter()
        .map(port_range_from_row)
        .collect();
    let targets = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name
                 FROM targets t
                WHERE t.port_list = $1
                ORDER BY name ASC, id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list target backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(port_list_target_from_row)
        .collect();
    let user_tags = port_list_user_tags(&client, &port_list_id).await?;
    Ok(Json(port_list_asset_detail_payload(
        port_list_asset_from_row(&row, ranges, targets),
        user_tags,
    )))
}

pub(crate) fn port_list_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN port_lists pl ON pl.id = tr.resource
        WHERE lower(pl.uuid) = lower($1)
          AND tr.resource_type = 'port_list'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn port_list_user_tags(
    client: &tokio_postgres::Client,
    port_list_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(port_list_user_tags_sql(), &[&port_list_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "port list user-tag query failed");
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
