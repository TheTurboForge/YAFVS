// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::port_list_user_tags_sql,
    collections::{PORT_LIST_DEFAULT_SORT, PORT_LIST_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    port_list_payloads::{
        PortListAssetDetail, PortListAssetItem, port_list_asset_detail_payload,
        port_list_asset_from_row, port_list_target_from_row, port_range_from_row,
    },
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    user_tags::ReportUserTag,
};

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
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "port list asset list",
    )
    .await?;
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
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_port_list_asset_detail(&client, &port_list_id).await?,
    ))
}

pub(crate) async fn export_port_list_metadata(
    State(state): State<AppState>,
    Path(port_list_id): Path<String>,
) -> Result<Json<PortListAssetDetail>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_port_list_asset_detail(&client, &port_list_id).await?,
    ))
}

pub(crate) async fn load_port_list_asset_detail(
    client: &tokio_postgres::Client,
    port_list_id: &str,
) -> Result<PortListAssetDetail, ApiError> {
    parse_uuid(&port_list_id)?;
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
    Ok(port_list_asset_detail_payload(
        port_list_asset_from_row(&row, ranges, targets),
        user_tags,
    ))
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
