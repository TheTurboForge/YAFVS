// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    asset_user_tag_query_sql::operating_system_user_tags_sql,
    collections::{OPERATING_SYSTEM_ASSET_DEFAULT_SORT, OPERATING_SYSTEM_ASSET_SORT_FIELDS},
    errors::ApiError,
    operating_system_payloads::{OperatingSystemAssetItem, operating_system_asset_from_row},
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn operating_system_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<OperatingSystemAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, OPERATING_SYSTEM_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, OPERATING_SYSTEM_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH latest_best_os AS (
             SELECT DISTINCT ON (hd.host)
                    hd.host, hd.value AS cpe
               FROM host_details hd
              WHERE hd.name = 'best_os_cpe'
              ORDER BY hd.host, hd.id DESC
         ),
         latest_host_severity AS (
             SELECT DISTINCT ON (hms.host)
                    hms.host,
                    round(CAST(hms.severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities hms
              ORDER BY hms.host, hms.creation_time DESC
         ),
         os_rows AS (
             SELECT oss.uuid AS id,
                    oss.name AS name,
                    coalesce(cpe_title(oss.name), '') AS title,
                    (
                      SELECT lhs.severity
                        FROM host_oss ho_latest
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_latest.host
                       WHERE ho_latest.os = oss.id
                       ORDER BY ho_latest.creation_time DESC
                       LIMIT 1
                    ) AS latest_severity,
                    (
                      SELECT max(lhs.severity)
                        FROM host_oss ho_highest
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_highest.host
                       WHERE ho_highest.os = oss.id
                    ) AS highest_severity,
                    (
                      SELECT round(CAST(avg(lhs.severity) AS numeric), 2)::double precision
                        FROM host_oss ho_average
                        LEFT JOIN latest_host_severity lhs ON lhs.host = ho_average.host
                       WHERE ho_average.os = oss.id
                    ) AS average_severity,
                    (
                      SELECT count(DISTINCT lbo.host)::bigint
                        FROM latest_best_os lbo
                       WHERE lbo.cpe = oss.name
                    ) AS hosts,
                    (
                      SELECT count(DISTINCT ho_all.host)::bigint
                        FROM host_oss ho_all
                       WHERE ho_all.os = oss.id
                    ) AS all_hosts,
                    coalesce(oss.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(oss.modification_time, 0)::bigint AS modified_at_unix
               FROM oss
         ),
         filtered AS (
             SELECT * FROM os_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(title) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "operating system asset list",
    )
    .await?;
    let items = rows.iter().map(operating_system_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn operating_system_asset_detail(
    State(state): State<AppState>,
    Path(os_id): Path<String>,
) -> Result<Json<OperatingSystemAssetItem>, ApiError> {
    parse_uuid(&os_id)?;
    let os_id = os_id.to_ascii_lowercase();
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"WITH latest_best_os AS (
             SELECT DISTINCT ON (hd.host)
                    hd.host, hd.value AS cpe
               FROM host_details hd
              WHERE hd.name = 'best_os_cpe'
              ORDER BY hd.host, hd.id DESC
         ),
         latest_host_severity AS (
             SELECT DISTINCT ON (hms.host)
                    hms.host,
                    round(CAST(hms.severity AS numeric), 1)::double precision AS severity
               FROM host_max_severities hms
              ORDER BY hms.host, hms.creation_time DESC
         )
         SELECT oss.uuid AS id,
                oss.name AS name,
                coalesce(cpe_title(oss.name), '') AS title,
                (
                  SELECT lhs.severity
                    FROM host_oss ho_latest
                    LEFT JOIN latest_host_severity lhs ON lhs.host = ho_latest.host
                   WHERE ho_latest.os = oss.id
                   ORDER BY ho_latest.creation_time DESC
                   LIMIT 1
                ) AS latest_severity,
                (
                  SELECT max(lhs.severity)
                    FROM host_oss ho_highest
                    LEFT JOIN latest_host_severity lhs ON lhs.host = ho_highest.host
                   WHERE ho_highest.os = oss.id
                ) AS highest_severity,
                (
                  SELECT round(CAST(avg(lhs.severity) AS numeric), 2)::double precision
                    FROM host_oss ho_average
                    LEFT JOIN latest_host_severity lhs ON lhs.host = ho_average.host
                   WHERE ho_average.os = oss.id
                ) AS average_severity,
                (
                  SELECT count(DISTINCT lbo.host)::bigint
                    FROM latest_best_os lbo
                   WHERE lbo.cpe = oss.name
                ) AS hosts,
                (
                  SELECT count(DISTINCT ho_all.host)::bigint
                    FROM host_oss ho_all
                   WHERE ho_all.os = oss.id
                ) AS all_hosts,
                coalesce(oss.creation_time, 0)::bigint AS created_at_unix,
                coalesce(oss.modification_time, 0)::bigint AS modified_at_unix
           FROM oss
          WHERE oss.uuid = $1
          LIMIT 1;"#,
            &[&os_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = operating_system_asset_from_row(&row);
    item.user_tags = operating_system_user_tags(&client, &os_id).await?;
    Ok(Json(item))
}

pub(crate) async fn operating_system_asset_export(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<OperatingSystemAssetItem>, ApiError> {
    operating_system_asset_detail(state, path).await
}

async fn operating_system_user_tags(
    client: &tokio_postgres::Client,
    os_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(operating_system_user_tags_sql(), &[&os_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "operating system user-tag query failed");
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
