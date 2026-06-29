// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{REPORT_FORMAT_DEFAULT_SORT, REPORT_FORMAT_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
};

#[derive(Serialize)]
pub(crate) struct ReportFormatReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct ReportFormatParamOption {
    value: String,
}

#[derive(Serialize)]
pub(crate) struct ReportFormatParamItem {
    name: String,
    #[serde(rename = "type")]
    param_type: String,
    value: String,
    default: String,
    min: Option<i64>,
    max: Option<i64>,
    options: Vec<ReportFormatParamOption>,
}

#[derive(Serialize)]
pub(crate) struct ReportFormatAssetItem {
    id: String,
    name: String,
    summary: String,
    description: String,
    extension: String,
    content_type: String,
    report_type: String,
    trust: String,
    trust_time: Option<String>,
    active: bool,
    predefined: bool,
    configurable: bool,
    deprecated: bool,
    alert_count: i64,
    report_config_count: i64,
    alerts: Vec<ReportFormatReference>,
    report_configs: Vec<ReportFormatReference>,
    params: Vec<ReportFormatParamItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn report_format_reference_from_row(row: &Row) -> ReportFormatReference {
    ReportFormatReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

pub(crate) fn report_format_param_option_from_row(row: &Row) -> ReportFormatParamOption {
    ReportFormatParamOption {
        value: row.get("value"),
    }
}

fn report_format_param_type(type_int: i32) -> String {
    match type_int {
        0 => "boolean",
        1 => "integer",
        2 => "selection",
        3 => "string",
        4 => "text",
        5 => "report_format_list",
        6 => "multi_selection",
        _ => "error",
    }
    .to_string()
}

pub(crate) fn report_format_param_from_row(
    row: &Row,
    options: Vec<ReportFormatParamOption>,
) -> ReportFormatParamItem {
    ReportFormatParamItem {
        name: row.get("name"),
        param_type: report_format_param_type(row.get("type_int")),
        value: row.get("value"),
        default: row.get("fallback"),
        min: row.get("min"),
        max: row.get("max"),
        options,
    }
}

fn report_format_trust(trust: i32, predefined: bool) -> String {
    if predefined {
        return "yes".to_string();
    }
    match trust {
        1 => "yes",
        2 => "no",
        _ => "unknown",
    }
    .to_string()
}

pub(crate) fn report_format_asset_from_row(
    row: &Row,
    alerts: Vec<ReportFormatReference>,
    report_configs: Vec<ReportFormatReference>,
    params: Vec<ReportFormatParamItem>,
) -> ReportFormatAssetItem {
    let predefined = row.get::<_, i32>("predefined_int") != 0;
    ReportFormatAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        summary: row.get("summary"),
        description: row.get("description"),
        extension: row.get("extension"),
        content_type: row.get("content_type"),
        report_type: row.get("report_type"),
        trust: report_format_trust(row.get("trust_int"), predefined),
        trust_time: unix_ts_to_rfc3339(row.get("trust_time_unix")),
        active: row.get::<_, i32>("active_int") != 0,
        predefined,
        configurable: row.get::<_, i32>("configurable_int") != 0,
        deprecated: row.get::<_, i32>("deprecated_int") != 0,
        alert_count: row.get("alert_count"),
        report_config_count: row.get("report_config_count"),
        alerts,
        report_configs,
        params,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_format_param_types_match_existing_contract() {
        assert_eq!(report_format_param_type(0), "boolean");
        assert_eq!(report_format_param_type(1), "integer");
        assert_eq!(report_format_param_type(2), "selection");
        assert_eq!(report_format_param_type(3), "string");
        assert_eq!(report_format_param_type(4), "text");
        assert_eq!(report_format_param_type(5), "report_format_list");
        assert_eq!(report_format_param_type(6), "multi_selection");
        assert_eq!(report_format_param_type(100), "error");
    }

    #[test]
    fn report_format_trust_preserves_predefined_override() {
        assert_eq!(report_format_trust(1, false), "yes");
        assert_eq!(report_format_trust(2, false), "no");
        assert_eq!(report_format_trust(3, false), "unknown");
        assert_eq!(report_format_trust(2, true), "yes");
    }
}

pub(crate) async fn report_format_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportFormatAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_FORMAT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_FORMAT_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH report_format_rows AS (
             SELECT rf.id AS internal_id,
                    rf.uuid AS id,
                    coalesce(rf.name, '') AS name,
                    coalesce(rf.summary, '') AS summary,
                    coalesce(rf.description, '') AS description,
                    coalesce(rf.extension, '') AS extension,
                    coalesce(rf.content_type, '') AS content_type,
                    coalesce(rf.report_type, '') AS report_type,
                    coalesce(rf.trust, 3)::integer AS trust_int,
                    coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                    coalesce(rf.flags & 1, 0)::integer AS active_int,
                    coalesce(rf.predefined, 0)::integer AS predefined_int,
                    (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                    (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                    coalesce((SELECT count(DISTINCT a.id)::bigint
                                FROM alerts a
                                JOIN alert_method_data amd ON amd.alert = a.id
                               WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                    coalesce((SELECT count(DISTINCT rc.id)::bigint
                                FROM report_configs rc
                               WHERE rc.report_format_id = rf.uuid), 0)::bigint AS report_config_count,
                    coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
               FROM report_formats rf
         ),
         filtered AS (
             SELECT * FROM report_format_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR lower(extension) LIKE '%' || lower($1) || '%'
                     OR lower(content_type) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| report_format_asset_from_row(row, Vec::new(), Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_format_asset_detail(
    State(state): State<AppState>,
    Path(report_format_id): Path<String>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    parse_uuid(&report_format_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT rf.id AS internal_id,
                      rf.uuid AS id,
                      coalesce(rf.name, '') AS name,
                      coalesce(rf.summary, '') AS summary,
                      coalesce(rf.description, '') AS description,
                      coalesce(rf.extension, '') AS extension,
                      coalesce(rf.content_type, '') AS content_type,
                      coalesce(rf.report_type, '') AS report_type,
                      coalesce(rf.trust, 3)::integer AS trust_int,
                      coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                      coalesce(rf.flags & 1, 0)::integer AS active_int,
                      coalesce(rf.predefined, 0)::integer AS predefined_int,
                      (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                      (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                      coalesce((SELECT count(DISTINCT a.id)::bigint
                                  FROM alerts a
                                  JOIN alert_method_data amd ON amd.alert = a.id
                                 WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                      coalesce((SELECT count(DISTINCT rc.id)::bigint
                                  FROM report_configs rc
                                 WHERE rc.report_format_id = rf.uuid), 0)::bigint AS report_config_count,
                      coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
                 FROM report_formats rf
                WHERE rf.uuid = $1
                LIMIT 1;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let alerts = client
        .query(
            r#"SELECT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alerts a
                 JOIN alert_method_data amd ON amd.alert = a.id
                WHERE amd.data = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let report_configs = client
        .query(
            r#"SELECT rc.uuid AS id,
                      coalesce(rc.name, '') AS name
                 FROM report_configs rc
                WHERE rc.report_format_id = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format config backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let mut params = Vec::new();
    for param_row in client
        .query(
            r#"SELECT rfp.id AS internal_id,
                      coalesce(rfp.name, '') AS name,
                      coalesce(rfp.type, 100)::integer AS type_int,
                      coalesce(rfp.value, '') AS value,
                      coalesce(rfp.fallback, '') AS fallback,
                      rfp.type_min AS min,
                      rfp.type_max AS max
                 FROM report_format_params rfp
                WHERE rfp.report_format = $1
                ORDER BY name ASC, internal_id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format params query failed");
            ApiError::Database
        })?
    {
        let param_id: i32 = param_row.get("internal_id");
        let options = client
            .query(
                r#"SELECT coalesce(value, '') AS value
                     FROM report_format_param_options
                    WHERE report_format_param = $1
                    ORDER BY value ASC;"#,
                &[&param_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report format param options query failed");
                ApiError::Database
            })?
            .iter()
            .map(report_format_param_option_from_row)
            .collect();
        params.push(report_format_param_from_row(&param_row, options));
    }

    Ok(Json(report_format_asset_from_row(
        &row,
        alerts,
        report_configs,
        params,
    )))
}
