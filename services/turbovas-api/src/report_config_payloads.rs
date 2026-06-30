// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::{Client, Row};

use crate::{errors::ApiError, formatters::unix_ts_to_rfc3339};

#[derive(Serialize)]
struct ReportConfigOwner {
    name: String,
}

#[derive(Serialize)]
pub(crate) struct ReportConfigValueReference {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct ReportConfigParamOption {
    value: String,
}

#[derive(Serialize)]
struct ReportConfigParamItem {
    name: String,
    #[serde(rename = "type")]
    param_type: String,
    value: String,
    default: String,
    using_default: bool,
    min: Option<i64>,
    max: Option<i64>,
    options: Vec<ReportConfigParamOption>,
    value_report_formats: Vec<ReportConfigValueReference>,
    default_report_formats: Vec<ReportConfigValueReference>,
}

#[derive(Serialize)]
pub(crate) struct ReportConfigAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: ReportConfigOwner,
    report_format: ReportConfigValueReference,
    writable: bool,
    in_use: bool,
    orphan: bool,
    alerts: Vec<ReportConfigValueReference>,
    params: Vec<ReportConfigParamItem>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

fn report_config_param_type_name(type_int: i64) -> String {
    match type_int {
        0 => "boolean",
        1 => "integer",
        2 => "selection",
        3 => "string",
        4 => "text",
        5 => "report_format_list",
        6 => "multi_selection",
        _ => "string",
    }
    .to_string()
}

fn report_config_reference_from_row(row: &Row) -> ReportConfigValueReference {
    ReportConfigValueReference {
        id: row.get("id"),
        name: row.get("name"),
    }
}

fn report_config_param_options_from_rows(rows: &[Row]) -> Vec<ReportConfigParamOption> {
    rows.iter()
        .map(|row| ReportConfigParamOption {
            value: row.get("value"),
        })
        .collect()
}

async fn report_config_param_values_from_csv(
    client: &Client,
    report_format_ids: &str,
) -> Result<Vec<ReportConfigValueReference>, ApiError> {
    let mut values = Vec::new();
    for report_format_id in report_format_ids
        .split(',')
        .map(str::trim)
        .filter(|report_format_id| !report_format_id.is_empty())
    {
        let reference = client
            .query_opt(
                r#"SELECT rf.uuid AS id,
                          coalesce(rf.name, '') AS name
                     FROM report_formats rf
                    WHERE rf.uuid = $1
                    LIMIT 1;"#,
                &[&report_format_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report config report-format reference query failed");
                ApiError::Database
            })?;
        values.push(match reference {
            Some(row) => report_config_reference_from_row(&row),
            None => ReportConfigValueReference {
                id: report_format_id.to_string(),
                name: String::new(),
            },
        });
    }
    Ok(values)
}

async fn report_config_param_from_row(
    client: &Client,
    row: &Row,
) -> Result<ReportConfigParamItem, ApiError> {
    let param_type_int = i64::from(row.get::<_, i32>("type_int"));
    let value = row.get::<_, String>("value");
    let default = row.get::<_, String>("default_value");
    let value_report_formats = if param_type_int == 5 {
        report_config_param_values_from_csv(client, &value).await?
    } else {
        Vec::new()
    };
    let default_report_formats = if param_type_int == 5 {
        report_config_param_values_from_csv(client, &default).await?
    } else {
        Vec::new()
    };
    let options = if param_type_int == 2 || param_type_int == 6 {
        let param_id: i32 = row.get("format_param_id");
        let rows = client
            .query(
                r#"SELECT coalesce(value, '') AS value
                     FROM report_format_param_options
                    WHERE report_format_param = $1
                    ORDER BY value ASC;"#,
                &[&param_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report config param options query failed");
                ApiError::Database
            })?;
        report_config_param_options_from_rows(&rows)
    } else {
        Vec::new()
    };

    Ok(ReportConfigParamItem {
        name: row.get("name"),
        param_type: report_config_param_type_name(param_type_int),
        value,
        default,
        using_default: row.get::<_, i32>("using_default") != 0,
        min: row.get("min"),
        max: row.get("max"),
        options,
        value_report_formats,
        default_report_formats,
    })
}

pub(crate) async fn report_config_asset_from_row(
    client: &Client,
    row: &Row,
) -> Result<ReportConfigAssetItem, ApiError> {
    let report_config_id: String = row.get("id");
    let internal_id: i32 = row.get("internal_id");
    let report_format_rowid: i32 = row.get("report_format_rowid");
    let alerts: Vec<ReportConfigValueReference> = client
        .query(
            r#"SELECT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alerts a
                 JOIN alert_method_data amd ON amd.alert = a.id
                WHERE amd.data = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_config_reference_from_row)
        .collect();
    let in_use = !alerts.is_empty();
    let params = if report_format_rowid == 0 {
        Vec::new()
    } else {
        let mut params = Vec::new();
        for param_row in client
            .query(
                r#"SELECT rcp.id AS config_param_id,
                          rfp.id AS format_param_id,
                          coalesce(rfp.name, '') AS name,
                          coalesce(rfp.type, 100)::integer AS type_int,
                          coalesce(rcp.value, rfp.value, rfp.fallback) AS value,
                          coalesce(rfp.value, rfp.fallback) AS default_value,
                          rfp.type_min AS min,
                          rfp.type_max AS max,
                          (rcp.id IS NULL)::integer AS using_default
                     FROM report_format_params rfp
                     LEFT JOIN report_config_params rcp
                       ON rcp.name = rfp.name
                      AND rcp.report_config = $1
                    WHERE rfp.report_format = $2
                    ORDER BY name ASC, format_param_id ASC;"#,
                &[&internal_id, &report_format_rowid],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report config params query failed");
                ApiError::Database
            })?
        {
            params.push(report_config_param_from_row(client, &param_row).await?);
        }
        params
    };
    let report_format = ReportConfigValueReference {
        id: row.get("report_format_id"),
        name: row.get("report_format_name"),
    };

    Ok(ReportConfigAssetItem {
        id: report_config_id,
        name: row.get("name"),
        comment: row.get("comment"),
        owner: ReportConfigOwner {
            name: row.get("owner_name"),
        },
        report_format,
        writable: true,
        in_use,
        orphan: row.get::<_, i32>("orphan") != 0,
        alerts,
        params,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_config_param_types_match_existing_contract() {
        assert_eq!(report_config_param_type_name(0), "boolean");
        assert_eq!(report_config_param_type_name(1), "integer");
        assert_eq!(report_config_param_type_name(2), "selection");
        assert_eq!(report_config_param_type_name(3), "string");
        assert_eq!(report_config_param_type_name(4), "text");
        assert_eq!(report_config_param_type_name(5), "report_format_list");
        assert_eq!(report_config_param_type_name(6), "multi_selection");
        assert_eq!(report_config_param_type_name(100), "string");
    }
}
