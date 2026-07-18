// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::unix_ts_to_rfc3339;

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
    alerts: Vec<ReportFormatReference>,
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
        alerts,
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
