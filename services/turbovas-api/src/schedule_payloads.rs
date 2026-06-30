// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Serialize)]
pub(crate) struct ScheduleTaskReference {
    id: String,
    name: String,
    usage_type: String,
}

#[derive(Serialize)]
pub(crate) struct ScheduleAssetItem {
    id: String,
    name: String,
    comment: String,
    icalendar: String,
    timezone: String,
    timezone_abbrev: Option<String>,
    task_count: i64,
    tasks: Vec<ScheduleTaskReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ScheduleAssetDetail {
    #[serde(flatten)]
    asset: ScheduleAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

pub(crate) fn schedule_task_from_row(row: &Row) -> ScheduleTaskReference {
    ScheduleTaskReference {
        id: row.get("id"),
        name: row.get("name"),
        usage_type: row.get("usage_type"),
    }
}

pub(crate) fn schedule_asset_from_row(
    row: &Row,
    tasks: Vec<ScheduleTaskReference>,
) -> ScheduleAssetItem {
    ScheduleAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        icalendar: row.get("icalendar"),
        timezone: row.get("timezone"),
        timezone_abbrev: None,
        task_count: row.get("task_count"),
        tasks,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn schedule_asset_detail_payload(
    asset: ScheduleAssetItem,
    user_tags: Vec<ReportUserTag>,
) -> ScheduleAssetDetail {
    ScheduleAssetDetail { asset, user_tags }
}
