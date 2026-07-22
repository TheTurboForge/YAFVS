// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

#[derive(Debug, Serialize)]
pub(crate) struct NvtEpssItem {
    score: f64,
    percentile: f64,
    cve: String,
    severity: f64,
}

pub(crate) fn nvt_epss_from_row(row: &Row) -> Option<NvtEpssItem> {
    let score = row.get::<_, Option<f64>>("max_epss_score")?;
    Some(NvtEpssItem {
        score,
        percentile: row
            .get::<_, Option<f64>>("max_epss_percentile")
            .unwrap_or(0.0),
        cve: row
            .get::<_, Option<String>>("max_epss_cve")
            .unwrap_or_default(),
        severity: row
            .get::<_, Option<f64>>("max_epss_severity")
            .unwrap_or(0.0),
    })
}

pub(crate) fn nvt_max_severity_from_row(row: &Row) -> Option<NvtEpssItem> {
    let score = row.get::<_, Option<f64>>("epss_score")?;
    Some(NvtEpssItem {
        score,
        percentile: row.get::<_, Option<f64>>("epss_percentile").unwrap_or(0.0),
        cve: row.get::<_, Option<String>>("epss_cve").unwrap_or_default(),
        severity: row.get::<_, Option<f64>>("epss_severity").unwrap_or(0.0),
    })
}
