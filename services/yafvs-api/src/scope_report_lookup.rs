// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Client;

use crate::errors::ApiError;

pub(crate) async fn scope_report_exists(
    client: &Client,
    scope_report_id: &str,
    scope_id: &str,
) -> Result<bool, ApiError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM scope_reports WHERE uuid = $1 AND scope_uuid = $2);",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(row.get::<_, bool>(0))
}

pub(crate) async fn scope_report_scope_uuid(
    client: &Client,
    scope_report_id: &str,
) -> Result<Option<String>, ApiError> {
    let row = client
        .query_opt(
            "SELECT scope_uuid FROM scope_reports WHERE uuid = $1;",
            &[&scope_report_id],
        )
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(row.map(|row| row.get::<_, String>(0)))
}
