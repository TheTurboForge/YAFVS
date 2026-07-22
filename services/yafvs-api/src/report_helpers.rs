// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::errors::ApiError;

pub(crate) async fn raw_report_exists(
    client: &tokio_postgres::Client,
    report_id: &str,
) -> Result<bool, ApiError> {
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM reports WHERE lower(uuid) = lower($1));",
            &[&report_id],
        )
        .await
        .map_err(|_| ApiError::Database)?;
    Ok(row.get::<_, bool>(0))
}
