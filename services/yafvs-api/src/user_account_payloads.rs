// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::formatters::unix_ts_to_rfc3339;

#[derive(Debug, Serialize)]
pub(crate) struct UserAccountItem {
    id: String,
    name: String,
    comment: String,
    created_at: Option<String>,
    modified_at: Option<String>,
}

pub(crate) fn user_account_from_row(row: &Row) -> UserAccountItem {
    UserAccountItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
