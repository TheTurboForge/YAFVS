// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_postgres::Transaction;

use crate::{
    errors::ApiError,
    tls_certificate_write_db::execute_tls_certificate_write_sql,
    tls_certificate_write_sql::{
        tls_certificate_delete_certificate_sql, tls_certificate_delete_orphan_locations_sql,
        tls_certificate_delete_orphan_origins_sql, tls_certificate_delete_permissions_sql,
        tls_certificate_delete_sources_sql, tls_certificate_delete_tag_resources_sql,
    },
};

pub(crate) async fn execute_tls_certificate_delete_transaction(
    tx: &Transaction<'_>,
    certificate_internal_id: i32,
) -> Result<(), ApiError> {
    execute_tls_certificate_write_sql(
        tx,
        tls_certificate_delete_permissions_sql(),
        &[&certificate_internal_id],
        "delete TLS certificate permissions",
    )
    .await?;
    execute_tls_certificate_write_sql(
        tx,
        tls_certificate_delete_tag_resources_sql(),
        &[&certificate_internal_id],
        "delete TLS certificate tag resources",
    )
    .await?;
    execute_tls_certificate_write_sql(
        tx,
        tls_certificate_delete_sources_sql(),
        &[&certificate_internal_id],
        "delete TLS certificate sources",
    )
    .await?;
    execute_tls_certificate_write_sql(
        tx,
        tls_certificate_delete_orphan_locations_sql(),
        &[],
        "delete TLS certificate orphan locations",
    )
    .await?;
    execute_tls_certificate_write_sql(
        tx,
        tls_certificate_delete_orphan_origins_sql(),
        &[],
        "delete TLS certificate orphan origins",
    )
    .await?;
    execute_tls_certificate_write_sql(
        tx,
        tls_certificate_delete_certificate_sql(),
        &[&certificate_internal_id],
        "delete TLS certificate",
    )
    .await?;
    Ok(())
}
