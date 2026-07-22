// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    errors::ApiError,
    tls_certificate_write_db::ensure_tls_certificate_is_human_owned,
    tls_certificate_write_sql::{
        tls_certificate_delete_certificate_sql, tls_certificate_delete_orphan_locations_sql,
        tls_certificate_delete_orphan_origins_sql, tls_certificate_delete_permissions_sql,
        tls_certificate_delete_sources_sql, tls_certificate_delete_tag_resources_sql,
        tls_certificate_write_state_sql,
    },
    tls_certificate_write_transactions::execute_tls_certificate_delete_transaction,
};

#[test]
fn tls_certificate_delete_accepts_any_human_owner_and_rejects_ownerless_assets() {
    assert!(ensure_tls_certificate_is_human_owned(Some(1)).is_ok());
    assert!(ensure_tls_certificate_is_human_owned(Some(2)).is_ok());
    assert!(matches!(
        ensure_tls_certificate_is_human_owned(None),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn tls_certificate_delete_sql_matches_inherited_delete_shape() {
    let state_sql = tls_certificate_write_state_sql();
    assert!(state_sql.contains("FROM tls_certificates"));
    assert!(state_sql.contains("WHERE uuid = $1"));
    assert!(state_sql.contains("owner::integer"));

    assert!(tls_certificate_delete_permissions_sql().contains("resource_type = 'tls_certificate'"));
    assert!(tls_certificate_delete_permissions_sql().contains("resource_location = 0"));
    assert!(
        tls_certificate_delete_tag_resources_sql().contains("resource_type = 'tls_certificate'")
    );
    assert_eq!(
        tls_certificate_delete_sources_sql(),
        "DELETE FROM tls_certificate_sources\n      WHERE tls_certificate = $1;"
    );
    assert!(tls_certificate_delete_orphan_locations_sql().contains("NOT EXISTS"));
    assert!(
        tls_certificate_delete_orphan_locations_sql()
            .contains("WHERE location = tls_certificate_locations.id")
    );
    assert!(
        tls_certificate_delete_orphan_origins_sql()
            .contains("WHERE origin = tls_certificate_origins.id")
    );
    assert_eq!(
        tls_certificate_delete_certificate_sql(),
        "DELETE FROM tls_certificates WHERE id = $1;"
    );

    let combined = [
        tls_certificate_delete_permissions_sql(),
        tls_certificate_delete_tag_resources_sql(),
        tls_certificate_delete_sources_sql(),
        tls_certificate_delete_orphan_locations_sql(),
        tls_certificate_delete_orphan_origins_sql(),
        tls_certificate_delete_certificate_sql(),
    ]
    .join("\n");
    for forbidden in ["credentials", "private_key", "password", "tasks", "reports"] {
        assert!(
            !combined.contains(forbidden),
            "TLS certificate delete must not touch {forbidden}"
        );
    }
    let _ = execute_tls_certificate_delete_transaction;
}

#[test]
fn tls_certificate_delete_handler_preserves_human_owner_check_order() {
    let source = include_str!("tls_certificate_writes.rs");
    let body = source
        .split_once("pub(crate) async fn delete_tls_certificate")
        .expect("delete handler")
        .1;
    assert!(
        body.find("resolve_tls_certificate_write_operator_owner")
            .unwrap()
            < body.find("load_tls_certificate_write_state").unwrap()
    );
    assert!(
        body.find("load_tls_certificate_write_state").unwrap()
            < body.find("ensure_tls_certificate_is_human_owned").unwrap()
    );
    assert!(
        body.find("ensure_tls_certificate_is_human_owned").unwrap()
            < body
                .find("execute_tls_certificate_delete_transaction")
                .unwrap()
    );
}
