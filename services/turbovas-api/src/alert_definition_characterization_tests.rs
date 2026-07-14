// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const HANDLER: &str = include_str!("alert_definition.rs");
const DATABASE: &str = include_str!("alert_definition_db.rs");
const PAYLOADS: &str = include_str!("alert_definition_payloads.rs");
const SQL: &str = include_str!("alert_definition_sql.rs");
const TRANSACTIONS: &str = include_str!("alert_definition_transactions.rs");
const DIRECT_ROUTES: &str = include_str!("direct_api_routes.rs");
const BROWSER_ROUTES: &str = include_str!("browser_proxy_routes.rs");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const GSAD_PROXY: &str = include_str!("../../../components/gsad/src/gsad_native_api.c");
const GSA_USER: &str = include_str!("../../../components/gsa/src/gmp/commands/user.ts");

#[test]
fn inherited_modify_alert_gaps_are_not_repeated() {
    assert!(SQL.contains("FOR UPDATE"));
    assert!(SQL.contains("filter = NULL"));
    assert!(SQL.contains("$2::boolean"));
    assert!(!SQL.contains("filter = 0"));
    assert!(TRANSACTIONS.contains("prepare(alert_definition_insert_method_data_sql())"));
    assert!(PAYLOADS.contains("deny_unknown_fields"));
    assert!(!DATABASE.contains("format!("));
}

#[test]
fn replacement_locks_namespace_target_owner_and_references_before_writes() {
    let handler = HANDLER
        .split("pub(crate) async fn put_alert_definition")
        .nth(1)
        .expect("PUT alert definition handler");
    let owner = handler
        .find("resolve_alert_definition_operator_owner")
        .unwrap();
    let namespace = handler.find("LOCK TABLE alerts").unwrap();
    let target = handler
        .find("load_alert_definition_state_for_update")
        .unwrap();
    let revision = handler
        .find("ensure_alert_definition_revision_matches")
        .unwrap();
    let uniqueness = handler.find("ensure_unique_alert_definition_name").unwrap();
    let references = handler.find("lock_alert_definition_references").unwrap();
    let replace = handler
        .find("execute_alert_definition_replace_transaction")
        .unwrap();
    assert!(owner < namespace);
    assert!(namespace < target);
    assert!(target < revision);
    assert!(revision < uniqueness);
    assert!(target < uniqueness);
    assert!(uniqueness < references);
    assert!(references < replace);
    assert!(SQL.matches("FOR SHARE").count() >= 3);
    assert!(handler.contains("LOCK TABLE credentials_data IN SHARE MODE"));
}

#[test]
fn reads_and_all_credential_references_are_operator_owned() {
    assert!(SQL.contains("AND a.owner = $2"));
    assert!(
        DATABASE
            .matches("ensure_owned_credential(&credential, owner_id)?")
            .count()
            >= 3
    );
    assert!(DATABASE.contains("alert_definition_read_sql(), &[&alert_id, &owner_id]"));
}

#[test]
fn collision_reference_and_commit_failures_have_explicit_contracts() {
    assert!(HANDLER.contains("ensure_unique_alert_definition_name"));
    assert!(DATABASE.contains(".ok_or(ApiError::NotFound)"));
    assert!(DATABASE.contains("Err(ApiError::Forbidden)"));
    assert!(DATABASE.contains("map_alert_definition_commit_error"));
    assert!(DATABASE.contains("ApiError::MutationOutcomeIndeterminate"));
    assert!(HANDLER.contains("ApiError::MutationCommittedResponseUnavailable"));
    assert!(!DATABASE.contains("tracing::warn!(%error"));
    assert!(!DATABASE.contains("tracing::error!(%error"));
}

#[test]
fn snmp_preserve_never_selects_or_reinserts_the_secret() {
    assert!(SQL.contains("WHEN amd.name = 'snmp_community'"));
    assert!(SQL.contains("THEN NULL::text"));
    assert!(SQL.contains("coalesce(amd.data, '') <> ''"));
    assert!(SQL.matches("AND amd.name = 'snmp_community') = 1").count() >= 2);
    assert!(SQL.contains("name <> 'snmp_community'"));
    assert!(TRANSACTIONS.contains("ValidatedSnmpCommunity::Replace(community)"));
    assert!(!TRANSACTIONS.contains("ValidatedSnmpCommunity::Preserve(community)"));
    assert!(!PAYLOADS.contains("snmp_community: String"));
}

#[test]
fn authenticated_direct_and_browser_routes_cover_get_and_put() {
    for routes in [DIRECT_ROUTES, BROWSER_ROUTES] {
        assert!(routes.contains("/api/v1/alerts/:alert_id/definition"));
    }
    assert!(DIRECT_ROUTES.contains("get(get_alert_definition)"));
    assert!(DIRECT_ROUTES.contains("put(put_alert_definition)"));
    let gate = DIRECT_ROUTES.find("if write_control_enabled").unwrap();
    assert!(DIRECT_ROUTES.find("get(get_alert_definition)").unwrap() < gate);
    assert!(gate < DIRECT_ROUTES.find("put(put_alert_definition)").unwrap());
    assert!(BROWSER_ROUTES.contains("get(browser_proxy_get_alert_definition)"));
    assert!(BROWSER_ROUTES.contains("put(browser_proxy_put_alert_definition)"));
    assert!(GSAD_PROXY.contains("if (native_api_put_path_is_allowed (path))"));
    assert!(
        GSAD_PROXY
            .contains("body = fetch_native_api_json (\"GET\", request_target, NULL, 0, secret,")
    );
    assert!(GSA_USER.contains("'create_alert'"));
    assert!(GSA_USER.contains("'modify_alert'"));
}

#[test]
fn full_replacement_requires_an_optimistic_revision_before_mutation() {
    assert!(SQL.contains("a.xmin::text AS revision"));
    assert!(SQL.contains("a.xmin::text,"));
    assert!(PAYLOADS.contains("pub(crate) expected_revision: String"));
    assert!(HANDLER.contains("ensure_alert_definition_revision_matches"));
    assert!(OPENAPI.contains("a stale value returns 409"));
}

#[test]
fn openapi_marks_non_retained_alert_semantics_as_intentional() {
    let definition_path = OPENAPI
        .split("  /alerts/{alert_id}/definition:\n")
        .nth(1)
        .expect("definition path")
        .split("\n  /alerts/{alert_id}/clone:")
        .next()
        .unwrap();
    assert!(!definition_path.contains("x-turbovas-inherited-still-owns"));
    assert_eq!(
        definition_path
            .matches("intentionally not retained")
            .count(),
        2
    );
}
