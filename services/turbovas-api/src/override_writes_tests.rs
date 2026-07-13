// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::{errors::ApiError, override_write_sql::*};

const HANDLER_SOURCE: &str = include_str!("override_writes.rs");
const TRANSACTION_SOURCE: &str = include_str!("override_write_transactions.rs");
const BROWSER_PROXY_SOURCE: &str = include_str!("browser_proxy_metadata_patch.rs");
const BROWSER_PROXY_ROUTES_SOURCE: &str = include_str!("browser_proxy_routes.rs");
const DIRECT_ROUTES_SOURCE: &str = include_str!("direct_api_routes.rs");
const INHERITED_PERMISSIONS_SOURCE: &str =
    include_str!("../../../components/gvmd/src/manage_sql_permissions.c");

#[test]
fn override_delete_requires_exact_operator_owner_match() {
    assert!(ensure_override_owner_matches_operator(7, 7).is_ok());
    assert!(matches!(
        ensure_override_owner_matches_operator(7, 8),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn override_create_patch_and_clone_sql_are_parameterized_and_cache_safe() {
    let insert = override_insert_sql();
    for required in [
        "INSERT INTO overrides",
        "make_uuid()",
        "CASE WHEN $10 = -1 THEN 0",
        "m_now() + ($10 * 86400)",
        "SELECT id FROM result_nvts WHERE nvt = $2",
        "RETURNING id::integer, uuid::text",
    ] {
        assert!(insert.contains(required), "create SQL missing {required}");
    }

    let patch = override_patch_sql();
    for required in [
        "nvt = CASE WHEN $2 THEN $3 ELSE nvt END",
        "hosts = CASE WHEN $6 THEN $7 ELSE hosts END",
        "severity = CASE WHEN $10 THEN $11 ELSE severity END",
        "task = CASE WHEN $14 THEN $15 ELSE task END",
        "result = CASE WHEN $16 THEN $17 ELSE result END",
        "end_time = CASE WHEN $18",
        "modification_time = m_now()",
    ] {
        assert!(patch.contains(required), "patch SQL missing {required}");
    }

    let clone = override_clone_sql();
    assert!(clone.contains("SELECT make_uuid(), $2, nvt, m_now(), m_now(), text, hosts"));
    assert!(clone.contains("new_severity, task, result, end_time, result_nvt"));
    let tags = override_clone_tags_sql();
    assert!(tags.contains("resource_type = 'override'"));
    assert!(tags.contains("resource_location = 0"));

    let patch_transaction = TRANSACTION_SOURCE
        .split_once("pub(crate) async fn execute_override_patch_transaction")
        .expect("override patch transaction")
        .1
        .split_once("pub(crate) async fn execute_override_clone_transaction")
        .expect("clone boundary")
        .0;
    assert!(patch_transaction.contains("let old_reports = load_override_affected_reports"));
    assert!(patch_transaction.contains("affected_reports.extend"));
    assert!(patch_transaction.contains("clear_override_report_count_caches"));
}

#[test]
fn override_scope_validation_preserves_operator_ownership_and_reference_consistency() {
    for sql in [override_task_scope_sql(), override_result_scope_sql()] {
        assert!(sql.contains("owner"));
    }
    assert!(override_nvt_exists_sql().contains("FROM nvts WHERE oid = $1"));
    assert!(override_nvt_exists_sql().contains("FROM scap.cves WHERE uuid = $1"));
    assert!(HANDLER_SOURCE.contains("ensure_override_task_result_match"));
    assert!(HANDLER_SOURCE.contains("ensure_override_nvt_exists"));
    assert!(HANDLER_SOURCE.contains("resolve_override_write_operator_owner"));
    assert!(HANDLER_SOURCE.contains("ensure_override_owner_matches_operator"));
}

#[test]
fn override_restore_and_hard_delete_are_bounded_to_owned_trash_rows() {
    let restore = override_restore_sql();
    assert!(restore.contains("INSERT INTO overrides"));
    assert!(restore.contains("FROM overrides_trash"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));
    for tags in [
        override_tag_locations_to_live_sql(),
        override_trash_tag_locations_to_live_sql(),
    ] {
        assert!(tags.contains("resource_type = 'override'"));
        assert!(tags.contains("resource_location = 0"));
    }
    assert_eq!(
        override_delete_trash_sql(),
        "DELETE FROM overrides_trash WHERE id = $1;"
    );

    let restore_handler = HANDLER_SOURCE
        .split_once("pub(crate) async fn restore_override")
        .expect("restore handler")
        .1
        .split_once("pub(crate) async fn hard_delete_override")
        .expect("hard-delete boundary")
        .0;
    assert!(restore_handler.contains("load_override_trash_state"));
    assert!(restore_handler.contains("ensure_override_owner_matches_operator"));
    assert!(restore_handler.contains("ensure_override_live_uuid_available"));
    assert!(restore_handler.contains("execute_override_restore_transaction"));
    assert!(
        restore_handler.find("tx.commit()").unwrap()
            < restore_handler.find("load_override_after_commit").unwrap()
    );

    let hard_delete_handler = HANDLER_SOURCE
        .split_once("pub(crate) async fn hard_delete_override")
        .expect("hard-delete handler")
        .1
        .split_once("async fn load_override_after_commit")
        .expect("reload helper boundary")
        .0;
    assert!(hard_delete_handler.contains("load_override_trash_state"));
    assert!(hard_delete_handler.contains("ensure_override_owner_matches_operator"));
    assert!(hard_delete_handler.contains("execute_override_hard_delete_transaction"));
    assert!(!hard_delete_handler.contains("DELETE FROM overrides"));
}

#[test]
fn override_direct_and_browser_routes_expose_the_retained_mutation_family() {
    for path in [
        "/api/v1/overrides",
        "/api/v1/overrides/:override_id",
        "/api/v1/overrides/:override_id/clone",
        "/api/v1/overrides/:override_id/restore",
        "/api/v1/overrides/:override_id/trash",
    ] {
        assert!(
            DIRECT_ROUTES_SOURCE.contains(path),
            "missing direct route {path}"
        );
        assert!(
            BROWSER_PROXY_ROUTES_SOURCE.contains(path),
            "missing browser route {path}"
        );
    }
    for proxy in [
        "browser_proxy_create_override",
        "browser_proxy_patch_override",
        "browser_proxy_clone_override",
        "browser_proxy_delete_override",
        "browser_proxy_restore_override",
        "browser_proxy_hard_delete_override",
    ] {
        assert!(BROWSER_PROXY_SOURCE.contains(proxy), "missing {proxy}");
    }
}

#[test]
fn override_delete_state_and_affected_report_sql_match_inherited_scope_branches() {
    let state = override_write_state_sql();
    for required in [
        "FROM overrides",
        "WHERE uuid = $1",
        "coalesce(owner, 0)::integer",
        "coalesce(nvt, '')::text",
        "coalesce(task, 0)::integer",
        "coalesce(result, 0)::integer",
        "FOR UPDATE",
    ] {
        assert!(
            state.contains(required),
            "override state SQL missing {required}"
        );
    }

    let affected = override_affected_reports_sql();
    for required in [
        "SELECT DISTINCT report::integer",
        "FROM results",
        "WHERE nvt = $1",
        "$3 <> 0 AND id = $3",
        "$3 = 0 AND $2 <> 0 AND task = $2",
        "$3 = 0 AND $2 = 0",
        "ORDER BY report::integer",
    ] {
        assert!(
            affected.contains(required),
            "affected report SQL missing {required}"
        );
    }
}

#[test]
fn override_delete_sql_moves_full_metadata_and_tags_but_never_hard_deletes() {
    let trash = override_trash_insert_sql();
    for required in [
        "INSERT INTO overrides_trash",
        "uuid, owner, nvt, creation_time, modification_time, text, hosts",
        "port, severity, new_severity, task, result, end_time, result_nvt",
        "FROM overrides",
        "RETURNING id::integer, uuid::text",
    ] {
        assert!(
            trash.contains(required),
            "override trash SQL missing {required}"
        );
    }
    assert!(!trash.contains("DELETE FROM overrides_trash"));

    for tags in [
        override_tag_locations_to_trash_sql(),
        override_trash_tag_locations_to_trash_sql(),
    ] {
        assert!(tags.contains("resource_type = 'override'"));
        assert!(tags.contains("resource_location = 1"));
        assert!(tags.contains("resource = $1"));
        assert!(tags.contains("resource = $2"));
    }
    assert_eq!(
        override_delete_live_sql(),
        "DELETE FROM overrides WHERE id = $1;"
    );
    let cache = override_clear_overridden_report_counts_sql();
    assert!(cache.contains("DELETE FROM report_counts"));
    assert!(cache.contains("override = 1"));
    assert!(cache.contains("report = ANY($1::integer[])"));
}

#[test]
fn override_delete_transaction_computes_reports_before_trash_and_clears_after_delete() {
    let affected = TRANSACTION_SOURCE
        .find("load_override_affected_reports")
        .expect("affected reports query");
    let trash = TRANSACTION_SOURCE
        .find("query_override_trash_record")
        .expect("trash insert");
    let live_tags = TRANSACTION_SOURCE
        .find("override_tag_locations_to_trash_sql")
        .expect("live tag move");
    let trash_tags = TRANSACTION_SOURCE
        .find("override_trash_tag_locations_to_trash_sql")
        .expect("trash tag move");
    let delete = TRANSACTION_SOURCE
        .find("override_delete_live_sql")
        .expect("live delete");
    let cache = TRANSACTION_SOURCE
        .find("override_clear_overridden_report_counts_sql")
        .expect("cache clear");
    assert!(affected < trash && trash < live_tags && live_tags < trash_tags);
    assert!(trash_tags < delete && delete < cache);
    assert!(TRANSACTION_SOURCE.contains("if !affected_reports.is_empty()"));
}

#[test]
fn override_delete_handler_authenticates_checks_owner_and_commits_before_204() {
    let handler = HANDLER_SOURCE
        .split_once("pub(crate) async fn delete_override")
        .expect("delete override handler")
        .1
        .split_once("#[cfg(test)]")
        .expect("test module boundary")
        .0;
    let auth = handler
        .find("require_override_write_operator")
        .expect("operator auth");
    let transaction = handler.find(".transaction()").expect("transaction begin");
    let owner = handler
        .find("resolve_override_write_operator_owner")
        .expect("operator owner resolution");
    let lock = handler.find("LOCK TABLE").expect("tag-resource table lock");
    let state = handler
        .find("load_override_write_state")
        .expect("override state");
    let owner_match = handler
        .find("ensure_override_owner_matches_operator")
        .expect("owner match");
    let execute = handler
        .find("execute_override_trash_transaction")
        .expect("trash transaction");
    let commit = handler.find("tx.commit()").expect("commit");
    let response = handler
        .find("StatusCode::NO_CONTENT")
        .expect("204 response");
    assert!(auth < transaction && transaction < owner && owner < lock);
    assert!(lock < state);
    assert!(state < owner_match && owner_match < execute);
    assert!(execute < commit && commit < response);
    assert!(handler.contains(
        "LOCK TABLE overrides, overrides_trash, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;"
    ));
}

#[test]
fn inherited_permission_location_helpers_are_no_ops_so_native_delete_does_not_invent_writes() {
    let set_locations = INHERITED_PERMISSIONS_SOURCE
        .split_once("permissions_set_locations")
        .expect("permissions_set_locations")
        .1
        .split_once("permissions_set_orphans")
        .expect("permissions_set_orphans boundary")
        .0;
    assert!(set_locations.contains("(void) type"));
    assert!(set_locations.contains("(void) old"));
    assert!(!set_locations.contains("UPDATE permissions"));
    assert!(!TRANSACTION_SOURCE.contains("permission"));
}

#[test]
fn override_delete_browser_proxy_forwards_authenticated_operator_context() {
    let proxy = BROWSER_PROXY_SOURCE
        .split_once("pub(crate) async fn browser_proxy_delete_override")
        .expect("override delete browser proxy")
        .1
        .split_once("pub(crate) async fn browser_proxy_delete_task")
        .expect("next proxy boundary")
        .0;
    let operator = proxy
        .find("browser_proxy_operator_from_headers")
        .expect("browser operator lookup");
    let delete = proxy.find("delete_override").expect("override delete call");
    assert!(operator < delete);
    assert!(proxy.contains("Some(Extension(operator))"));
    assert!(BROWSER_PROXY_ROUTES_SOURCE.contains(
        ".route(\n            \"/api/v1/overrides/:override_id\",\n            delete(browser_proxy_delete_override),"
    ));
}
