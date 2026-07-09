// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::{
    direct_api::direct_api_v1_method_is_allowed,
    filter_query_sql::{filter_alert_backlinks_sql, filter_asset_detail_sql, filter_assets_sql},
};

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_FILTERS: &str = include_str!("../../../components/gvmd/src/manage_sql_filters.c");
const MANAGE_SQL_PERMISSIONS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_permissions.c");
const MANAGE_SQL_RESOURCES: &str =
    include_str!("../../../components/gvmd/src/manage_sql_resources.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");

fn inherited_function(source: &str, name: &str) -> String {
    let marker = format!("\n{name} (");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} function marker must exist"));
    let tail = &source[start..];
    let end = tail.find("\n/**").unwrap_or(tail.len());
    tail[..end].to_string()
}

#[test]
fn inherited_permission_location_helpers_are_currently_noops() {
    let set_locations = inherited_function(MANAGE_SQL_PERMISSIONS, "permissions_set_locations");
    for required in ["(void) type", "(void) old", "(void) new", "(void) to"] {
        assert!(
            set_locations.contains(required),
            "permissions_set_locations should remain characterized as no-op until implemented: missing {required}"
        );
    }
    assert!(!set_locations.contains("UPDATE permissions"));

    let set_orphans = inherited_function(MANAGE_SQL_PERMISSIONS, "permissions_set_orphans");
    for required in ["(void) type", "(void) resource", "(void) location"] {
        assert!(
            set_orphans.contains(required),
            "permissions_set_orphans should remain characterized as no-op until implemented: missing {required}"
        );
    }
    assert!(!set_orphans.contains("UPDATE permissions"));
}

fn openapi_path_block(path: &str) -> String {
    let marker = format!("  {path}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{path} path block must exist"));
    let tail = &OPENAPI[start..];
    let end = tail
        .lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("  /") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string());
    end
}

#[test]
fn inherited_filter_schema_has_live_and_trash_state() {
    let filters_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS filters")
        .expect("filters table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS filters_trash")
        .expect("filters_trash must follow filters")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "comment text",
        "type text",
        "term text",
        "creation_time integer",
        "modification_time integer",
    ] {
        assert!(
            filters_table.contains(column),
            "filters table missing {column}"
        );
    }

    let filters_trash_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS filters_trash")
        .expect("filters_trash table definition must exist")
        .1
        .split_once(");")
        .expect("filters_trash definition must terminate")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "term text",
    ] {
        assert!(
            filters_trash_table.contains(column),
            "filters_trash table missing {column}"
        );
    }
}

#[test]
fn inherited_create_filter_normalizes_type_term_owner_and_name() {
    let create_filter = inherited_function(MANAGE_SQL_FILTERS, "create_filter");
    for required in [
        "type_db_name (type)",
        "valid_type (db_type)",
        "valid_subtype (type)",
        "acl_user_may (\"create_filter\")",
        "resource_with_name_exists (name, \"filter\", 0)",
        "manage_clean_filter (term ? term : \"\"",
        "current_credentials.uuid",
        "INSERT INTO filters",
        "make_uuid ()",
        "m_now ()",
    ] {
        assert!(
            create_filter.contains(required),
            "create_filter missing {required}"
        );
    }
    assert!(!create_filter.contains("filters_trash"));
    assert!(!create_filter.contains("alert_method_data"));
}

#[test]
fn inherited_modify_filter_has_alert_linked_type_guards() {
    let modify_filter = inherited_function(MANAGE_SQL_FILTERS, "modify_filter");
    for required in [
        "find_filter_with_permission (filter_id, &filter, \"modify_filter\")",
        "acl_user_may (\"modify_filter\")",
        "filter_in_use_for_output (filter)",
        "filter_in_use_for_result_event (filter)",
        "strcasecmp (type, \"result\")",
        "filter_in_use_for_secinfo_event (filter)",
        "strcasecmp (type, \"info\")",
        "resource_with_name_exists (name, \"filter\", filter)",
        "manage_clean_filter (term ? term : \"\"",
        "UPDATE filters SET",
    ] {
        assert!(
            modify_filter.contains(required),
            "modify_filter missing {required}"
        );
    }
    assert!(!modify_filter.contains("filters_trash"));
    assert!(!modify_filter.contains("DELETE FROM filters"));
}

#[test]
fn inherited_copy_filter_copies_term_type_and_active_tags() {
    let copy_filter = inherited_function(MANAGE_SQL_FILTERS, "copy_filter");
    assert!(copy_filter.contains("copy_resource"));
    assert!(copy_filter.contains("\"filter\""));
    assert!(copy_filter.contains("\"term, type\""));
    assert!(copy_filter.contains("1, new_filter"));

    let resources = inherited_function(MANAGE_SQL_RESOURCES, "copy_resource_lock");
    assert!(resources.contains("INSERT INTO tag_resources"));
    assert!(resources.contains("resource_type = '%s' AND resource = %llu"));
    assert!(resources.contains("LOCATION_TABLE"));
}

#[test]
fn inherited_delete_filter_is_trash_permissions_tags_and_alert_linked() {
    let delete_filter = inherited_function(MANAGE_SQL_FILTERS, "delete_filter");
    for required in [
        "acl_user_may (\"delete_filter\")",
        "find_filter_with_permission (filter_id, &filter, \"delete_filter\")",
        "find_trash (\"filter\", filter_id, &filter)",
        "FROM alerts_trash",
        "FROM alert_condition_data_trash",
        "FROM alert_condition_data",
        "DELETE FROM settings",
        "INSERT INTO filters_trash",
        "UPDATE alerts_trash",
        "permissions_set_locations",
        "tags_set_locations",
        "permissions_set_orphans",
        "tags_remove_resource",
        "DELETE FROM filters WHERE id",
    ] {
        assert!(
            delete_filter.contains(required),
            "delete_filter missing {required}"
        );
    }
}

#[test]
fn native_filter_reads_are_metadata_and_alert_backlinks_only() {
    let list = filter_assets_sql("name ASC");
    let detail = filter_asset_detail_sql();
    let backlinks = filter_alert_backlinks_sql();
    let combined = format!("{list}\n{detail}\n{backlinks}");

    for required in [
        "FROM filters f",
        "FROM alerts a",
        "FROM alert_condition_data acd",
        "acd.name = 'filter_id'",
        "coalesce(f.term, '') AS term",
        "count(DISTINCT alert_id)::bigint",
    ] {
        assert!(
            combined.contains(required),
            "filter read SQL missing {required}"
        );
    }
    for forbidden in [
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "filters_trash",
        "settings",
        "permissions_set",
        "tags_set",
        "password",
        "secret",
    ] {
        assert!(
            !combined.contains(forbidden),
            "native filter read SQL must not contain {forbidden}"
        );
    }
}

#[test]
fn native_direct_api_allows_filter_create_metadata_patch_trash_move_restore_and_hard_delete_under_write_control()
 {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/filters",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc",
        false
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/filters",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/filters",
        true
    ));
    for method in [Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/filters", true),
            "{method} /api/v1/filters must remain closed"
        );
    }
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc/clone",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc/restore",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc/trash",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc/restore",
        false,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc/trash",
        false,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/filters/12345678-1234-1234-1234-123456789abc/clone",
        false,
    ));
    for method in [Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/filters/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/filters/{{id}} must remain closed"
        );
    }
}

#[test]
fn openapi_documents_filter_metadata_patch_and_trash_move_boundary() {
    let list = openapi_path_block("/filters");
    assert!(list.contains("get:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(list.contains("alert-reference counts"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-turbovas-replaces: saved-filter-create"));
    assert!(!list.contains("x-turbovas-inherited-still-owns: saved-filter-alert-linkage"));

    let detail = openapi_path_block("/filters/{filter_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(detail.contains("alert output-filter backlinks"));
    assert!(detail.contains("x-turbovas-replaces: saved-filter-metadata-modify"));
    assert!(detail.contains("x-turbovas-replaces: saved-filter-trash-move"));
    assert!(detail.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(detail.contains("x-turbovas-inherited-still-owns: saved-filter-alert-linkage"));

    let clone = openapi_path_block("/filters/{filter_id}/clone");
    assert!(clone.contains("post:"));
    assert!(clone.contains("x-turbovas-exposure: direct-write"));
    assert!(clone.contains("x-turbovas-replaces: saved-filter-clone"));
    assert!(clone.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!clone.contains("x-turbovas-inherited-still-owns: saved-filter-alert-linkage"));

    let restore = openapi_path_block("/filters/{filter_id}/restore");
    assert!(restore.contains("post:"));
    assert!(restore.contains("x-turbovas-exposure: direct-write"));
    assert!(restore.contains("x-turbovas-replaces: saved-filter-restore"));
    assert!(restore.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(restore.contains("x-turbovas-inherited-still-owns: saved-filter-alert-linkage"));

    let hard_delete = openapi_path_block("/filters/{filter_id}/trash");
    assert!(hard_delete.contains("delete:"));
    assert!(hard_delete.contains("operationId: deleteFiltersByFilterIdTrash"));
    assert!(hard_delete.contains("x-turbovas-exposure: direct-write"));
    assert!(hard_delete.contains("x-turbovas-replaces: saved-filter-hard-delete"));
    assert!(hard_delete.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(hard_delete.contains("x-turbovas-inherited-still-owns: saved-filter-alert-linkage"));

    assert!(!GSAD_GMP_C.contains("export_filter_gmp"));
    assert!(!GSAD_GMP_C.contains("export_filters_gmp"));
    let bulk_export = inherited_function(GSAD_GMP_C, "bulk_export_gmp");
    assert!(bulk_export.contains("str_equal (type, \"filter\")"));
}
