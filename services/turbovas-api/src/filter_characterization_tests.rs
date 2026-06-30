// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_FILTERS: &str = include_str!("../../../components/gvmd/src/manage_sql_filters.c");
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
fn native_direct_api_allows_only_filter_metadata_patch_under_write_control() {
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
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
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
    for method in [Method::POST, Method::DELETE, Method::PUT] {
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
fn openapi_documents_filter_metadata_patch_boundary() {
    let list = openapi_path_block("/filters");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(list.contains(
        "x-turbovas-inherited-still-owns: saved-filter-term-type-create-delete-trash-alert-linkage"
    ));

    let detail = openapi_path_block("/filters/{filter_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(!detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(detail.contains("x-turbovas-replaces: saved-filter-metadata-modify"));
    assert!(detail.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(detail.contains(
        "x-turbovas-inherited-still-owns: saved-filter-term-type-create-delete-trash-alert-linkage"
    ));
}
