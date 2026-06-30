// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_PORT_LISTS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_port_lists.c");
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
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("  /") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn inherited_port_list_schema_has_live_trash_and_range_children() {
    let port_lists_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS port_lists")
        .expect("port_lists table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS port_lists_trash")
        .expect("port_lists_trash must follow port_lists")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "comment text",
        "predefined integer",
        "creation_time integer",
        "modification_time integer",
    ] {
        assert!(
            port_lists_table.contains(column),
            "port_lists table missing {column}"
        );
    }

    let port_lists_trash_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS port_lists_trash")
        .expect("port_lists_trash table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS port_ranges")
        .expect("port_ranges must follow port_lists_trash")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "predefined integer",
    ] {
        assert!(
            port_lists_trash_table.contains(column),
            "port_lists_trash table missing {column}"
        );
    }

    for (table, reference) in [
        ("port_ranges", "port_list integer REFERENCES port_lists"),
        (
            "port_ranges_trash",
            "port_list integer REFERENCES port_lists_trash",
        ),
    ] {
        let table_block = MANAGE_PG
            .split_once(&format!("CREATE TABLE IF NOT EXISTS {table}"))
            .unwrap_or_else(|| panic!("{table} definition must exist"))
            .1
            .split_once(");")
            .unwrap_or_else(|| panic!("{table} definition must terminate"))
            .0;
        for column in [
            "uuid text UNIQUE NOT NULL",
            reference,
            "type integer",
            "start integer",
            "\\\"end\\\" integer",
            "exclude integer",
        ] {
            assert!(table_block.contains(column), "{table} missing {column}");
        }
    }
}

#[test]
fn inherited_create_port_list_validates_ranges_owner_acl_name_and_feed_predefined_state() {
    let create_internal = inherited_function(MANAGE_SQL_PORT_LISTS, "create_port_list_internal");
    for required in [
        "assert (current_credentials.uuid)",
        "acl_user_may (\"create_port_list\")",
        "validate_port_range (port_ranges)",
        "resource_with_name_exists (name, \"port_list\", 0)",
        "SELECT COUNT(*) FROM port_lists",
        "SELECT COUNT(*) FROM port_lists_trash",
        "create_port_list_lock",
        "INSERT INTO port_lists",
        "SELECT id FROM users WHERE uuid",
        "make_port_ranges_openvas_default",
        "port_range_ranges (port_ranges)",
        "sql_commit ()",
    ] {
        assert!(
            create_internal.contains(required),
            "create_port_list_internal missing {required}"
        );
    }

    let create_no_acl = inherited_function(MANAGE_SQL_PORT_LISTS, "create_port_list_no_acl");
    assert!(create_no_acl.contains("create_port_list_internal (0"));
    assert!(create_no_acl.contains("1, /* Predefined. */"));
}

#[test]
fn inherited_modify_port_list_is_metadata_only_and_blocks_predefined_lists() {
    let modify_port_list = inherited_function(MANAGE_SQL_PORT_LISTS, "modify_port_list");
    for required in [
        "if (port_list_id == NULL)",
        "acl_user_may (\"modify_port_list\")",
        "port_list_predefined_uuid (port_list_id)",
        "find_port_list_with_permission (port_list_id, &port_list,",
        "resource_with_name_exists (name, \"port_list\", port_list)",
        "UPDATE port_lists SET",
        "name = '%s'",
        "comment = '%s'",
        "modification_time = m_now ()",
    ] {
        assert!(
            modify_port_list.contains(required),
            "modify_port_list missing {required}"
        );
    }
    assert!(!modify_port_list.contains("port_ranges"));
    assert!(!modify_port_list.contains("port_lists_trash"));
}

#[test]
fn inherited_delete_port_list_is_target_guarded_and_moves_ranges_permissions_and_tags() {
    let delete_port_list = inherited_function(MANAGE_SQL_PORT_LISTS, "delete_port_list");
    for required in [
        "acl_user_may (\"delete_port_list\")",
        "find_port_list_with_permission (port_list_id, &port_list,",
        "find_trash (\"port_list\", port_list_id, &port_list)",
        "SELECT count(*) FROM targets_trash",
        "SELECT count(*) FROM targets",
        "INSERT INTO port_lists_trash",
        "INSERT INTO port_ranges_trash",
        "UPDATE targets_trash",
        "permissions_set_locations (\"port_list\"",
        "tags_set_locations (\"port_list\"",
        "permissions_set_orphans (\"port_list\"",
        "tags_remove_resource (\"port_list\"",
        "DELETE FROM port_ranges WHERE port_list",
        "DELETE FROM port_lists WHERE id",
        "DELETE FROM port_ranges_trash WHERE port_list",
        "DELETE FROM port_lists_trash WHERE id",
    ] {
        assert!(
            delete_port_list.contains(required),
            "delete_port_list missing {required}"
        );
    }
}

#[test]
fn inherited_restore_port_list_moves_ranges_targets_permissions_and_tags_back_to_live_tables() {
    let restore_port_list = inherited_function(MANAGE_SQL_PORT_LISTS, "restore_port_list");
    for required in [
        "find_trash (\"port_list\", port_list_id, &port_list)",
        "SELECT count(*) FROM port_lists",
        "ACL_USER_OWNS",
        "INSERT INTO port_lists",
        "INSERT INTO port_ranges",
        "UPDATE targets_trash",
        "port_list_location = ",
        "permissions_set_locations (\"port_list\"",
        "tags_set_locations (\"port_list\"",
        "DELETE FROM port_ranges_trash WHERE port_list",
        "DELETE FROM port_lists_trash WHERE id",
        "sql_commit ()",
    ] {
        assert!(
            restore_port_list.contains(required),
            "restore_port_list missing {required}"
        );
    }
}

#[test]
fn native_direct_api_keeps_port_list_writes_closed_until_full_contract_lands() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/port-lists",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc",
        false
    ));
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/port-lists", true),
            "{method} /api/v1/port-lists must remain closed"
        );
    }
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/port-lists/{{id}} must remain closed"
        );
    }
}

#[test]
fn openapi_documents_port_lists_as_read_only_until_write_contract_lands() {
    let list = openapi_path_block("/port-lists");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(
        list.contains(
            "x-turbovas-inherited-still-owns: port-list-import-export-writes-and-deletes"
        )
    );

    let detail = openapi_path_block("/port-lists/{port_list_id}");
    assert!(detail.contains("get:"));
    assert!(!detail.contains("patch:"));
    assert!(!detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(
        detail.contains(
            "x-turbovas-inherited-still-owns: port-list-import-export-writes-and-deletes"
        )
    );
}
