// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_PORT_LISTS: &str =
    include_str!("../../../components/gvmd/src/manage_port_lists.c");
const MANAGE_SQL_PORT_LISTS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_port_lists.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GMP_PORT_LISTS: &str = include_str!("../../../components/gvmd/src/gmp_port_lists.c");
const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");

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
fn feed_port_list_xml_parser_is_owned_outside_the_gmp_command_module() {
    let parse = inherited_function(MANAGE_PORT_LISTS, "parse_port_list_entity");
    for required in [
        "entity_attribute (port_list, \"id\")",
        "entity_child (port_list, \"name\")",
        "entity_child (port_list, \"comment\")",
        "entity_child (port_list, \"deprecated\")",
        "entity_child (port_list, \"port_ranges\")",
        "entity_attribute (port_range, \"id\")",
        "PORT_PROTOCOL_TCP",
        "PORT_PROTOCOL_UDP",
        "PORT_PROTOCOL_OTHER",
        "range->exclude = 0",
    ] {
        assert!(parse.contains(required), "feed XML parser missing {required}");
    }
    for caller in ["create_port_list_from_file", "update_port_list_from_file"] {
        let function = inherited_function(MANAGE_PORT_LISTS, caller);
        assert!(
            function.contains("parse_port_list_entity"),
            "{caller} must retain the shared feed XML parser"
        );
    }
    assert!(!GMP_PORT_LISTS.contains("\nparse_port_list_entity ("));
}

#[test]
fn inherited_copy_port_list_copies_metadata_ranges_and_tags_as_non_predefined() {
    let copy_port_list = inherited_function(MANAGE_SQL_PORT_LISTS, "copy_port_list");
    for required in [
        "copy_resource_lock (\"port_list\", name, comment, port_list_id, NULL, 1",
        "UPDATE port_lists SET predefined = 0",
        "INSERT INTO port_ranges",
        "SELECT make_uuid(), %llu, type, start",
        "FROM port_ranges WHERE port_list = %llu",
        "sql_commit ()",
    ] {
        assert!(
            copy_port_list.contains(required),
            "copy_port_list missing {required}"
        );
    }

    let copy_resource = inherited_function(
        include_str!("../../../components/gvmd/src/manage_sql_resources.c"),
        "copy_resource_lock",
    );
    for required in [
        "acl_user_may (command)",
        "find_resource_with_permission",
        "resource_with_name_exists (name, type, 0)",
        "uniquify ('%s', name, %llu, ' Clone')",
        "INSERT INTO tag_resources",
        "resource_location = ",
        "LOCATION_TABLE",
    ] {
        assert!(
            copy_resource.contains(required),
            "copy_resource_lock missing {required}"
        );
    }
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
fn inherited_port_list_import_wraps_uploaded_xml_and_parser_keeps_three_create_branches() {
    let import = inherited_function(GSAD_GMP_C, "import_port_list_gmp");
    for required in [
        "<create_port_list>",
        "params_value (params, \"xml_file\")",
        "gmp (connection, credentials, NULL, &entity, response_data, command)",
        "response_from_entity (connection, credentials, params, entity",
    ] {
        assert!(
            import.contains(required),
            "import_port_list_gmp missing {required}"
        );
    }

    let create_run = inherited_function(GMP_PORT_LISTS, "create_port_list_run");
    for required in [
        "get_port_lists_response = entity_child (entity, \"get_port_lists_response\")",
        "parse_port_list_entity (port_list, &port_list_id, &import_name",
        "GET_PORT_LISTS_RESPONSE requires a",
        "GET_PORT_LISTS_RESPONSE ID must be",
        "!is_uuid (port_list_id)",
        "create_port_list (port_list_id",
        "copy = entity_child (entity, \"copy\")",
        "copy_port_list (name ? entity_text (name) : NULL",
        "entity_child (entity, \"port_range\")",
        "create_port_list (NULL",
    ] {
        assert!(
            create_run.contains(required),
            "create_port_list_run missing {required}"
        );
    }
}

#[test]
fn port_list_native_metadata_export_no_longer_uses_singular_gsad_xml_export() {
    assert!(
        !GSAD_GMP_C.contains("export_port_list_gmp"),
        "singular port-list metadata export must stay native JSON, not legacy gsad XML"
    );
    assert!(
        !GSAD_GMP_C.contains("export_port_lists_gmp"),
        "bulk port-list XML export must not stay exposed once native JSON metadata export is retained"
    );

    let bulk_export = inherited_function(GSAD_GMP_C, "bulk_export_gmp");
    assert!(
        bulk_export.contains("str_equal (type, \"port_list\")"),
        "generic bulk export must reject port_list after native JSON metadata export replacement"
    );

    for forbidden in [
        "create_port_list",
        "modify_port_list",
        "delete_port_list",
        "create_port_range",
        "import_port_list",
    ] {
        assert!(
            !bulk_export.contains(forbidden),
            "bulk port-list export must not include mutation boundary {forbidden}"
        );
    }
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
fn native_direct_api_allows_current_port_list_write_control_paths_only_when_enabled() {
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
    let export_path = "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc/export";
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        export_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        export_path,
        true
    ));
    for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, export_path, true),
            "{method} port-list metadata export must stay closed; import/file export remains inherited"
        );
    }
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-lists",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-lists",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-list-imports",
        true,
    ));
    for method in [Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/port-lists", true),
            "{method} /api/v1/port-lists must remain closed"
        );
    }
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc/clone",
        true,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-lists/12345678-1234-1234-1234-123456789abc/restore",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-lists/not-a-uuid/clone",
        true,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/port-lists/not-a-uuid/restore",
        true,
    ));
    for method in [Method::POST, Method::PUT] {
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
fn openapi_documents_port_list_write_control_boundary() {
    let list = openapi_path_block("/port-lists");
    let results = openapi_path_block("/results");
    let vulnerabilities = openapi_path_block("/vulnerabilities");
    let scan_configs = openapi_path_block("/scan-configs");
    assert!(list.contains("get:"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-yafvs-exposure: direct-read"));
    assert!(!list.contains("x-yafvs-inherited-still-owns: port-list-bulk-xml-export"));
    assert!(list.contains("operationId: postPortLists"));
    assert!(list.contains("x-yafvs-replaces: port-list-create"));
    assert!(list.contains("name: predefined"));
    assert!(list.contains("enum: ['0', '1']"));
    assert!(!results.contains("name: predefined"));
    assert!(!vulnerabilities.contains("name: predefined"));
    assert!(scan_configs.contains("name: predefined"));
    assert_eq!(OPENAPI.matches("- name: predefined").count(), 2);

    let import = openapi_path_block("/port-list-imports");
    assert!(import.contains("post:"));
    assert!(import.contains("operationId: postPortListImports"));
    assert!(import.contains("x-yafvs-exposure: direct-write"));
    assert!(import.contains("x-yafvs-replaces: port-list-import"));
    assert!(!import.contains("x-yafvs-inherited-still-owns: port-list-bulk-xml-export"));
    assert!(import.contains("PortListImportRequest"));

    let detail = openapi_path_block("/port-lists/{port_list_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("x-yafvs-exposure: direct-read"));
    assert!(detail.contains("x-yafvs-exposure: direct-write"));
    assert!(detail.contains("x-yafvs-replaces: port-list-metadata-and-range-modify"));
    assert!(detail.contains("x-yafvs-side-effect: metadata-and-range-write"));
    assert!(detail.contains("x-yafvs-replaces: port-list-trash-move"));
    assert!(detail.contains("x-yafvs-safety-contract: write-control-v1"));
    assert!(!detail.contains("x-yafvs-inherited-still-owns: port-list-bulk-xml-export"));

    let clone = openapi_path_block("/port-lists/{port_list_id}/clone");
    assert!(clone.contains("post:"));
    assert!(clone.contains("operationId: postPortListsByPortListIdClone"));
    assert!(clone.contains("x-yafvs-exposure: direct-write"));
    assert!(clone.contains("x-yafvs-replaces: port-list-clone"));
    assert!(clone.contains("x-yafvs-safety-contract: write-control-v1"));
    assert!(!clone.contains("x-yafvs-inherited-still-owns: port-list-bulk-xml-export"));

    let restore = openapi_path_block("/port-lists/{port_list_id}/restore");
    assert!(restore.contains("post:"));
    assert!(restore.contains("x-yafvs-exposure: direct-write"));
    assert!(restore.contains("x-yafvs-replaces: port-list-restore"));
    assert!(restore.contains("x-yafvs-safety-contract: write-control-v1"));
    assert!(!restore.contains("x-yafvs-inherited-still-owns: port-list-bulk-xml-export"));

    let hard_delete = openapi_path_block("/port-lists/{port_list_id}/trash");
    assert!(hard_delete.contains("delete:"));
    assert!(hard_delete.contains("operationId: deletePortListsByPortListIdTrash"));
    assert!(hard_delete.contains("x-yafvs-direct: true"));
    assert!(hard_delete.contains("x-yafvs-exposure: direct-write"));
    assert!(hard_delete.contains("x-yafvs-replaces: port-list-hard-delete"));
    assert!(!hard_delete.contains("x-yafvs-inherited-still-owns: port-list-bulk-xml-export"));
    let export = openapi_path_block("/port-lists/{port_list_id}/export");
    assert!(export.contains("get:"));
    assert!(export.contains("x-yafvs-exposure: direct-read"));

    let create_range = openapi_path_block("/port-lists/{port_list_id}/ranges");
    assert!(create_range.contains("post:"));
    assert!(create_range.contains("x-yafvs-replaces: port-list-range-create"));
    assert!(create_range.contains("PortListCreateRangeRequest"));
    assert!(export.contains("x-yafvs-replaces: port-list-metadata-export-read"));
    assert!(!export.contains("x-yafvs-inherited-still-owns:"));
    assert!(!export.contains("x-yafvs-safety-contract: write-control-v1"));
}
