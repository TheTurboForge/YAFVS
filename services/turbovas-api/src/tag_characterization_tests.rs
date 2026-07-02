// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_TAGS: &str = include_str!("../../../components/gvmd/src/manage_sql_tags.c");
const MANAGE_TAGS: &str = include_str!("../../../components/gvmd/src/manage_tags.c");
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
fn inherited_tag_schema_has_live_trash_and_resource_tables() {
    let tags_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS tags")
        .expect("tags table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS tag_resources")
        .expect("tag_resources must follow tags")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "comment text",
        "resource_type text",
        "active integer",
        "value text",
        "creation_time integer",
        "modification_time integer",
    ] {
        assert!(tags_table.contains(column), "tags table missing {column}");
    }

    let tag_resources_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS tag_resources")
        .expect("tag_resources table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS tags_trash")
        .expect("tags_trash must follow tag_resources")
        .0;
    for column in [
        "tag integer REFERENCES tags (id)",
        "resource_type text",
        "resource integer",
        "resource_uuid text",
        "resource_location integer",
    ] {
        assert!(
            tag_resources_table.contains(column),
            "tag_resources table missing {column}"
        );
    }

    let tags_trash_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS tags_trash")
        .expect("tags_trash table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS tag_resources_trash")
        .expect("tag_resources_trash must follow tags_trash")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "resource_type text",
        "active integer",
        "value text",
    ] {
        assert!(
            tags_trash_table.contains(column),
            "tags_trash table missing {column}"
        );
    }

    let tag_resources_trash_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS tag_resources_trash")
        .expect("tag_resources_trash table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS integration_configs")
        .expect("integration_configs must follow tag_resources_trash")
        .0;
    for column in [
        "tag integer REFERENCES tags_trash (id)",
        "resource_type text",
        "resource integer",
        "resource_uuid text",
        "resource_location integer",
    ] {
        assert!(
            tag_resources_trash_table.contains(column),
            "tag_resources_trash table missing {column}"
        );
    }
}

#[test]
fn inherited_copy_tag_copies_metadata_and_all_resource_assignments() {
    let copy_tag = inherited_function(MANAGE_SQL_TAGS, "copy_tag");
    for required in [
        "copy_resource (\"tag\", name, comment, tag_id",
        "value, resource_type, active",
        "if (new_tag_return)",
        "*new_tag_return = new_tag",
        "INSERT INTO tag_resources",
        "resource_type, resource, resource_uuid, resource_location",
        "FROM tag_resources",
        "WHERE tag = %llu",
    ] {
        assert!(copy_tag.contains(required), "copy_tag missing {required}");
    }
}

#[test]
fn inherited_delete_tag_has_live_trash_already_trash_and_hard_delete_paths() {
    let delete_tag = inherited_function(MANAGE_SQL_TAGS, "delete_tag");
    for required in [
        "sql_begin_immediate ()",
        "acl_user_may (\"delete_tag\")",
        "find_tag_with_permission (tag_id, &tag, \"delete_tag\")",
        "find_trash (\"tag\", tag_id, &tag)",
        "if (ultimate == 0)",
        "It's already in the trashcan.",
        "permissions_set_orphans (\"tag\", tag, LOCATION_TRASH)",
        "DELETE FROM tag_resources_trash WHERE tag",
        "DELETE FROM tags_trash WHERE id",
        "INSERT INTO tags_trash",
        "INSERT INTO tag_resources_trash",
        "permissions_set_locations (\"tag\"",
        "permissions_set_orphans (\"tag\", tag, LOCATION_TABLE)",
        "tags_remove_resource (\"tag\", tag, LOCATION_TABLE)",
        "DELETE FROM tag_resources WHERE tag",
        "DELETE FROM tags WHERE id",
        "sql_commit ()",
    ] {
        assert!(
            delete_tag.contains(required),
            "delete_tag missing {required}"
        );
    }
}

#[test]
fn inherited_modify_tag_owns_set_add_remove_and_filter_resource_semantics() {
    let modify_tag = inherited_function(MANAGE_SQL_TAGS, "modify_tag");
    for required in [
        "resources_action == NULL",
        "strcmp (resources_action, \"set\") == 0",
        "DELETE FROM tag_resources WHERE tag = %llu",
        "strcmp (resources_action, \"add\")",
        "strcmp (resources_action, \"remove\")",
        "tag_remove_resources_list",
        "tag_add_resources_list",
        "resources_filter && strcmp (resources_filter, \"\")",
        "tag_remove_resources_filter",
        "tag_add_resources_filter",
    ] {
        assert!(
            modify_tag.contains(required),
            "modify_tag missing inherited resource mutation branch {required}"
        );
    }
}

#[test]
fn inherited_tag_writability_helpers_are_currently_permissive_live_closed_trash() {
    let tag_writable = inherited_function(MANAGE_TAGS, "tag_writable");
    let trash_tag_writable = inherited_function(MANAGE_TAGS, "trash_tag_writable");
    let tag_in_use = inherited_function(MANAGE_TAGS, "tag_in_use");
    let trash_tag_in_use = inherited_function(MANAGE_TAGS, "trash_tag_in_use");
    assert!(tag_writable.contains("return 1;"));
    assert!(trash_tag_writable.contains("return 0;"));
    assert!(tag_in_use.contains("return 0;"));
    assert!(trash_tag_in_use.contains("return 0;"));
}

#[test]
fn native_direct_api_still_limits_tag_write_control_to_metadata_and_explicit_resources() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/tags",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc",
        false
    ));
    let export_path = "/api/v1/tags/12345678-1234-1234-1234-123456789abc/export";
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
            "{method} tag metadata export must stay closed; filter actions and file export remain inherited"
        );
    }
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc/resources",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc/clone",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc/restore",
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/tags/12345678-1234-1234-1234-123456789abc/trash",
        true
    ));
}

#[test]
fn openapi_tag_contract_records_remaining_inherited_tail() {
    for path in ["/tags", "/tags/{tag_id}", "/tags/{tag_id}/resources"] {
        let block = openapi_path_block(path);
        assert!(
            block.contains("x-turbovas-inherited-still-owns: tag-filter-actions-and-file-export")
        );
    }
    let clone_block = openapi_path_block("/tags/{tag_id}/clone");
    assert!(clone_block.contains("x-turbovas-replaces: tag-clone"));
    assert!(clone_block.contains("x-turbovas-safety-contract: write-control-v1"));
    let export_block = openapi_path_block("/tags/{tag_id}/export");
    assert!(export_block.contains("x-turbovas-replaces: tag-metadata-export-read"));
    assert!(export_block.contains("x-turbovas-exposure: direct-read"));
    assert!(
        export_block
            .contains("x-turbovas-inherited-still-owns: tag-filter-actions-and-file-export")
    );
    assert!(!export_block.contains("x-turbovas-safety-contract: write-control-v1"));
    let delete_block = openapi_path_block("/tags/{tag_id}");
    assert!(delete_block.contains("Move tag to trash"));
    assert!(delete_block.contains("x-turbovas-replaces: tag-trash-move"));
    let restore_block = openapi_path_block("/tags/{tag_id}/restore");
    assert!(restore_block.contains("x-turbovas-replaces: tag-restore"));
    let hard_delete_block = openapi_path_block("/tags/{tag_id}/trash");
    assert!(hard_delete_block.contains("x-turbovas-replaces: tag-hard-delete"));
}
