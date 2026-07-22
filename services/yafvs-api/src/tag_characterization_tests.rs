// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_TAGS: &str = include_str!("../../../components/gvmd/src/manage_sql_tags.c");
const MANAGE_SQL_TAGS_H: &str = include_str!("../../../components/gvmd/src/manage_sql_tags.h");
const MANAGE_TAGS_H: &str = include_str!("../../../components/gvmd/src/manage_tags.h");
const MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_C: &str = include_str!("../../../components/gvmd/src/manage.c");
const MANAGE_COMMANDS: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const GVMD_GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GVMD_GMP_GET: &str = include_str!("../../../components/gvmd/src/gmp_get.c");
const GVMD_CMAKE: &str = include_str!("../../../components/gvmd/src/CMakeLists.txt");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const YAFVS_CONTROL: &str = include_str!("../../../components/gvmd/src/yafvs_control.c");
const TAG_WRITES: &str = include_str!("tag_writes.rs");
const TAG_PAYLOADS: &str = include_str!("tag_payloads.rs");
const GSA_TAGS: &str = include_str!("../../../components/gsa/src/gmp/native-api/tags.ts");
const GSA_CAPABILITIES: &str =
    include_str!("../../../components/gsa/src/gmp/capabilities/capabilities.ts");
const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_H: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GSA_TAG_SELECTION: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/tag-resource-selection.ts");
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
fn dedicated_get_tags_xml_transport_is_retired_without_losing_shared_semantics() {
    for retired in [
        "get_tag_gmp",
        "get_tags_gmp",
        "ELSE (get_tag)",
        "ELSE (get_tags)",
    ] {
        assert!(!GSAD_GMP.contains(retired));
        assert!(!GSAD_GMP_H.contains(retired));
    }
    for retired in ["|(get_tag)", "|(get_tags)"] {
        assert!(!GSAD_VALIDATOR.contains(retired));
    }
    for retired in [
        "get_tags_data",
        "CLIENT_GET_TAGS",
        "handle_get_tags",
        "strcasecmp (\"GET_TAGS\"",
    ] {
        assert!(!GVMD_GMP.contains(retired));
    }
    assert!(!MANAGE_COMMANDS.contains("{\"GET_TAGS\""));
    assert!(MANAGE_COMMANDS.contains("\"GET_TAGS\","));
    let valid_command = inherited_function(MANAGE_COMMANDS, "valid_gmp_command");
    assert!(valid_command.contains("native_acl_operations"));

    for retired in [
        "\ntag_count (",
        "\ninit_tag_iterator (",
        "DEF_ACCESS (tag_iterator_resource_type,",
        "\ntag_iterator_active (",
        "DEF_ACCESS (tag_iterator_value,",
        "\ntag_iterator_resources (",
        "\ninit_tag_name_iterator (",
        "DEF_ACCESS (tag_name_iterator_name,",
        "\ntag_in_use (",
        "\ntrash_tag_in_use (",
        "\ntag_writable (",
        "\ntrash_tag_writable (",
    ] {
        assert!(!MANAGE_SQL_TAGS.contains(retired));
        assert!(!MANAGE_TAGS_H.contains(retired));
    }
    assert!(!GVMD_CMAKE.contains("manage_tags.c"));
    assert!(!GMP_SCHEMA.contains("<name>get_tags</name>"));
    assert!(GMP_SCHEMA.contains("CREATE_TAG, GET_TAGS, MODIFY_TAG"));

    for retained in ["TAG_ITERATOR_FILTER_COLUMNS", "TAG_ITERATOR_COLUMNS"] {
        assert!(MANAGE_SQL_TAGS_H.contains(retained));
    }
    for retained in ["tags_remove_resource (", "tags_set_locations ("] {
        assert!(
            MANAGE_SQL_TAGS.contains(retained),
            "shared tag lifecycle helper was lost: {retained}"
        );
        assert!(
            MANAGE_SQL_TAGS_H.contains(retained),
            "shared tag lifecycle declaration was lost: {retained}"
        );
    }
    assert!(!MANAGE_SQL_TAGS_H.contains("TAG_ITERATOR_TRASH_COLUMNS"));
    let select_columns = inherited_function(MANAGE_SQL, "type_select_columns");
    assert!(select_columns.contains("strcasecmp (type, \"TAG\") == 0"));
    assert!(select_columns.contains("return tag_columns"));
    let filter_columns = inherited_function(MANAGE_SQL, "type_filter_columns");
    assert!(filter_columns.contains("strcasecmp (type, \"TAG\") == 0"));
    assert!(filter_columns.contains("TAG_ITERATOR_FILTER_COLUMNS"));

    for retained in [
        "init_resource_tag_iterator (",
        "resource_tag_iterator_uuid",
        "resource_tag_iterator_name",
        "resource_tag_iterator_value",
        "resource_tag_iterator_comment",
        "resource_tag_exists (",
        "resource_tag_count (",
    ] {
        assert!(
            MANAGE_SQL_TAGS.contains(retained),
            "shared tag implementation was lost: {retained}"
        );
        assert!(
            MANAGE_TAGS_H.contains(retained),
            "shared tag declaration was lost: {retained}"
        );
    }
    for (consumer, source) in [
        ("generic resource response", GVMD_GMP_GET),
        ("override and result response", GVMD_GMP),
        ("NVT response", MANAGE_C),
        ("report and task response", MANAGE_SQL),
    ] {
        assert!(
            source.contains("init_resource_tag_iterator"),
            "{consumer} lost shared tag expansion"
        );
        assert!(
            source.contains("resource_tag_iterator_uuid"),
            "{consumer} lost shared tag identity expansion"
        );
    }
    assert!(GSA_TAGS.contains("api/v1/tags"));
    assert!(GSA_CAPABILITIES.contains("'get_tags'"));
    assert!(TAG_PAYLOADS.contains("row.get::<_, bool>(\"human_owned\")"));
    assert!(TAG_PAYLOADS.contains("tag_resource_direct_write_type_is_supported"));
    assert!(TAG_PAYLOADS.contains("in_use: false"));

    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(!repo.join("components/gvmd/src/manage_tags.c").exists());
}

#[test]
fn generic_gsad_bulk_delete_rejects_tags_before_xml_synthesis() {
    let bulk_delete = inherited_function(GSAD_GMP, "bulk_delete_gmp");
    let rejection = bulk_delete
        .find("g_ascii_strcasecmp (type, \"tag\")")
        .expect("generic gsad bulk delete must reject tags case-insensitively");
    let synthesis = bulk_delete
        .find("g_strdup_printf (\"<delete_%s")
        .expect("generic bulk delete synthesis boundary must remain visible");
    assert!(rejection < synthesis);
}

#[test]
fn every_live_filtered_bulk_tag_page_has_a_typed_selector() {
    fn collect_bulk_tag_pages(
        root: &std::path::Path,
        current: &std::path::Path,
        pages: &mut std::collections::BTreeSet<String>,
    ) {
        for entry in std::fs::read_dir(current).expect("GSA page directory must be readable") {
            let path = entry.expect("GSA page entry must be readable").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "__tests__") {
                    continue;
                }
                collect_bulk_tag_pages(root, &path, pages);
            } else if matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("ts" | "tsx" | "js" | "jsx")
            ) {
                let source =
                    std::fs::read_to_string(&path).expect("GSA page source must be readable");
                if source.contains("onTagsBulk={") {
                    pages.insert(
                        path.strip_prefix(root)
                            .expect("GSA page must be below page root")
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
    }

    let page_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../components/gsa/src/web/pages");
    let mut pages = std::collections::BTreeSet::new();
    collect_bulk_tag_pages(&page_root, &page_root, &mut pages);
    let expected = [
        "credentials/CredentialListPage.tsx",
        "portlists/PortListListPage.tsx",
        "scanners/ScannerListPage.tsx",
        "targets/TargetListPage.tsx",
        "users/UsersListPage.jsx",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(pages, expected);
    for resource_type in ["credential", "portlist", "scanner", "target", "user"] {
        assert!(
            GSA_TAG_SELECTION.contains(&format!("case '{resource_type}'")),
            "live filtered bulk-tag resource lacks typed selector: {resource_type}"
        );
    }
}

#[test]
fn tag_creation_has_no_transitional_filter_control_path() {
    assert!(!YAFVS_CONTROL.contains("\"tag-create "));
    assert!(!YAFVS_CONTROL.contains("\"tag-modify "));
    assert!(!TAG_WRITES.contains("request_tag_create"));
    assert!(!TAG_WRITES.contains("request_tag_modify"));

    let gsa_create = GSA_TAGS
        .split_once("export const createNativeTag")
        .expect("native GSA tag create adapter must exist")
        .1
        .split_once("export const patchNativeTag")
        .expect("native GSA tag patch adapter must follow create")
        .0;
    assert!(!gsa_create.contains("resource_filter"));
    assert!(!GSA_TAGS.contains("resource_filter"));
}

#[test]
fn retired_and_dangling_gsad_tag_commands_stay_removed() {
    for function in [
        "create_tags_gmp",
        "create_tag_gmp",
        "delete_tag_gmp",
        "save_tag_gmp",
        "toggle_tag_gmp",
    ] {
        assert!(
            !GSAD_GMP.contains(function),
            "obsolete GSAD function remains: {function}"
        );
    }
    for command in [
        "create_tags",
        "create_tag",
        "delete_tag",
        "save_tag",
        "toggle_tag",
    ] {
        assert!(
            !GSAD_VALIDATOR.contains(&format!("|({command})")),
            "obsolete GSAD validator command remains: {command}"
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
fn raw_gmp_tag_mutation_and_generic_restore_are_retired() {
    for retired in [
        "CLIENT_CREATE_TAG",
        "CLIENT_DELETE_TAG",
        "CLIENT_MODIFY_TAG",
        "create_tag_data",
        "delete_tag_data",
        "modify_tag_data",
        "strcasecmp (\"CREATE_TAG\"",
        "strcasecmp (\"DELETE_TAG\"",
        "strcasecmp (\"MODIFY_TAG\"",
    ] {
        assert!(
            !GVMD_GMP.contains(retired),
            "raw GMP tag residue: {retired}"
        );
    }
    for retired in [
        "\ntag_uuid (",
        "\ncopy_tag (",
        "\ndelete_tag (",
        "\ncreate_tag (",
        "\nmodify_tag (",
        "\nfind_tag_with_permission (",
        "\ntag_add_resource (",
        "\ntag_add_resource_uuid (",
        "\ntag_add_resources_list (",
        "\ntag_add_resources_filter (",
        "\ntag_remove_resources_list (",
        "\ntag_remove_resources_filter (",
    ] {
        assert!(
            !MANAGE_SQL_TAGS.contains(retired),
            "raw tag SQL writer residue: {retired}"
        );
        assert!(
            !MANAGE_TAGS_H.contains(retired),
            "raw tag writer declaration residue: {retired}"
        );
    }

    for retired in ["CREATE_TAG", "DELETE_TAG", "MODIFY_TAG"] {
        assert!(
            !MANAGE_COMMANDS.contains(&format!("{{\"{retired}\"")),
            "retired command remains public: {retired}"
        );
        assert!(
            MANAGE_COMMANDS.contains(&format!("\"{retired}\",")),
            "native ACL operation key was lost: {retired}"
        );
    }
    for retired in ["create_tag", "delete_tag", "modify_tag"] {
        assert!(
            !GMP_SCHEMA.contains(&format!("<name>{retired}</name>")),
            "retired live schema command remains: {retired}"
        );
    }
    assert!(GMP_SCHEMA.contains("CREATE_TAG, GET_TAGS, MODIFY_TAG"));

    assert!(!MANAGE_SQL.contains("\nmanage_restore ("));
    assert!(!GVMD_GMP.contains("CLIENT_RESTORE"));
    assert!(!GVMD_GMP.contains("strcasecmp (\"RESTORE\""));
    assert!(!MANAGE_COMMANDS.contains("{\"RESTORE\""));
    assert!(!GMP_SCHEMA.contains("<name>restore</name>"));
}

#[test]
fn native_direct_api_exposes_bounded_tag_reads_and_writes() {
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
            "{method} tag metadata export must stay read-only"
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
fn openapi_tag_contract_replaces_filter_and_resource_type_tail() {
    let create_block = openapi_path_block("/tags");
    assert!(!create_block.contains("x-yafvs-inherited-still-owns"));
    assert!(!create_block.contains("resource_filter"));
    let resource_block = openapi_path_block("/tags/{tag_id}/resources");
    assert!(!resource_block.contains("x-yafvs-inherited-still-owns"));
    assert!(!resource_block.contains("resource_filter"));
    let patch_block = openapi_path_block("/tags/{tag_id}");
    assert!(
        patch_block
            .contains("x-yafvs-replaces: tag-metadata-resource-type-and-atomic-assignment-write")
    );
    assert!(patch_block.contains("typed collection selectors"));
    assert!(patch_block.contains("raw manager filter expressions"));
    assert!(patch_block.contains("Raw GMP tag modification is retired"));
    assert!(!patch_block.contains("remain inherited"));
    let clone_block = openapi_path_block("/tags/{tag_id}/clone");
    assert!(clone_block.contains("x-yafvs-replaces: tag-clone"));
    assert!(clone_block.contains("x-yafvs-safety-contract: write-control-v1"));
    let export_block = openapi_path_block("/tags/{tag_id}/export");
    assert!(export_block.contains("x-yafvs-replaces: tag-metadata-export-read"));
    assert!(export_block.contains("x-yafvs-exposure: direct-read"));
    assert!(!export_block.contains("x-yafvs-inherited-still-owns"));
    assert!(!export_block.contains("x-yafvs-safety-contract: write-control-v1"));
    let delete_block = openapi_path_block("/tags/{tag_id}");
    assert!(delete_block.contains("Move tag to trash"));
    assert!(delete_block.contains("x-yafvs-replaces: tag-trash-move"));
    let restore_block = openapi_path_block("/tags/{tag_id}/restore");
    assert!(restore_block.contains("x-yafvs-replaces: tag-restore"));
    let hard_delete_block = openapi_path_block("/tags/{tag_id}/trash");
    assert!(hard_delete_block.contains("x-yafvs-replaces: tag-hard-delete"));
}
