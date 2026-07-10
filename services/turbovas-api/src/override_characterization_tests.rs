// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_OVERRIDES: &str =
    include_str!("../../../components/gvmd/src/manage_sql_overrides.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const OVERRIDES_RS: &str = include_str!("overrides.rs");
const OVERRIDE_QUERY_SQL_RS: &str = include_str!("override_query_sql.rs");

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
fn inherited_override_schema_has_live_trash_result_and_scope_columns() {
    for table in ["overrides", "overrides_trash"] {
        let table_block = MANAGE_PG
            .split_once(&format!("CREATE TABLE IF NOT EXISTS {table}"))
            .unwrap_or_else(|| panic!("{table} definition must exist"))
            .1
            .split_once(");")
            .unwrap_or_else(|| panic!("{table} definition must terminate"))
            .0;
        for column in [
            "uuid text UNIQUE NOT NULL",
            "owner integer REFERENCES users",
            "nvt text NOT NULL",
            "result_nvt integer",
            "new_severity double precision",
            "severity double precision",
            "hosts text",
            "port text",
            "task integer",
            "result integer",
            "end_time integer",
        ] {
            assert!(table_block.contains(column), "{table} missing {column}");
        }
    }
}

#[test]
fn inherited_create_override_validates_severity_scope_and_rebuilds_report_caches() {
    let create_override = inherited_function(MANAGE_SQL_OVERRIDES, "create_override");
    for required in [
        "acl_user_may (\"create_override\")",
        "nvt_exists (nvt)",
        "validate_results_port (port)",
        "sscanf (severity, \"%lf\"",
        "sscanf (new_severity, \"%lf\"",
        "result_nvt_notice (nvt)",
        "INSERT INTO overrides",
        "SELECT id FROM users WHERE users.uuid",
        "SELECT id FROM result_nvts WHERE nvt",
        "acl_users_with_access_where (\"override\"",
        "reports_for_override (new_override)",
        "setting_auto_cache_rebuild_int ()",
        "report_cache_counts",
        "report_clear_count_cache",
    ] {
        assert!(
            create_override.contains(required),
            "create_override missing {required}"
        );
    }
}

#[test]
fn inherited_modify_override_validates_targets_results_and_cache_invalidation() {
    let modify_override = inherited_function(MANAGE_SQL_OVERRIDES, "modify_override");
    for required in [
        "find_override_with_permission (override_id, &override, \"modify_override\")",
        "find_task_with_permission (task_id, &task, NULL)",
        "find_trash_task_with_permission (task_id, &task, NULL)",
        "find_result_with_permission (result_id, &result, NULL)",
        "validate_results_port (port)",
        "nvt_exists (nvt)",
        "cache_invalidated_sql",
        "reports_for_override (override)",
        "result_nvt_notice (quoted_nvt)",
        "UPDATE overrides SET",
        "reports_add_for_override (reports, override)",
        "acl_users_with_access_where (\"override\"",
        "report_cache_counts",
        "report_clear_count_cache",
    ] {
        assert!(
            modify_override.contains(required),
            "modify_override missing {required}"
        );
    }
}

#[test]
fn inherited_delete_override_moves_trash_permissions_tags_and_rebuilds_report_caches() {
    let delete_override = inherited_function(MANAGE_SQL_OVERRIDES, "delete_override");
    for required in [
        "acl_user_may (\"delete_override\")",
        "find_override_with_permission (override_id, &override, \"delete_override\")",
        "find_trash (\"override\", override_id, &override)",
        "reports_for_override (override)",
        "acl_users_with_access_where (\"override\"",
        "INSERT INTO overrides_trash",
        "permissions_set_locations (\"override\"",
        "tags_set_locations (\"override\"",
        "permissions_set_orphans (\"override\"",
        "tags_remove_resource (\"override\"",
        "DELETE FROM overrides WHERE id",
        "setting_auto_cache_rebuild_int ()",
        "report_cache_counts",
        "report_clear_count_cache",
    ] {
        assert!(
            delete_override.contains(required),
            "delete_override missing {required}"
        );
    }
}

#[test]
fn native_override_reads_are_metadata_only_and_do_not_touch_report_cache_or_scanner_control() {
    for required in [
        "LEFT JOIN users u ON u.id = o.owner",
        "LEFT JOIN nvts n ON n.oid = o.nvt",
        "LEFT JOIN tasks t ON t.id = o.task",
        "LEFT JOIN results r ON r.id = o.result",
        "active_int",
        "orphan_int",
    ] {
        assert!(
            OVERRIDE_QUERY_SQL_RS.contains(required),
            "override_query_sql.rs missing {required}"
        );
    }
    for forbidden in [
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "report_cache_counts",
        "report_clear_count_cache",
        "start_task",
        "resume_task",
        "stop_task",
        "credential",
        "password",
        "secret",
    ] {
        assert!(
            !OVERRIDES_RS.contains(forbidden),
            "native override reads must not contain {forbidden}"
        );
        assert!(
            !OVERRIDE_QUERY_SQL_RS.contains(forbidden),
            "native override query SQL must not contain {forbidden}"
        );
    }
}

#[test]
fn inherited_override_result_detail_uses_result_expansion_semantics() {
    for required in [
        "find_attribute (attribute_names, attribute_values,\n                                \"result\", &attribute)",
        "get_overrides_data->result = strcmp (attribute, \"0\")",
        "override_iterator_result (overrides)",
        "result_uuid (override_iterator_result (overrides),",
        "buffer_override_xml (buffer, &overrides,\n                               get_overrides_data->get.details,\n                               get_overrides_data->result, &count)",
    ] {
        assert!(
            GMP_C.contains(required),
            "inherited override result detail path missing {required}"
        );
    }
    assert!(
        OVERRIDE_QUERY_SQL_RS.contains("LEFT JOIN results r ON r.id = o.result"),
        "native override metadata may expose a linked result reference"
    );
    assert!(
        !OVERRIDES_RS.contains("result = strcmp")
            && !OVERRIDE_QUERY_SQL_RS.contains("result = strcmp"),
        "native override reads must not claim inherited GET_OVERRIDES result expansion semantics"
    );
}

#[test]
fn native_direct_api_allows_owner_scoped_override_trash_only() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/overrides",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/export",
        false
    ));
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/overrides", true),
            "{method} /api/v1/overrides must remain closed"
        );
    }
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        if method != Method::DELETE {
            assert!(
                !direct_api_v1_method_is_allowed(
                    &method,
                    "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
                    true,
                ),
                "{method} /api/v1/overrides/{{id}} must remain closed"
            );
        }
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/export",
                true,
            ),
            "{method} /api/v1/overrides/{{id}}/export must remain closed"
        );
    }
}

#[test]
fn openapi_documents_owner_scoped_override_trash_contract() {
    let list = openapi_path_block("/overrides");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(list.contains(
        "x-turbovas-inherited-still-owns: override-create-modify-clone-xml-export-restore-hard-delete-and-result-expansion"
    ));

    let detail = openapi_path_block("/overrides/{override_id}");
    assert!(detail.contains("get:"));
    assert!(!detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("operationId: deleteOverridesByOverrideId"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(detail.contains("x-turbovas-replaces: override-trash-move"));
    assert!(detail.contains("x-turbovas-owner-semantics: preserve-existing-owner"));
    assert!(detail.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains(
        "x-turbovas-inherited-still-owns: override-create-modify-clone-xml-export-restore-hard-delete-and-result-expansion"
    ));

    let export = openapi_path_block("/overrides/{override_id}/export");
    for required in [
        "get:",
        "operationId: getOverridesByOverrideIdExport",
        "x-turbovas-direct: true",
        "x-turbovas-exposure: direct-read",
        "x-turbovas-maturity: live-read",
        "x-turbovas-replaces: override-metadata-export-read",
        "$ref: '#/components/schemas/OverrideAsset'",
    ] {
        assert!(
            export.contains(required),
            "override metadata export OpenAPI block missing {required}"
        );
    }
    assert!(export.contains(
        "x-turbovas-inherited-still-owns: override-create-modify-clone-xml-export-restore-hard-delete-and-result-expansion"
    ));
    for forbidden in [
        "x-turbovas-exposure: direct-write",
        "x-turbovas-safety-contract: write-control-v1",
        "\n    post:",
        "\n    patch:",
        "\n    delete:",
    ] {
        assert!(
            !export.contains(forbidden),
            "override metadata export must not expose inherited write/export/trash/result effects: {forbidden}"
        );
    }
}
