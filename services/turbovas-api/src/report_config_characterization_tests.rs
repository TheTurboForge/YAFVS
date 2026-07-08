// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::{
    direct_api::direct_api_v1_method_is_allowed,
    report_config_query_sql::{report_config_asset_detail_sql, report_config_assets_sql},
};

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_REPORT_CONFIGS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_report_configs.c");
const GMP_REPORT_CONFIGS: &str = include_str!("../../../components/gvmd/src/gmp_report_configs.c");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSA_ENTITY_TS: &str = include_str!("../../../components/gsa/src/gmp/commands/entity.ts");
const GSA_ENTITIES_TS: &str = include_str!("../../../components/gsa/src/gmp/commands/entities.ts");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const REPORT_CONFIG_PAYLOADS_RS: &str = include_str!("report_config_payloads.rs");

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
fn native_report_config_read_sql_is_metadata_and_format_context_only() {
    let list_sql = report_config_assets_sql("name ASC");
    let detail_sql = report_config_asset_detail_sql();
    let combined = format!("{list_sql}\n{detail_sql}");
    let upper_sql = combined.to_ascii_uppercase();

    for required in [
        "FROM report_configs rc",
        "LEFT JOIN users u ON u.id = rc.owner",
        "LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id",
        "coalesce(rc.report_format_id, '') AS report_format_id",
        "coalesce(rf.name, '') AS report_format_name",
    ] {
        assert!(
            combined.contains(required),
            "report-config read SQL missing {required}"
        );
    }
    assert!(list_sql.contains("count(*) OVER()::bigint AS total"));
    assert!(list_sql.contains("ORDER BY name ASC, name ASC, id ASC LIMIT $2 OFFSET $3"));
    for forbidden in [
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "TRASH",
        "credentials",
        "password",
        "secret",
    ] {
        assert!(
            !upper_sql.contains(&forbidden.to_ascii_uppercase()),
            "report-config read SQL must not include write or secret path: {forbidden}"
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

fn source_function(source: &str, name: &str) -> String {
    let marker = format!("fn {name}(");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} function marker must exist"));
    let tail = &source[start..];
    let end = tail
        .find("\npub(crate) async fn")
        .or_else(|| tail.find("\n#[cfg(test)]"))
        .unwrap_or(tail.len());
    tail[..end].to_string()
}

#[test]
fn inherited_report_config_schema_has_live_trash_and_param_children() {
    let report_configs_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS report_configs")
        .expect("report_configs table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS report_configs_trash")
        .expect("report_configs_trash must follow report_configs")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "comment text",
        "report_format_id text",
        "creation_time integer",
        "modification_time integer",
    ] {
        assert!(
            report_configs_table.contains(column),
            "report_configs table missing {column}"
        );
    }

    let report_configs_trash_table = MANAGE_PG
        .split_once("CREATE TABLE IF NOT EXISTS report_configs_trash")
        .expect("report_configs_trash table definition must exist")
        .1
        .split_once("CREATE TABLE IF NOT EXISTS report_config_params")
        .expect("report_config_params must follow report_configs_trash")
        .0;
    for column in [
        "uuid text UNIQUE NOT NULL",
        "owner integer REFERENCES users",
        "name text NOT NULL",
        "report_format_id text",
    ] {
        assert!(
            report_configs_trash_table.contains(column),
            "report_configs_trash table missing {column}"
        );
    }

    for (table, reference) in [
        (
            "report_config_params",
            "REFERENCES report_configs (id) ON DELETE RESTRICT",
        ),
        (
            "report_config_params_trash",
            "REFERENCES report_configs_trash (id) ON DELETE RESTRICT",
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
            "report_config integer",
            reference,
            "name text",
            "value text",
        ] {
            assert!(table_block.contains(column), "{table} missing {column}");
        }
    }
}

#[test]
fn inherited_create_and_modify_report_config_validate_format_params_acl_and_owner() {
    let validate_report_config_param =
        inherited_function(MANAGE_SQL_REPORT_CONFIGS, "validate_report_config_param");
    for required in [
        "SELECT id FROM report_format_params",
        "report_format = %llu",
        "AND name = '%s'",
        "report format has no parameter",
        "report_format_validate_param_value",
    ] {
        assert!(
            validate_report_config_param.contains(required),
            "validate_report_config_param missing {required}"
        );
    }

    let create_report_config =
        inherited_function(MANAGE_SQL_REPORT_CONFIGS, "create_report_config");
    for required in [
        "acl_user_may (\"create_report_config\")",
        "SELECT count(*) FROM report_configs WHERE name",
        "find_report_format_with_permission (report_format_id",
        "SELECT count(*) FROM report_format_params",
        "INSERT INTO report_configs",
        "SELECT id FROM users WHERE uuid",
        "current_credentials.uuid",
        "validate_report_config_param",
        "insert_report_config_param",
    ] {
        assert!(
            create_report_config.contains(required),
            "create_report_config missing {required}"
        );
    }

    let modify_report_config =
        inherited_function(MANAGE_SQL_REPORT_CONFIGS, "modify_report_config");
    for required in [
        "acl_user_may (\"modify_report_config\")",
        "find_report_config_with_permission (report_config_id",
        "SELECT count(*) FROM report_configs",
        "UPDATE report_configs SET name",
        "UPDATE report_configs SET comment",
        "SELECT id FROM report_formats",
        "DELETE FROM report_config_params",
        "validate_report_config_param",
        "insert_report_config_param",
        "SET modification_time = m_now ()",
    ] {
        assert!(
            modify_report_config.contains(required),
            "modify_report_config missing {required}"
        );
    }
}

#[test]
fn inherited_delete_and_restore_report_config_are_alert_guarded_trash_permissions_and_tags() {
    let delete_report_config =
        inherited_function(MANAGE_SQL_REPORT_CONFIGS, "delete_report_config");
    for required in [
        "acl_user_may (\"delete_report_config\")",
        "find_report_config_with_permission (report_config_id",
        "find_trash (\"report_config\", report_config_id",
        "trash_report_config_in_use (report_config)",
        "report_config_in_use (report_config)",
        "permissions_set_orphans (\"report_config\"",
        "tags_remove_resource (\"report_config\"",
        "INSERT INTO report_configs_trash",
        "INSERT INTO report_config_params_trash",
        "permissions_set_locations (\"report_config\"",
        "tags_set_locations (\"report_config\"",
        "DELETE FROM report_config_params",
        "DELETE FROM report_configs",
    ] {
        assert!(
            delete_report_config.contains(required),
            "delete_report_config missing {required}"
        );
    }

    let restore_report_config =
        inherited_function(MANAGE_SQL_REPORT_CONFIGS, "restore_report_config");
    for required in [
        "find_trash (\"report_config\", report_config_id",
        "ACL_USER_OWNS",
        "SELECT count(*) FROM report_configs",
        "WHERE name =",
        "WHERE uuid = (SELECT uuid",
        "INSERT INTO report_configs",
        "INSERT INTO report_config_params",
        "permissions_set_locations (\"report_config\"",
        "tags_set_locations (\"report_config\"",
        "DELETE FROM report_config_params_trash",
        "DELETE FROM report_configs_trash",
        "sql_commit ()",
    ] {
        assert!(
            restore_report_config.contains(required),
            "restore_report_config missing {required}"
        );
    }
}

#[test]
fn inherited_gmp_report_config_parser_contract_is_copy_or_metadata_param_write() {
    let params_from_entity = inherited_function(GMP_REPORT_CONFIGS, "params_from_entity");
    for required in [
        "strcmp (entity_name (param_entity), \"param\") == 0",
        "param_name = entity_child (param_entity, \"name\")",
        "g_strstrip (g_strdup (entity_text (param_name)))",
        "strcmp (param->name, \"\") == 0",
        "param_value = entity_child (param_entity, \"value\")",
        "entity_attribute (param_value, \"use_default\")",
        "array_add (params, param)",
    ] {
        assert!(
            params_from_entity.contains(required),
            "params_from_entity missing {required}"
        );
    }

    let create_run = inherited_function(GMP_REPORT_CONFIGS, "create_report_config_run");
    for required in [
        "copy = entity_child (entity, \"copy\")",
        "copy_report_config (name ? entity_text (name) : NULL",
        "report_format = entity_child (entity, \"report_format\")",
        "entity_attribute (report_format, \"id\")",
        "A NAME element is required",
        "The NAME element must not be empty",
        "A REPORT_FORMAT element with an ID attribute",
        "params = params_from_entity (entity)",
        "create_report_config (name->text",
        "Parameter validation failed: %s",
    ] {
        assert!(
            create_run.contains(required),
            "create_report_config_run missing {required}"
        );
    }

    let modify_run = inherited_function(GMP_REPORT_CONFIGS, "modify_report_config_run");
    for required in [
        "entity_attribute(entity, \"report_config_id\")",
        "A report_config_id attribute is required",
        "The NAME element must not be empty",
        "params = params_from_entity (entity)",
        "modify_report_config (report_config_id",
        "Cannot modify params of",
        "Parameter validation failed: %s",
    ] {
        assert!(
            modify_run.contains(required),
            "modify_report_config_run missing {required}"
        );
    }
}

#[test]
fn report_config_native_metadata_export_no_longer_uses_singular_gsad_xml_export() {
    assert!(
        !GSAD_GMP_C.contains("export_report_config_gmp"),
        "singular report-config metadata export must stay native JSON, not legacy gsad XML"
    );
    assert!(
        !GSAD_GMP_C.contains("export_report_configs_gmp"),
        "bulk report-config XML export must not stay exposed once native JSON metadata export is retained"
    );

    let bulk_export = inherited_function(GSAD_GMP_C, "bulk_export_gmp");
    assert!(
        bulk_export.contains("str_equal (type, \"report_config\")"),
        "generic bulk export must reject report_config after native JSON metadata export replacement"
    );
    for required in [
        "resource_type",
        "bulk_select",
        "bulk_selected:",
        "first=1 rows=-1 uuid=",
        "params_add (params, \"filter\"",
        "return export_many (connection, type",
    ] {
        assert!(
            bulk_export.contains(required),
            "bulk_export_gmp missing {required}"
        );
    }

    for required in [
        "async export({id}: EntityCommandParams)",
        "cmd: 'bulk_export'",
        "resource_type: this.name",
        "bulk_select: BULK_SELECT_BY_IDS",
        "['bulk_selected:' + id]: 1",
    ] {
        assert!(
            GSA_ENTITY_TS.contains(required),
            "single entity export missing {required}"
        );
    }

    for required in [
        "exportByIds(ids: string[])",
        "cmd: 'bulk_export'",
        "resource_type: this.name",
        "bulk_select: BULK_SELECT_BY_IDS",
        "data['bulk_selected:' + id] = 1",
    ] {
        assert!(
            GSA_ENTITIES_TS.contains(required),
            "bulk entity export missing {required}"
        );
    }

    for forbidden in [
        "get_reports",
        "report_format_id",
        "config_id",
        "apply_report_format",
        "manage_send_report",
        "report_id",
    ] {
        assert!(
            !bulk_export.contains(forbidden),
            "generic bulk export must not include report-generation boundary {forbidden}"
        );
    }
}

#[test]
fn native_report_config_reads_are_metadata_only_and_do_not_generate_reports_or_touch_secrets() {
    let detail_loader = source_function(REPORT_CONFIG_PAYLOADS_RS, "report_config_asset_from_row");
    for required in [
        "JOIN alert_method_data",
        "report_format_params rfp",
        "LEFT JOIN report_config_params rcp",
        "report_config_param_from_row",
        "let in_use = !alerts.is_empty();",
        "owner_name",
        "report_format_id",
    ] {
        assert!(
            detail_loader.contains(required),
            "report_config_asset_from_row missing {required}"
        );
    }
    for forbidden in [
        "credential",
        "password",
        "secret",
        "feed",
        "apply_report_format",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "report_config_in_use",
    ] {
        assert!(
            !detail_loader.contains(forbidden),
            "report_config_asset_from_row must not contain {forbidden}"
        );
    }
}

#[test]
fn native_report_config_report_format_list_values_are_type_gated() {
    let param_loader = source_function(REPORT_CONFIG_PAYLOADS_RS, "report_config_param_from_row");
    assert_eq!(
        param_loader.matches("if param_type_int == 5").count(),
        2,
        "report-format reference expansion must be gated to type 5 for value and default"
    );
    assert!(param_loader.contains("report_config_param_values_from_csv(client, &value)"));
    assert!(param_loader.contains("report_config_param_values_from_csv(client, &default)"));
    assert!(param_loader.contains("if param_type_int == 2 || param_type_int == 6"));
    assert!(param_loader.contains("report_format_param_options"));
}

#[test]
fn native_direct_api_exposes_only_report_config_create_write_control() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/report-configs",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
        false
    ));
    let export_path = "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc/export";
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
            "{method} report-config metadata export must stay closed; XML/file export remains inherited"
        );
    }
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/report-configs",
        true
    ));
    for method in [Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/report-configs", true),
            "{method} /api/v1/report-configs must remain closed"
        );
    }
    for method in [Method::POST, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/report-configs/{{id}} must remain closed"
        );
    }
    assert!(
        direct_api_v1_method_is_allowed(
            &Method::PATCH,
            "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
            true,
        ),
        "PATCH /api/v1/report-configs/{{id}} is now native direct write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(
            &Method::DELETE,
            "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
            true,
        ),
        "DELETE /api/v1/report-configs/{{id}} is now native direct write-control for trash moves"
    );
    assert!(
        direct_api_v1_method_is_allowed(
            &Method::POST,
            "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc/clone",
            true,
        ),
        "POST /api/v1/report-configs/{{id}}/clone is now native direct write-control"
    );
    assert!(
        !direct_api_v1_method_is_allowed(
            &Method::POST,
            "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc/clone",
            false,
        ),
        "clone must stay closed without direct write-control enablement"
    );
}

#[test]
fn openapi_documents_report_config_create_and_patch_as_direct_write_control() {
    let list = openapi_path_block("/report-configs");
    assert!(list.contains("get:"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-write"));
    assert!(list.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(!list.contains("x-turbovas-inherited-still-owns:"));

    let detail = openapi_path_block("/report-configs/{report_config_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(detail.contains("x-turbovas-replaces: report-config-metadata-param-modify"));
    assert!(detail.contains("x-turbovas-replaces: report-config-trash-move"));
    assert!(detail.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!detail.contains("x-turbovas-inherited-still-owns:"));

    let clone = openapi_path_block("/report-configs/{report_config_id}/clone");
    assert!(clone.contains("post:"));
    assert!(clone.contains("x-turbovas-exposure: direct-write"));
    assert!(clone.contains("x-turbovas-replaces: report-config-clone"));
    assert!(clone.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!clone.contains("x-turbovas-inherited-still-owns:"));
    let restore = openapi_path_block("/report-configs/{report_config_id}/restore");
    assert!(restore.contains("post:"));
    assert!(restore.contains("x-turbovas-exposure: direct-write"));
    assert!(restore.contains("x-turbovas-replaces: report-config-restore"));
    assert!(restore.contains("x-turbovas-safety-contract: write-control-v1"));
    let hard_delete = openapi_path_block("/report-configs/{report_config_id}/trash");
    assert!(hard_delete.contains("delete:"));
    assert!(hard_delete.contains("x-turbovas-exposure: direct-write"));
    assert!(hard_delete.contains("x-turbovas-replaces: report-config-hard-delete"));
    assert!(hard_delete.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!hard_delete.contains("x-turbovas-inherited-still-owns:"));
    let export = openapi_path_block("/report-configs/{report_config_id}/export");
    assert!(export.contains("get:"));
    assert!(export.contains("x-turbovas-exposure: direct-read"));
    assert!(export.contains("x-turbovas-replaces: report-config-metadata-export-read"));
    assert!(!export.contains("x-turbovas-inherited-still-owns:"));
    assert!(!export.contains("x-turbovas-safety-contract: write-control-v1"));
}
