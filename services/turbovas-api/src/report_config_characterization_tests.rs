// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_REPORT_CONFIGS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_report_configs.c");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const REPORT_CONFIGS_RS: &str = include_str!("report_configs.rs");

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
fn native_report_config_reads_are_metadata_only_and_do_not_generate_reports_or_touch_secrets() {
    let detail_loader = source_function(REPORT_CONFIGS_RS, "report_config_asset_from_row");
    for required in [
        "JOIN alert_method_data",
        "report_format_params rfp",
        "LEFT JOIN report_config_params rcp",
        "report_config_param_from_row",
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
    ] {
        assert!(
            !detail_loader.contains(forbidden),
            "report_config_asset_from_row must not contain {forbidden}"
        );
    }
}

#[test]
fn native_report_config_report_format_list_values_are_type_gated() {
    let param_loader = source_function(REPORT_CONFIGS_RS, "report_config_param_from_row");
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
fn native_direct_api_keeps_report_config_writes_closed_until_full_contract_lands() {
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
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, "/api/v1/report-configs", true),
            "{method} /api/v1/report-configs must remain closed"
        );
    }
    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/report-configs/12345678-1234-1234-1234-123456789abc",
                true,
            ),
            "{method} /api/v1/report-configs/{{id}} must remain closed"
        );
    }
}

#[test]
fn openapi_documents_report_configs_as_read_only_until_write_contract_lands() {
    let list = openapi_path_block("/report-configs");
    assert!(list.contains("get:"));
    assert!(!list.contains("post:"));
    assert!(list.contains("x-turbovas-exposure: direct-read"));
    assert!(
        list.contains("x-turbovas-inherited-still-owns: report-config-export-writes-and-deletes")
    );

    let detail = openapi_path_block("/report-configs/{report_config_id}");
    assert!(detail.contains("get:"));
    assert!(!detail.contains("patch:"));
    assert!(!detail.contains("delete:"));
    assert!(detail.contains("x-turbovas-exposure: direct-read"));
    assert!(
        detail.contains("x-turbovas-inherited-still-owns: report-config-export-writes-and-deletes")
    );
}
