// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const OPENAPI: &str = include_str!("../../../api/openapi/yafvs-v1.yaml");
const OVERRIDES_RS: &str = include_str!("overrides.rs");
const OVERRIDE_QUERY_SQL_RS: &str = include_str!("override_query_sql.rs");

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
fn native_direct_api_allows_override_writes_under_write_control() {
    let id = "12345678-1234-1234-1234-123456789abc";
    for path in [
        "/api/v1/overrides",
        "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/export",
    ] {
        assert!(direct_api_v1_method_is_allowed(&Method::GET, path, false));
        assert!(direct_api_v1_method_is_allowed(&Method::GET, path, true));
    }

    let write_routes = [
        (Method::POST, "/api/v1/overrides"),
        (
            Method::PATCH,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        ),
        (
            Method::DELETE,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        ),
        (
            Method::POST,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/clone",
        ),
        (
            Method::POST,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/restore",
        ),
        (
            Method::DELETE,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/trash",
        ),
    ];
    for (method, path) in write_routes {
        assert!(
            !direct_api_v1_method_is_allowed(&method, path, false),
            "{method} {path} must require write control"
        );
        assert!(
            direct_api_v1_method_is_allowed(&method, path, true),
            "{method} {path} must be open under write control"
        );
    }

    for (method, path) in [
        (Method::PATCH, "/api/v1/overrides"),
        (Method::DELETE, "/api/v1/overrides"),
        (
            Method::POST,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        ),
        (
            Method::PUT,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc",
        ),
        (
            Method::PATCH,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/restore",
        ),
        (
            Method::POST,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/trash",
        ),
        (
            Method::POST,
            "/api/v1/overrides/12345678-1234-1234-1234-123456789abc/export",
        ),
    ] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, path, true),
            "{method} {path} must remain closed"
        );
    }
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        &format!("/api/v1/overrides/{id}"),
        false,
    ));
}

#[test]
fn openapi_documents_override_native_contract() {
    let list = openapi_path_block("/overrides");
    assert!(list.contains("get:"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-yafvs-exposure: direct-read"));
    assert!(list.contains("x-yafvs-exposure: direct-write"));
    assert!(list.contains("x-yafvs-replaces: override-create"));
    assert!(list.contains("x-yafvs-operator-identity: direct-token-operator"));
    assert!(list.contains("x-yafvs-owner-semantics: request-operator-owner"));
    assert!(list.contains("x-yafvs-safety-contract: write-control-v1"));
    assert!(!list.contains("x-yafvs-inherited-still-owns:"));
    assert!(list.contains("XML metadata export"));
    assert!(list.contains("override aggregate dashboards"));
    assert!(list.contains("filtered override-detail result expansion"));

    let detail = openapi_path_block("/overrides/{override_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(detail.contains("operationId: patchOverridesByOverrideId"));
    assert!(detail.contains("x-yafvs-exposure: direct-write"));
    assert!(detail.contains("x-yafvs-replaces: override-metadata-modify"));
    assert!(detail.contains("x-yafvs-replaces: override-trash-move"));
    assert!(detail.contains("x-yafvs-owner-semantics: preserve-existing-owner"));
    assert!(detail.contains("x-yafvs-safety-contract: write-control-v1"));
    assert!(detail.contains("x-yafvs-exposure: direct-read"));
    assert!(!detail.contains("x-yafvs-inherited-still-owns:"));

    for (path, required) in [
        (
            "/overrides/{override_id}/clone",
            &[
                "post:",
                "operationId: postOverridesByOverrideIdClone",
                "x-yafvs-exposure: direct-write",
                "x-yafvs-owner-semantics: request-operator-owner",
                "x-yafvs-safety-contract: write-control-v1",
                "OverrideCloneRequest",
            ][..],
        ),
        (
            "/overrides/{override_id}/restore",
            &[
                "post:",
                "operationId: postOverridesByOverrideIdRestore",
                "x-yafvs-exposure: direct-write",
                "x-yafvs-owner-semantics: preserve-existing-owner",
                "x-yafvs-safety-contract: write-control-v1",
            ][..],
        ),
        (
            "/overrides/{override_id}/trash",
            &[
                "delete:",
                "operationId: deleteOverridesByOverrideIdTrash",
                "x-yafvs-exposure: direct-write",
                "x-yafvs-owner-semantics: preserve-existing-owner",
                "x-yafvs-safety-contract: write-control-v1",
            ][..],
        ),
    ] {
        let block = openapi_path_block(path);
        for required in required {
            assert!(block.contains(required), "{path} missing {required}");
        }
        assert!(!block.contains("x-yafvs-inherited-still-owns:"));
    }

    let export = openapi_path_block("/overrides/{override_id}/export");
    for required in [
        "get:",
        "operationId: getOverridesByOverrideIdExport",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-maturity: live-read",
        "x-yafvs-replaces: override-metadata-export-read",
        "$ref: '#/components/schemas/OverrideAsset'",
    ] {
        assert!(
            export.contains(required),
            "override metadata export OpenAPI block missing {required}"
        );
    }
    assert!(!export.contains("x-yafvs-inherited-still-owns:"));

    let create_schema = OPENAPI
        .split_once("    OverrideCreateRequest:\n")
        .expect("override create schema must exist")
        .1
        .split_once("    OverridePatchRequest:\n")
        .expect("override patch schema must follow create schema")
        .0;
    for required in [
        "required: [nvt_id, text, new_severity]",
        "        hosts:",
        "          type: [string, 'null']",
        "        port:",
        "        severity:",
        "        task_id:",
        "        result_id:",
        "        activation:",
        "$ref: '#/components/schemas/OverrideActivation'",
    ] {
        assert!(
            create_schema.contains(required),
            "create schema missing {required}"
        );
    }
    let patch_schema = OPENAPI
        .split_once("    OverridePatchRequest:\n")
        .expect("override patch schema must exist")
        .1
        .split_once("    OverrideCloneRequest:\n")
        .expect("override clone schema must follow patch schema")
        .0;
    assert!(patch_schema.contains("minProperties: 1"));
    assert!(patch_schema.contains("        nvt_id:"));
    assert!(patch_schema.contains("        new_severity:"));
    assert!(patch_schema.contains("        activation:"));
    assert!(patch_schema.matches("'null'").count() >= 5);
    let clone_schema = OPENAPI
        .split_once("    OverrideCloneRequest:\n")
        .expect("override clone schema must exist")
        .1;
    assert!(clone_schema.contains("maxProperties: 0"));
    let activation_schema = OPENAPI
        .split_once("    OverrideActivation:\n")
        .expect("override activation schema must exist")
        .1
        .split_once("    OverrideCreateRequest:\n")
        .expect("override activation schema must precede create schema")
        .0;
    for mode in ["always", "inactive", "for_days"] {
        assert!(activation_schema.contains(&format!("enum: [{mode}]")));
    }
    assert!(activation_schema.contains("minimum: 1"));
}
