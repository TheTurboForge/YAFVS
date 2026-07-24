// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const GSA_TARGET_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/target.ts");
const GSA_TARGETS_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/targets.ts");
const GSA_NATIVE_TARGETS: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/targets.ts");
const GSA_REPORT_DETAILS: &str =
    include_str!("../../../components/gsa/src/web/pages/reports/DetailsPage.tsx");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_H: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVM_LIBS_GMP_C: &str = include_str!("../../../components/gvm-libs/gmp/gmp.c");
const GVM_LIBS_GMP_H: &str = include_str!("../../../components/gvm-libs/gmp/gmp.h");
const MANAGE_PG_C: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_TARGETS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_targets.c");
const MANAGE_TARGETS_H: &str = include_str!("../../../components/gvmd/src/manage_targets.h");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const MANAGE_COMMANDS_C: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const MANAGE_OPENVAS_C: &str = include_str!("../../../components/gvmd/src/manage_openvas.c");
const MANAGE_OPENVASD_C: &str = include_str!("../../../components/gvmd/src/manage_openvasd.c");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const TARGET_HANDLERS: &str = include_str!("target_handlers.rs");
const TARGET_WRITES: &str = include_str!("target_writes.rs");
const TARGET_QUERY_SQL: &str = include_str!("target_query_sql.rs");
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
fn target_reads_exports_and_acl_are_native_only_without_retiring_target_control() {
    let target_get = GSA_TARGET_COMMAND
        .split_once("async get({id}: EntityCommandParams)")
        .expect("GSA target get method must exist")
        .1
        .split_once("  async export")
        .expect("GSA target get method must end before export")
        .0;
    assert!(target_get.contains("requireNativeTargetApi(this.http)"));
    assert!(target_get.contains("fetchNativeTarget(this.http, id)"));
    assert!(!target_get.contains("super.get"));
    assert!(GSA_TARGET_COMMAND.contains("protected getElementFromRoot(): never"));
    assert!(
        GSA_TARGET_COMMAND
            .contains("throw new Error('Target XML response parsing has been retired')")
    );
    assert!(!GSA_TARGET_COMMAND.contains("get_targets_response"));
    assert!(!GSA_TARGET_COMMAND.contains("cmd: 'get_target'"));
    assert!(GSA_TARGETS_COMMAND.contains("protected getEntitiesResponse(): never"));
    assert!(
        GSA_TARGETS_COMMAND
            .contains("throw new Error('Target XML collection parsing has been retired')")
    );
    assert!(!GSA_TARGETS_COMMAND.contains("get_targets_response"));
    assert!(!GSA_REPORT_DETAILS.contains("gmp.target.get"));

    for retired in [
        "get_target_gmp",
        "get_targets_gmp",
        "export_target_gmp",
        "export_targets_gmp",
    ] {
        assert!(!GSAD_GMP_C.contains(retired));
        assert!(!GSAD_GMP_H.contains(retired));
    }
    for retired in [
        "get_target",
        "get_targets",
        "export_target",
        "export_targets",
    ] {
        assert!(!GSAD_VALIDATOR.contains(&format!("|({retired})")));
        assert!(!GSAD_GMP_C.contains(&format!("ELSE ({retired})")));
    }
    assert!(!GSAD_GMP_C.contains("\nget_target ("));
    assert!(!GVM_LIBS_GMP_C.contains("gmp_get_targets ("));
    assert!(!GVM_LIBS_GMP_H.contains("gmp_get_targets ("));

    for retired in [
        "get_targets_data_t",
        "get_targets_data_reset",
        "CLIENT_GET_TARGETS",
        "handle_get_targets",
        "strcasecmp (\"GET_TARGETS\"",
        "send_alive_tests_str",
        "send_alive_tests_subelems",
    ] {
        assert!(!GMP_C.contains(retired), "gvmd still contains {retired}");
    }
    assert!(!MANAGE_COMMANDS_C.contains("{\"GET_TARGETS\","));
    assert!(MANAGE_COMMANDS_C.contains("\"GET_TARGETS\","));
    assert!(!GMP_SCHEMA.contains("<name>get_targets</name>"));
    assert!(!GMP_SCHEMA.contains("<get_targets>"));
    assert!(GMP_SCHEMA.contains("<command>GET_TARGETS</command>"));

    let bulk_export = inherited_function(GSAD_GMP_C, "bulk_export_gmp");
    assert!(bulk_export.contains("g_ascii_strcasecmp (type, \"target\") == 0"));
    assert!(bulk_export.contains("MHD_HTTP_BAD_REQUEST"));
    assert!(bulk_export.contains("/api/v1/targets/{target_id}/export"));
    let target_rejection = bulk_export
        .find("g_ascii_strcasecmp (type, \"target\")")
        .unwrap();
    assert!(target_rejection < bulk_export.find("params_add (params, \"filter\"").unwrap());
    assert!(target_rejection < bulk_export.find("export_many (connection, type").unwrap());

    for native_owner in [
        "fetchNativeTargets",
        "fetchNativeTarget",
        "exportNativeTargetMetadata",
        "exportNativeTargetsMetadata",
    ] {
        assert!(GSA_NATIVE_TARGETS.contains(native_owner));
    }
    for native_owner in [
        "pub(crate) async fn targets(",
        "pub(crate) async fn target_detail(",
        "pub(crate) async fn target_export(",
    ] {
        assert!(TARGET_HANDLERS.contains(native_owner));
    }
    for metadata_field in [
        "id?: string",
        "name?: string",
        "credential_type?: string",
        "port?: number | null",
    ] {
        assert!(GSA_NATIVE_TARGETS.contains(metadata_field));
    }
    assert!(!GSA_NATIVE_TARGETS.contains("credential_iterator_password"));
    for reference_column in [
        "ssh_credential_id",
        "ssh_credential_name",
        "ssh_credential_type",
    ] {
        assert!(TARGET_QUERY_SQL.contains(reference_column));
    }
    for secret_column in ["password", "private_key", "community"] {
        assert!(!TARGET_QUERY_SQL.contains(secret_column));
    }

    for retired in ["ELSE (create_target)", "ELSE (save_target)"] {
        assert!(!GSAD_GMP_C.contains(retired));
    }
    for retained in [
        "target_openvas_ssh_credential_db",
        "credential_iterator_password",
    ] {
        assert!(MANAGE_OPENVAS_C.contains(retained));
    }
    for retained in [
        "target_openvas_ssh_credential_db",
        "openvasd_target_add_credential",
    ] {
        assert!(MANAGE_OPENVASD_C.contains(retained));
    }
}

fn openapi_path_block(path: &str) -> String {
    let marker = format!("\n  {path}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{path} path block must exist"));
    let tail = &OPENAPI[start + 1..];
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

fn openapi_operation_block(path_block: &str, method: &str) -> String {
    let marker = format!("    {method}:");
    let start = path_block
        .find(&marker)
        .unwrap_or_else(|| panic!("{method} operation block must exist"));
    let tail = &path_block[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            let trimmed = line.trim_end();
            if line.starts_with("    ")
                && !line.starts_with("      ")
                && matches!(
                    trimmed,
                    "    get:" | "    post:" | "    patch:" | "    put:" | "    delete:"
                )
            {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn raw_target_mutation_transports_and_duplicate_c_writers_are_absent() {
    for retired in [
        "CLIENT_CREATE_TARGET",
        "CLIENT_MODIFY_TARGET",
        "CLIENT_DELETE_TARGET",
        "create_target_data",
        "modify_target_data",
        "delete_target_data",
        "strcasecmp (\"CREATE_TARGET\"",
        "strcasecmp (\"MODIFY_TARGET\"",
        "strcasecmp (\"DELETE_TARGET\"",
    ] {
        assert!(!GMP_C.contains(retired), "gvmd parser retains {retired}");
    }
    for name in ["create_target", "modify_target", "delete_target"] {
        assert!(!GMP_SCHEMA.contains(&format!("<name>{name}</name>")));
    }
    for historical_reference in [
        "<command>CREATE_TARGET</command>",
        "<command>CREATE_TARGET, MODIFY_TARGET</command>",
        "<command>MODIFY_TARGET</command>",
    ] {
        assert!(
            GMP_SCHEMA.contains(historical_reference),
            "historical GMP schema provenance lost {historical_reference}"
        );
    }
    for retired in [
        "gmp_create_target_ext",
        "gmp_delete_target_ext",
        "gmp_create_target_opts_t",
    ] {
        assert!(!GVM_LIBS_GMP_C.contains(retired));
        assert!(!GVM_LIBS_GMP_H.contains(retired));
    }
    for writer in [
        "copy_target",
        "create_target",
        "modify_target",
        "delete_target",
    ] {
        assert!(!MANAGE_SQL_TARGETS_C.contains(&format!("\n{writer} (")));
        assert!(!MANAGE_TARGETS_H.contains(&format!("\n{writer} (")));
    }
    for retained_table in [
        "CREATE TABLE IF NOT EXISTS targets\"",
        "CREATE TABLE IF NOT EXISTS targets_trash\"",
        "CREATE TABLE IF NOT EXISTS targets_login_data\"",
        "CREATE TABLE IF NOT EXISTS targets_trash_login_data\"",
    ] {
        assert!(
            MANAGE_PG_C.contains(retained_table),
            "retained target storage lost {retained_table}"
        );
    }
    for native in [
        "create_target",
        "patch_target",
        "clone_target",
        "delete_target",
        "restore_target",
        "hard_delete_target",
    ] {
        assert!(
            TARGET_WRITES.contains(&format!("fn {native}")),
            "native write missing {native}"
        );
    }
    for capability in [
        "\"CREATE_TARGET\",",
        "\"MODIFY_TARGET\",",
        "\"DELETE_TARGET\",",
    ] {
        assert!(
            MANAGE_COMMANDS_C.contains(capability),
            "ACL vocabulary lost {capability}"
        );
    }
    for link in [
        "target_openvas_ssh_credential_db",
        "openvasd_target_add_credential",
    ] {
        assert!(MANAGE_OPENVAS_C.contains(link) || MANAGE_OPENVASD_C.contains(link));
    }

    for removed in ["create_target_gmp", "save_target_gmp", "delete_target_gmp"] {
        assert!(!GSAD_GMP_C.contains(removed));
        assert!(!GSAD_GMP_H.contains(removed));
    }
    for removed in ["create_target", "save_target", "delete_target"] {
        assert!(!GSAD_GMP_C.contains(&format!("ELSE ({removed})")));
        assert!(!GSAD_VALIDATOR.contains(&format!("|({removed})")));
    }

    let create_gsa = GSA_TARGET_COMMAND
        .split_once("  async create({")
        .expect("GSA target create method must exist")
        .1
        .split_once("  async save(")
        .expect("GSA target create method must end before save")
        .0;
    let save_gsa = GSA_TARGET_COMMAND
        .split_once("  async save(")
        .expect("GSA target save method must exist")
        .1;
    for method in [create_gsa, save_gsa] {
        assert!(method.contains("requireNativeTargetApi(this.http)"));
        assert!(!method.contains("entityAction("));
        assert!(!method.contains("this.action("));
        assert!(!method.contains("cmd: 'create_target'"));
        assert!(!method.contains("cmd: 'save_target'"));
    }
    assert!(create_gsa.contains("createNativeTarget(this.http, nativeCreateArgs)"));
    assert!(save_gsa.contains("patchNativeTarget(this.http, nativePatchArgs)"));

    let delete_gsa = GSA_TARGET_COMMAND
        .split_once("async delete({id}: EntityCommandParams)")
        .expect("GSA target delete method must exist")
        .1
        .split_once("  async create")
        .expect("GSA target delete method must end before create")
        .0;
    assert!(delete_gsa.contains("requireNativeTargetApi(this.http)"));
    assert!(delete_gsa.contains("deleteNativeTarget(this.http, id)"));
    assert!(!delete_gsa.contains("super.delete"));

    let delete_by_filter = GSA_TARGETS_COMMAND
        .split_once("  async deleteByFilter(filter: Filter)")
        .expect("TargetsCommand deleteByFilter method must exist")
        .1
        .split_once("  private async deleteIds")
        .expect("TargetsCommand deleteByFilter must end before deleteIds")
        .0;
    assert_eq!(
        delete_by_filter
            .matches("await this.traverseAllFilteredTargets(query)")
            .count(),
        2,
        "all-filter deletion must complete two preflight traversals"
    );
    for contract in [
        "pageSize: NATIVE_COMMAND_PAGE_SIZE",
        "firstIds.some((id, index) => id !== ids[index])",
        "preflight stabilization detected candidate-set drift",
        "const ids = targetIds(targets)",
        "deleteNativeTarget(this.http, id)",
    ] {
        assert!(
            GSA_TARGETS_COMMAND.contains(contract),
            "native target deletion lost {contract}"
        );
    }
    assert!(!GSA_TARGETS_COMMAND.contains("bulk_delete"));
    assert!(!GSA_TARGETS_COMMAND.contains("super.delete"));
}

#[test]
fn native_target_broad_mutation_routes_remain_closed() {
    for path in [
        "/api/v1/targets",
        "/api/v1/targets/12345678-1234-1234-1234-123456789abc",
        "/api/v1/targets/12345678-1234-1234-1234-123456789abc/export",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "target read path must remain direct allowlisted: {path}"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "target read path must allow GET without write control: {path}"
        );
    }

    assert!(
        direct_api_v1_method_is_allowed(
            &Method::PATCH,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc",
            true,
        ),
        "target metadata PATCH must be allowed when direct write-control is enabled"
    );
    assert!(
        !direct_api_v1_method_is_allowed(
            &Method::PATCH,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc",
            false,
        ),
        "target metadata PATCH must require direct write-control"
    );

    for (method, path) in [
        (&Method::DELETE, "/api/v1/targets"),
        (
            &Method::PATCH,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc/restore",
        ),
    ] {
        assert!(
            !direct_api_v1_method_is_allowed(method, path, true),
            "target broad mutation path must not be reachable yet: {method} {path}"
        );
    }

    for method in [Method::POST, Method::PATCH, Method::DELETE, Method::PUT] {
        assert!(
            !direct_api_v1_method_is_allowed(
                &method,
                "/api/v1/targets/12345678-1234-1234-1234-123456789abc/export",
                true,
            ),
            "target metadata export must remain GET-only: {method}"
        );
    }

    for (method, path) in [
        (
            &Method::DELETE,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc",
        ),
        (
            &Method::POST,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc/clone",
        ),
        (
            &Method::POST,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc/restore",
        ),
        (
            &Method::DELETE,
            "/api/v1/targets/12345678-1234-1234-1234-123456789abc/trash",
        ),
    ] {
        assert!(
            direct_api_v1_method_is_allowed(method, path, true),
            "target lifecycle path must be explicitly opened by this bounded slice: {method} {path}"
        );
        assert!(
            !direct_api_v1_method_is_allowed(method, path, false),
            "target lifecycle path must require direct write-control: {method} {path}"
        );
    }

    for path in [
        "/api/v1/targets/12345678-1234-1234-1234-123456789abc/clone",
        "/api/v1/targets/12345678-1234-1234-1234-123456789abc/restore",
        "/api/v1/targets/12345678-1234-1234-1234-123456789abc/trash",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "target lifecycle subpath must not be direct allowlisted yet: {path}"
        );
    }

    for (path, replacement) in [
        ("/targets", "target-list-read"),
        ("/targets/{target_id}", "target-detail-summary-read"),
    ] {
        let block = openapi_path_block(path);
        let get = openapi_operation_block(&block, "get");
        assert!(
            get.contains(replacement),
            "{path} GET OpenAPI block must keep {replacement}"
        );
        assert!(!get.contains(
            "x-yafvs-inherited-still-owns: target-file-input-task-control-and-credential-secret-workflows"
        ));
    }

    for (path, replacement) in [
        (
            "/targets/{target_id}",
            "target-metadata-simple-scan-inputs-and-credential-links-modify",
        ),
        ("/targets/{target_id}", "target-trash-move"),
        (
            "/targets",
            "target-create-with-optional-credential-references",
        ),
        ("/targets/{target_id}/clone", "target-clone"),
        ("/targets/{target_id}/restore", "target-restore"),
        ("/targets/{target_id}/trash", "target-hard-delete"),
    ] {
        let block = openapi_path_block(path);
        assert!(
            block.contains(replacement),
            "{path} OpenAPI block must keep {replacement}"
        );
        assert!(block.contains(
            "x-yafvs-inherited-still-owns: target-file-input-task-control-and-credential-secret-workflows"
        ));
    }
    let export = openapi_path_block("/targets/{target_id}/export");
    for required in [
        "get:",
        "operationId: getTargetsByTargetIdExport",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-maturity: live-read",
        "x-yafvs-replaces: target-metadata-export-read",
        "$ref: '#/components/schemas/Target'",
        "Credential references include id/name/type/port only",
        "file/host-filter input variants",
    ] {
        assert!(
            export.contains(required),
            "target metadata export OpenAPI block missing {required}"
        );
    }
    assert!(!export.contains(
        "x-yafvs-inherited-still-owns: target-file-input-task-control-and-credential-secret-workflows"
    ));
    for forbidden in [
        "x-yafvs-exposure: direct-write",
        "x-yafvs-safety-contract: write-control-v1",
        "\n    post:",
        "\n    patch:",
        "\n    put:",
        "\n    delete:",
    ] {
        assert!(
            !export.contains(forbidden),
            "target metadata export must not expose inherited write/file-export behavior: {forbidden}"
        );
    }

    let detail = openapi_path_block("/targets/{target_id}");
    assert!(detail.contains(
        "x-yafvs-replaces: target-metadata-simple-scan-inputs-and-credential-links-modify"
    ));
    assert!(detail.contains("x-yafvs-replaces: target-trash-move"));
    for forbidden in ["post:", "/clone", "/restore", "/trash"] {
        assert!(
            !detail.contains(forbidden),
            "target detail OpenAPI must not expose broad mutation {forbidden}"
        );
    }
}
