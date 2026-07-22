// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::direct_api_v1_method_is_allowed;

const MANAGE_PG_C: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_REPORT_FORMATS_C: &str =
    include_str!("../../../components/gvmd/src/manage_report_formats.c");
const MANAGE_SQL_REPORT_FORMATS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_report_formats.c");
const GVMD_GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GVMD_MANAGE_COMMANDS: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const GVMD_GMP_SCHEMA: &str =
    include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_H: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GSA_REPORT_FORMAT_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/report-format.ts");
const GSA_REPORT_FORMATS_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/report-formats.ts");
const GSA_REPORT_FORMAT_CAPABILITIES: &str =
    include_str!("../../../components/gsa/src/gmp/capabilities/capabilities.ts");
const GSA_REPORT_FORMAT_TABLE: &str =
    include_str!("../../../components/gsa/src/web/pages/reportformats/Table.jsx");
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
fn dedicated_report_format_xml_transport_is_retired_without_losing_shared_semantics() {
    for source in [GSA_REPORT_FORMAT_COMMAND, GSA_REPORT_FORMATS_COMMAND] {
        for retired in [
            "extends EntityCommand",
            "extends EntitiesCommand",
            "getElementFromRoot",
            "getEntitiesResponse",
            "getAggregates",
            "cmd: 'get_report_format",
        ] {
            assert!(!source.contains(retired), "GSA still contains {retired}");
        }
        assert!(source.contains("extends HttpCommand"));
    }
    assert!(GSA_REPORT_FORMAT_CAPABILITIES.contains("'get_report_formats'"));

    for retired in [
        "get_report_format_gmp",
        "get_report_formats_gmp",
        "export_report_format_gmp",
        "export_report_formats_gmp",
        "ELSE (get_report_format)",
        "ELSE (get_report_formats)",
        "ELSE (export_report_format)",
        "ELSE (export_report_formats)",
    ] {
        assert!(!GSAD_GMP_C.contains(retired));
        assert!(!GSAD_GMP_H.contains(retired));
    }
    for retired in [
        "|(get_report_format)",
        "|(get_report_formats)",
        "|(export_report_format)",
        "|(export_report_formats)",
    ] {
        assert!(!GSAD_VALIDATOR.contains(retired));
    }

    for retired in [
        "get_report_formats_data",
        "CLIENT_GET_REPORT_FORMATS",
        "handle_get_report_formats",
    ] {
        assert!(!GVMD_GMP_C.contains(retired));
    }
    assert!(!GVMD_MANAGE_COMMANDS.contains("{\"GET_REPORT_FORMATS\""));
    assert!(GVMD_MANAGE_COMMANDS.contains("\"GET_REPORT_FORMATS\","));
    assert!(GVMD_MANAGE_COMMANDS.contains("\"GET_FILTERS\","));
    let native_acl = inherited_function(GVMD_MANAGE_COMMANDS, "valid_gmp_command");
    assert!(native_acl.contains("native_acl_operations"));
    assert!(!GVMD_GMP_SCHEMA.contains("<name>get_report_formats</name>"));
    assert!(GVMD_GMP_SCHEMA.contains("GET_REPORT_FORMATS, CREATE_REPORT_FORMAT"));

    let bulk_export = inherited_function(GSAD_GMP_C, "bulk_export_gmp");
    let rejection = bulk_export
        .find("g_ascii_strcasecmp (type, \"report_format\") == 0")
        .expect("generic gsad bulk export must reject report formats");
    let synthesis = bulk_export
        .find("export_many")
        .expect("generic gsad bulk export synthesis marker must remain");
    assert!(rejection < synthesis);
    for resource_type in ["filter", "port_list", "report_format", "tag", "vuln"] {
        assert!(
            bulk_export.contains(&format!(
                "g_ascii_strcasecmp (type, \"{resource_type}\") == 0"
            )),
            "case-insensitive XML bulk-export rejection missing for {resource_type}"
        );
    }

    for retained in [
        "init_report_format_iterator",
        "find_report_format_with_permission",
        "apply_report_format",
        "create_report_format_from_file",
    ] {
        assert!(
            MANAGE_REPORT_FORMATS_C.contains(retained)
                || MANAGE_SQL_REPORT_FORMATS_C.contains(retained),
            "shared report-format behavior was lost: {retained}"
        );
    }
    assert!(GVMD_GMP_C.contains("\"get_report_formats\""));
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
fn report_format_metadata_export_reuses_detail_loader() {
    let source = include_str!("report_formats.rs");
    let export_source = source
        .split_once("pub(crate) async fn export_report_format_metadata")
        .expect("report-format export wrapper must exist")
        .1;

    assert!(export_source.contains("report_format_asset_detail(state, path).await"));
    for inherited_workflow in [
        "export_report_format_gmp",
        "import_report_format",
        "verify_report_format",
        "delete_report_format",
    ] {
        assert!(
            !export_source.contains(inherited_workflow),
            "report-format metadata export must not call inherited workflow {inherited_workflow}"
        );
    }
}

#[test]
fn trusted_feed_report_format_import_mutates_db_files_signatures_and_events() {
    let import_file = inherited_function(MANAGE_REPORT_FORMATS_C, "create_report_format_from_file");
    for required in [
        "parse_xml_file (path, &report_format)",
        "parse_report_format_entity",
        "set_resource_id_deprecated (\"report_format\"",
        "create_report_format_no_acl",
        "log_event (\"report_format\", \"Report format\"",
        "log_event_fail (\"report_format\"",
    ] {
        assert!(
            import_file.contains(required),
            "inherited report-format file import missing {required}"
        );
    }

    let save_files = inherited_function(MANAGE_SQL_REPORT_FORMATS_C, "save_report_format_files");
    for required in [
        "GVMD_STATE_DIR",
        "\"report_formats\"",
        "current_credentials.uuid",
        "gvm_file_remove_recurse",
        "g_mkdir_with_parents",
        "path_is_in_directory",
        "g_base64_decode",
        "g_file_set_contents",
        "chmod (full_file_name",
    ] {
        assert!(
            save_files.contains(required),
            "report-format import file persistence missing {required}"
        );
    }

    let create_no_acl =
        inherited_function(MANAGE_SQL_REPORT_FORMATS_C, "create_report_format_no_acl");
    assert!(
        create_no_acl.contains("create_report_format_internal (0, /* Check permission. */"),
        "no-ACL report-format import wrapper must keep delegating to the shared create transaction"
    );

    let create_internal =
        inherited_function(MANAGE_SQL_REPORT_FORMATS_C, "create_report_format_internal");
    for required in [
        "SELECT COUNT(*) FROM report_formats WHERE uuid = '%s';",
        "SELECT COUNT(*) FROM report_formats_trash",
        "WHERE original_uuid = '%s';",
        "gvm_uuid_make",
        "\"signatures\", \"report_formats\"",
        "symlink (old, new)",
        "save_report_format_files",
        "INSERT INTO report_formats",
        "add_report_format_params",
        "current_credentials.uuid",
        "sql_commit ();",
    ] {
        assert!(
            create_internal.contains(required),
            "report-format create/import transaction missing {required}"
        );
    }

    let add_params = inherited_function(MANAGE_SQL_REPORT_FORMATS_C, "add_report_format_params");
    for required in [
        "report_format_param_type_from_name",
        "SELECT count(*) FROM report_format_params",
        "INSERT INTO report_format_params",
        "INSERT INTO report_format_param_options",
        "report_format_validate_param_value",
        "return 8",
        "return 9",
    ] {
        assert!(
            add_params.contains(required),
            "report-format param/options persistence missing {required}"
        );
    }

    for required_table in [
        "CREATE TABLE IF NOT EXISTS report_formats",
        "CREATE TABLE IF NOT EXISTS report_formats_trash",
        "CREATE TABLE IF NOT EXISTS report_format_params",
        "CREATE TABLE IF NOT EXISTS report_format_param_options",
    ] {
        assert!(
            MANAGE_PG_C.contains(required_table),
            "report-format schema missing {required_table}"
        );
    }
}

#[test]
fn trusted_report_format_execution_is_shell_free_and_fail_closed() {
    let runner = inherited_function(MANAGE_SQL_REPORT_FORMATS_C, "run_report_format_script");
    for required in [
        "execv (script, argv)",
        "dup2 (output_fd, STDOUT_FILENO)",
        r#"open ("/dev/null", O_WRONLY | O_CLOEXEC)"#,
        "cleanup_manage_process (FALSE)",
        "setgroups (0, NULL)",
        "waitpid (pid, &status, 0)",
    ] {
        assert!(
            runner.contains(required),
            "trusted report generator missing shell-free execution fragment: {required}"
        );
    }
    for forbidden in ["system (", "g_strdup_printf", "/bin/sh", "command ="] {
        assert!(
            !runner.contains(forbidden),
            "trusted report generator must not use shell command construction: {forbidden}"
        );
    }

    let apply = inherited_function(MANAGE_SQL_REPORT_FORMATS_C, "apply_report_format");
    for required in [
        "report_format_predefined (report_format) == 0",
        "report_format_trust (report_format) != TRUST_YES",
        "report_format_extension_is_safe",
        "output_file, output_fd",
        "unlink (output_file)",
    ] {
        assert!(
            apply.contains(required),
            "report-format application missing fail-closed fragment: {required}"
        );
    }
}

#[test]
fn custom_executable_report_format_mutation_surfaces_are_retired() {
    for (surface, source, forbidden) in [
        ("GSA command", GSA_REPORT_FORMAT_COMMAND, "async save("),
        ("GSA command", GSA_REPORT_FORMAT_COMMAND, "async import("),
        ("GSA command", GSA_REPORT_FORMAT_COMMAND, "EntityCommand"),
        (
            "GSA capabilities",
            GSA_REPORT_FORMAT_CAPABILITIES,
            "'delete_report_format'",
        ),
        (
            "GSA report-format table",
            GSA_REPORT_FORMAT_TABLE,
            "trash: true",
        ),
        (
            "GSA report-format table",
            GSA_REPORT_FORMAT_TABLE,
            "tags: true",
        ),
        ("gsad GMP bridge", GSAD_GMP_C, "delete_report_format_gmp"),
        ("gsad GMP bridge", GSAD_GMP_C, "import_report_format_gmp"),
        ("gsad GMP bridge", GSAD_GMP_C, "save_report_format_gmp"),
        (
            "gvmd GMP parser",
            GVMD_GMP_C,
            "strcasecmp (\"CREATE_REPORT_FORMAT\"",
        ),
        (
            "gvmd GMP parser",
            GVMD_GMP_C,
            "strcasecmp (\"DELETE_REPORT_FORMAT\"",
        ),
        (
            "gvmd GMP parser",
            GVMD_GMP_C,
            "strcasecmp (\"MODIFY_REPORT_FORMAT\"",
        ),
        (
            "gvmd GMP parser",
            GVMD_GMP_C,
            "strcasecmp (\"VERIFY_REPORT_FORMAT\"",
        ),
        (
            "GMP schema",
            GVMD_GMP_SCHEMA,
            "<name>create_report_format</name>",
        ),
        (
            "GMP schema",
            GVMD_GMP_SCHEMA,
            "<name>delete_report_format</name>",
        ),
        (
            "GMP schema",
            GVMD_GMP_SCHEMA,
            "<name>modify_report_format</name>",
        ),
        (
            "GMP schema",
            GVMD_GMP_SCHEMA,
            "<name>verify_report_format</name>",
        ),
    ] {
        assert!(
            !source.contains(forbidden),
            "retired custom report-format surface remains in {surface}: {forbidden}"
        );
    }
}

#[test]
fn report_format_reads_and_trusted_builtin_exports_remain_native() {
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/report-formats",
        false,
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        "/api/v1/report-formats/12345678-1234-1234-1234-123456789abc/export",
        false,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/report-formats/12345678-1234-1234-1234-123456789abc",
        false,
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/report-formats/12345678-1234-1234-1234-123456789abc",
        true,
    ));
    for path in [
        "/api/v1/report-formats",
        "/api/v1/report-formats/12345678-1234-1234-1234-123456789abc/import",
    ] {
        assert!(
            !direct_api_v1_method_is_allowed(&Method::POST, path, true),
            "native report-format import/write path must remain closed until its file/XML contract exists: {path}"
        );
    }

    let list_block = openapi_path_block("/report-formats");
    let detail_block = openapi_path_block("/report-formats/{report_format_id}");
    for forbidden in ["\n    post:", "\n    patch:", "\n    delete:"] {
        assert!(
            !list_block.contains(forbidden),
            "OpenAPI report-format list block unexpectedly exposes operation {forbidden}"
        );
    }
    for forbidden in ["\n    post:", "\n    patch:", "\n    delete:"] {
        assert!(
            !detail_block.contains(forbidden),
            "OpenAPI report-format detail block unexpectedly exposes operation {forbidden}"
        );
    }

    let export_block = openapi_path_block("/report-formats/{report_format_id}/export");
    for required in [
        "get:",
        "operationId: getReportFormatsByReportFormatIdExport",
        "x-yafvs-direct: true",
        "x-yafvs-exposure: direct-read",
        "x-yafvs-maturity: live-read",
        "x-yafvs-replaces: report-format-metadata-export-read",
        "$ref: '#/components/schemas/ReportFormatAsset'",
    ] {
        assert!(
            export_block.contains(required),
            "OpenAPI report-format export block missing {required}"
        );
    }
    for forbidden in [
        "x-yafvs-exposure: direct-write",
        "x-yafvs-safety-contract: write-control-v1",
        "\n    post:",
        "\n    patch:",
        "\n    delete:",
    ] {
        assert!(
            !export_block.contains(forbidden),
            "OpenAPI report-format export block must not expose write/file semantics: {forbidden}"
        );
    }
}
