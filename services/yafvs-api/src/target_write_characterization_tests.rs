// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const GSA_ENTITY_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/entity.ts");
const GSA_TARGET_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/target.ts");
const GSA_TARGETS_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/targets.ts");
const GSA_GMP: &str = include_str!("../../../components/gsa/src/gmp/gmp.ts");
const GSA_NATIVE_TARGETS: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/targets.ts");
const GSA_ENTITIES_CONTAINER: &str =
    include_str!("../../../components/gsa/src/web/entities/EntitiesContainer.tsx");
const GSA_REPORT_DETAILS: &str =
    include_str!("../../../components/gsa/src/web/pages/reports/DetailsPage.tsx");
const GSA_TARGET_LIST_PAGE: &str =
    include_str!("../../../components/gsa/src/web/pages/targets/TargetListPage.tsx");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_H: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVM_LIBS_GMP_C: &str = include_str!("../../../components/gvm-libs/gmp/gmp.c");
const GVM_LIBS_GMP_H: &str = include_str!("../../../components/gvm-libs/gmp/gmp.h");
const MANAGE_PG_C: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_TARGETS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_targets.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const MANAGE_COMMANDS_C: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const MANAGE_OPENVAS_C: &str = include_str!("../../../components/gvmd/src/manage_openvas.c");
const MANAGE_OPENVASD_C: &str = include_str!("../../../components/gvmd/src/manage_openvasd.c");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const TARGET_HANDLERS: &str = include_str!("target_handlers.rs");
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

    for retained in ["ELSE (create_target)", "ELSE (save_target)"] {
        assert!(GSAD_GMP_C.contains(retained));
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
fn inherited_target_create_and_modify_are_host_port_credential_and_in_use_guarded() {
    let create = inherited_function(MANAGE_SQL_TARGETS_C, "create_target");
    for required in [
        "validate_port_range (port_range)",
        "validate_port (ssh_port)",
        "alive_test_from_array (alive_tests)",
        "alive_test_from_string (alive_test_str)",
        "acl_user_may (\"create_target\") == 0",
        "resource_with_name_exists (name, \"target\", 0)",
        "find_port_list_with_permission (port_list_id, &port_list",
        "create_port_list_unique (name, port_list_comment, port_range",
        "clean_hosts (chosen_hosts, &max)",
        "manage_count_hosts (clean, clean_exclude)",
        "manage_max_hosts ()",
        "INSERT INTO targets",
        "INSERT INTO targets_login_data",
        "credential_type (ssh_credential)",
        "credential_type (ssh_elevate_credential)",
        "credential_type (smb_credential)",
        "credential_type (esxi_credential)",
        "credential_type (snmp_credential)",
        "credential_type (krb5_credential)",
        "sql_commit ();",
    ] {
        assert!(
            create.contains(required),
            "create_target missing {required}"
        );
    }

    let modify = inherited_function(MANAGE_SQL_TARGETS_C, "modify_target");
    for required in [
        "acl_user_may (\"modify_target\") == 0",
        "find_target_with_permission (target_id, &target, \"modify_target\")",
        "resource_with_name_exists (name, \"target\", target)",
        "target_in_use (target)",
        "find_port_list_with_permission (port_list_id, &port_list",
        "find_credential_with_permission (ssh_credential_id",
        "find_credential_with_permission (ssh_elevate_credential_id",
        "find_credential_with_permission (smb_credential_id",
        "find_credential_with_permission (esxi_credential_id",
        "find_credential_with_permission (snmp_credential_id",
        "find_credential_with_permission (krb5_credential_id",
        "set_target_login_data (target, \"ssh\"",
        "set_target_login_data (target, \"elevate\"",
        "set_target_login_data (target, \"smb\"",
        "set_target_login_data (target, \"esxi\"",
        "set_target_login_data (target, \"snmp\"",
        "set_target_login_data (target, \"krb5\"",
        "clean_hosts (hosts, &max)",
        "manage_count_hosts (clean, clean_exclude)",
        "sql_commit ();",
    ] {
        assert!(
            modify.contains(required),
            "modify_target missing {required}"
        );
    }
}

#[test]
fn inherited_target_alive_test_modify_is_not_task_in_use_guarded() {
    let modify = inherited_function(MANAGE_SQL_TARGETS_C, "modify_target");
    let alive_start = modify
        .find("if (alive_tests && alive_tests->len")
        .expect("alive-tests modify block exists");
    let port_list_start = modify
        .find("if (port_list_id)")
        .expect("port-list modify block exists");
    let alive_block = &modify[alive_start..port_list_start];
    assert!(alive_block.contains("alive_test_from_array (alive_tests)"));
    assert!(alive_block.contains("alive_test_from_string (alive_test_str)"));
    assert!(alive_block.contains("alive_test = '%i'"));
    assert!(
        !alive_block.contains("target_in_use (target)"),
        "inherited alive-test modification is not guarded by target_in_use"
    );

    let allow_start = modify
        .find("if (allow_simultaneous_ips)")
        .expect("allow-simultaneous modify block exists");
    let allow_block = &modify[allow_start..alive_start];
    assert!(allow_block.contains("target_in_use (target)"));

    let reverse_only_start = modify
        .find("if (reverse_lookup_only)")
        .expect("reverse-lookup-only modify block exists");
    let reverse_unify_start = modify
        .find("if (reverse_lookup_unify)")
        .expect("reverse-lookup-unify modify block exists");
    let commit_start = modify[reverse_unify_start..]
        .find("sql_commit ();")
        .map(|offset| reverse_unify_start + offset)
        .expect("modify_target commit follows reverse lookup blocks");
    let reverse_only_block = &modify[reverse_only_start..reverse_unify_start];
    let reverse_unify_block = &modify[reverse_unify_start..commit_start];
    assert!(reverse_only_block.contains("target_in_use (target)"));
    assert!(reverse_only_block.contains("reverse_lookup_only = '%i'"));
    assert!(reverse_unify_block.contains("target_in_use (target)"));
    assert!(reverse_unify_block.contains("reverse_lookup_unify = '%i'"));

    assert!(modify[port_list_start..].contains("target_in_use (target)"));

    let exclude_start = modify
        .find("if (exclude_hosts)")
        .expect("host/exclude-host modify block exists");
    let reverse_only_start = modify
        .find("if (reverse_lookup_only)")
        .expect("reverse-lookup-only modify block exists");
    let host_block = &modify[exclude_start..reverse_only_start];
    assert!(host_block.contains("target_in_use (target)"));
    assert!(host_block.contains("clean_hosts (hosts, &max)"));
    assert!(host_block.contains("clean_hosts (exclude_hosts, NULL)"));
    assert!(host_block.contains("manage_count_hosts (clean, clean_exclude)"));
    assert!(host_block.contains("hosts = '%s'"));
    assert!(host_block.contains("exclude_hosts = '%s'"));
}

#[test]
fn inherited_target_clone_delete_and_restore_preserve_login_data_and_task_links() {
    let copy = inherited_function(MANAGE_SQL_TARGETS_C, "copy_target");
    for required in [
        "copy_resource (\"target\", name, comment, target_id",
        "hosts, exclude_hosts, port_list, reverse_lookup_only,",
        "allow_simultaneous_ips",
        "INSERT INTO targets_login_data",
        "(target, type, credential, port, host_key_pins)",
        "FROM targets_login_data",
    ] {
        assert!(copy.contains(required), "copy_target missing {required}");
    }

    let delete = inherited_function(MANAGE_SQL_TARGETS_C, "delete_target");
    for required in [
        "acl_user_may (\"delete_target\") == 0",
        "find_target_with_permission (target_id, &target, \"delete_target\")",
        "find_trash (\"target\", target_id, &target)",
        "SELECT count(*) FROM tasks",
        "target_location = ",
        "INSERT INTO targets_trash",
        "INSERT INTO targets_trash_login_data",
        "credential_location",
        "UPDATE tasks",
        "permissions_set_locations (\"target\"",
        "tags_set_locations (\"target\"",
        "permissions_set_orphans (\"target\"",
        "tags_remove_resource (\"target\"",
        "DELETE FROM targets_login_data WHERE target = %llu;",
        "DELETE FROM targets WHERE id = %llu;",
    ] {
        assert!(
            delete.contains(required),
            "delete_target missing {required}"
        );
    }

    for required in [
        "INSERT INTO targets",
        "FROM targets_trash WHERE id = %llu;",
        "INSERT INTO targets_login_data",
        "FROM targets_trash_login_data WHERE target = %llu;",
        "DELETE FROM targets_trash_login_data",
        "UPDATE tasks",
        "target_location = ",
        "permissions_set_locations (\"target\"",
        "tags_set_locations (\"target\"",
        "DELETE FROM targets_trash WHERE id = %llu;",
    ] {
        assert!(
            MANAGE_SQL_TARGETS_C.contains(required),
            "target restore path missing {required}"
        );
    }

    for required in [
        "target INTEGER REFERENCES targets (id) ON DELETE RESTRICT",
        "credential INTEGER REFERENCES credentials (id) ON DELETE RESTRICT",
        "target INTEGER REFERENCES targets_trash (id) ON DELETE RESTRICT",
        "credential_location INTEGER",
    ] {
        assert!(
            MANAGE_PG_C.contains(required),
            "target schema missing {required}"
        );
    }
}

#[test]
fn target_delete_is_native_only_while_raw_gmp_and_create_save_bridges_remain() {
    for required in [
        "copy_target (create_target_data->name,",
        "create_target_data->copy",
        "find_credential_with_permission",
        "Targets cannot have both an SMB and",
        "else switch (create_target",
        "create_target_data->name,",
        "XML_OK_CREATED_ID (\"create_target\")",
    ] {
        assert!(
            GMP_C.contains(required),
            "GMP target parser missing {required}"
        );
    }

    let create_gsad = inherited_function(GSAD_GMP_C, "create_target_gmp");
    for required in [
        "CHECK_VARIABLE_INVALID (name, \"Create Target\")",
        "CHECK_VARIABLE_INVALID (target_source, \"Create Target\")",
        "<create_target>",
        "<ssh_credential id=\\\"%s\\\">",
        "<ssh_elevate_credential id=\\\"%s\\\"/>",
        "<smb_credential id=\\\"%s\\\"/>",
        "<esxi_credential id=\\\"%s\\\"/>",
        "<snmp_credential id=\\\"%s\\\"/>",
        "<krb5_credential id=\\\"%s\\\"/>",
        "<asset_hosts",
    ] {
        assert!(
            create_gsad.contains(required),
            "create_target_gmp missing {required}"
        );
    }

    let save_gsad = inherited_function(GSAD_GMP_C, "save_target_gmp");
    for required in [
        "<modify_target target_id=\\\"%s\\\">",
        "<ssh_credential id=\\\"%s\\\">",
        "<alive_tests>",
    ] {
        assert!(
            save_gsad.contains(required),
            "save_target_gmp missing {required}"
        );
    }

    for retained in ["create_target_gmp", "save_target_gmp"] {
        assert!(GSAD_GMP_C.contains(retained));
        assert!(GSAD_GMP_H.contains(retained));
    }
    for retained in ["create_target", "save_target"] {
        assert!(GSAD_GMP_C.contains(&format!("ELSE ({retained})")));
        assert!(GSAD_VALIDATOR.contains(&format!("|({retained})")));
    }

    for required in [
        "cmd: 'create_target'",
        "cmd: 'save_target'",
        "hostAssetIds",
        "ssh_credential_id: sshCredentialId",
        "ssh_elevate_credential_id:",
        "smb_credential_id: smbCredentialId",
        "snmp_credential_id: snmpCredentialId",
        "krb5_credential_id: krb5CredentialId",
    ] {
        assert!(
            GSA_TARGET_COMMAND.contains(required),
            "GSA target command missing {required}"
        );
    }
    assert!(!GSA_TARGET_COMMAND.contains("hosts_filter"));
    assert!(!GSA_ENTITY_COMMAND.contains("async clone("));
    assert!(GSA_TARGET_COMMAND.contains("const requireNativeTargetApi"));
    assert!(GSA_TARGET_COMMAND.contains("requireNativeTargetApi(this.http)"));
    assert!(GSA_TARGET_COMMAND.contains("cloneNativeTarget(this.http, id)"));
    assert!(!GSA_TARGET_COMMAND.contains("super.clone({id})"));

    assert!(GSA_TARGET_LIST_PAGE.contains("withEntitiesContainer<Target>('target'"));
    assert!(GSA_ENTITIES_CONTAINER.contains("const entitiesCommandName = pluralizeType(gmpName)"));
    assert!(GSA_ENTITIES_CONTAINER.contains("this.entitiesCommand = gmp[entitiesCommandName]"));
    for live_collection_delete in [
        "entitiesCommand.delete(Array.from(selected as Set<TModel>))",
        "entitiesCommand.deleteByFilter(loadedFilter as Filter)",
        "entitiesCommand.deleteByFilter((loadedFilter as Filter).all())",
    ] {
        assert!(
            GSA_ENTITIES_CONTAINER.contains(live_collection_delete),
            "live target collection path missing {live_collection_delete}"
        );
    }
    assert!(GSA_GMP.contains("public readonly targets: TargetsCommand"));
    assert!(GSA_GMP.contains("this.targets = new TargetsCommand(this.http)"));

    let delete_targets = GSA_TARGETS_COMMAND
        .split_once("  async delete(targets: Target[])")
        .expect("TargetsCommand delete method must exist")
        .1
        .split_once("  async deleteByIds(ids: string[])")
        .expect("TargetsCommand delete method must end before deleteByIds")
        .0;
    let delete_target_ids = GSA_TARGETS_COMMAND
        .split_once("  async deleteByIds(ids: string[])")
        .expect("TargetsCommand deleteByIds method must exist")
        .1
        .split_once("  async deleteByFilter(filter: Filter)")
        .expect("TargetsCommand deleteByIds method must end before deleteByFilter")
        .0;
    let delete_targets_by_filter = GSA_TARGETS_COMMAND
        .split_once("  async deleteByFilter(filter: Filter)")
        .expect("TargetsCommand deleteByFilter method must exist")
        .1
        .split_once("  private async deleteIds")
        .expect("TargetsCommand deleteByFilter method must end before deleteIds")
        .0;
    for (name, method) in [
        ("delete", delete_targets),
        ("deleteByIds", delete_target_ids),
        ("deleteByFilter", delete_targets_by_filter),
    ] {
        assert!(method.contains("requireNativeTargetApi(this.http)"));
        assert!(method.contains("this.deleteIds("));
        assert!(
            !method.contains("super."),
            "TargetsCommand {name} calls super"
        );
    }
    assert_eq!(
        delete_targets_by_filter
            .matches("await this.traverseAllFilteredTargets(query)")
            .count(),
        2,
        "all-filter deletion must complete two preflight traversals"
    );
    for stabilization_contract in [
        "pageSize: NATIVE_COMMAND_PAGE_SIZE",
        "firstIds.some((id, index) => id !== ids[index])",
        "preflight stabilization detected candidate-set drift",
        "const ids = targetIds(targets)",
    ] {
        assert!(
            delete_targets_by_filter.contains(stabilization_contract),
            "target delete stabilization missing {stabilization_contract}"
        );
    }
    assert!(GSA_TARGETS_COMMAND.contains("deleteNativeTarget(this.http, id)"));
    assert!(!GSA_TARGETS_COMMAND.contains("bulk_delete"));
    assert!(!GSA_TARGETS_COMMAND.contains("super.delete"));

    let delete_gsa = GSA_TARGET_COMMAND
        .split_once("async delete({id}: EntityCommandParams)")
        .expect("GSA target delete method must exist")
        .1
        .split_once("  async create")
        .expect("GSA target delete method must end before create")
        .0;
    assert!(delete_gsa.contains("requireNativeTargetApi(this.http)"));
    assert!(delete_gsa.contains("deleteNativeTarget(this.http, id)"));
    let id_guard = delete_gsa
        .find("typeof id !== 'string' || id.trim().length === 0")
        .expect("single target delete must guard the runtime ID");
    assert!(
        id_guard
            < delete_gsa
                .find("deleteNativeTarget(this.http, id)")
                .unwrap(),
        "single target delete must guard the ID before native deletion"
    );
    assert!(!delete_gsa.contains("super.delete"));

    assert!(!GSAD_GMP_C.contains("delete_target_gmp"));
    assert!(!GSAD_GMP_H.contains("delete_target_gmp"));
    assert!(!GSAD_GMP_C.contains("ELSE (delete_target)"));
    assert!(!GSAD_VALIDATOR.contains("|(delete_target)"));

    for retained in [
        "delete_target_data_t",
        "strcasecmp (\"DELETE_TARGET\", element_name)",
        "delete_target_data->ultimate",
        "CLIENT_DELETE_TARGET",
    ] {
        assert!(
            GMP_C.contains(retained),
            "raw gvmd parser missing {retained}"
        );
    }
    assert!(GMP_SCHEMA.contains("<name>delete_target</name>"));
    let delete_manager = inherited_function(MANAGE_SQL_TARGETS_C, "delete_target");
    assert!(delete_manager.contains("acl_user_may (\"delete_target\") == 0"));
    assert!(delete_manager.contains("find_target_with_permission"));
    assert!(delete_manager.contains("INSERT INTO targets_trash"));
    assert!(delete_manager.contains("DELETE FROM targets WHERE id = %llu;"));
    assert!(GVM_LIBS_GMP_C.contains("gmp_delete_target_ext ("));
    assert!(GVM_LIBS_GMP_C.contains("<delete_target target_id=\\\"%s\\\" ultimate=\\\"%d\\\"/>"));
    assert!(GVM_LIBS_GMP_H.contains("gmp_delete_target_ext ("));
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
