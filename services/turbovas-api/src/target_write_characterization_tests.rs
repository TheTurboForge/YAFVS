// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const GSA_ENTITY_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/entity.ts");
const GSA_TARGET_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/target.ts");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const MANAGE_PG_C: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_SQL_TARGETS_C: &str =
    include_str!("../../../components/gvmd/src/manage_sql_targets.c");
const GMP_C: &str = include_str!("../../../components/gvmd/src/gmp.c");
const PYTHON_GVM_TARGETS: &str =
    include_str!("../../../components/python-gvm/gvm/protocols/gmp/requests/v224/_targets.py");
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
        "INSERT INTO targets_login_data (target, type, credential, port)",
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
fn inherited_target_gmp_gsad_gsa_and_python_surfaces_still_carry_broad_control() {
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

    for required in [
        "return move_resource_to_trash (connection, \"target\"",
        "<modify_target target_id=\\\"%s\\\">",
        "<ssh_credential id=\\\"%s\\\">",
        "<alive_tests>",
        "ELSE (create_target)",
        "ELSE (delete_target)",
        "ELSE (save_target)",
    ] {
        assert!(
            GSAD_GMP_C.contains(required),
            "gsad target surface missing {required}"
        );
    }

    for required in [
        "cmd: 'create_target'",
        "cmd: 'save_target'",
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
    for required in [
        "def create_target(",
        "def modify_target(",
        "def clone_target(cls, target_id: EntityID)",
        "def delete_target(",
        "XmlCommand(\"create_target\")",
        "XmlCommand(\"modify_target\")",
        "XmlCommand(\"delete_target\")",
        "cmd.add_element(\"copy\", str(target_id))",
    ] {
        assert!(
            PYTHON_GVM_TARGETS.contains(required),
            "python-gvm target request surface missing {required}"
        );
    }
    for required in [
        "const response = await this.entityAction(",
        "cmd: 'clone'",
        "resource_type: this.name",
        "cmd: 'delete_' + this.name",
    ] {
        assert!(
            GSA_ENTITY_COMMAND.contains(required),
            "generic GSA target entity surface missing {required}"
        );
    }
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
            "x-turbovas-inherited-still-owns: target-export-and-credential-secret-mutation"
        ));
    }
    let export = openapi_path_block("/targets/{target_id}/export");
    for required in [
        "get:",
        "operationId: getTargetsByTargetIdExport",
        "x-turbovas-direct: true",
        "x-turbovas-exposure: direct-read",
        "x-turbovas-maturity: live-read",
        "x-turbovas-replaces: target-metadata-export-read",
        "x-turbovas-inherited-still-owns: target-export-and-credential-secret-mutation",
        "$ref: '#/components/schemas/Target'",
        "Credential references include id/name/type/port only",
        "inherited file-export formats remain outside this read endpoint",
    ] {
        assert!(
            export.contains(required),
            "target metadata export OpenAPI block missing {required}"
        );
    }
    for forbidden in [
        "x-turbovas-exposure: direct-write",
        "x-turbovas-safety-contract: write-control-v1",
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
        "x-turbovas-replaces: target-metadata-simple-scan-inputs-and-credential-links-modify"
    ));
    assert!(detail.contains("x-turbovas-replaces: target-trash-move"));
    for forbidden in ["post:", "/clone", "/restore", "/trash"] {
        assert!(
            !detail.contains(forbidden),
            "target detail OpenAPI must not expose broad mutation {forbidden}"
        );
    }
}
