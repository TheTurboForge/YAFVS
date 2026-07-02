// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;

use crate::direct_api::{direct_api_v1_method_is_allowed, direct_api_v1_path_is_allowed};

const GSA_CREDENTIAL_COMMAND: &str =
    include_str!("../../../components/gsa/src/gmp/commands/credential.ts");
const GSA_ENTITY_COMMAND: &str = include_str!("../../../components/gsa/src/gmp/commands/entity.ts");
const GSAD_GMP_C: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const MANAGE_SQL_C: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
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
fn inherited_credential_create_is_acl_guarded_secret_bearing_and_store_aware() {
    let create = inherited_function(MANAGE_SQL_C, "create_credential");
    for required in [
        "acl_user_may (\"create_credential\") == 0",
        "resource_with_name_exists (name, \"credential\", 0)",
        "validate_credential_username (login) == 0",
        "feature_enabled (FEATURE_ID_CREDENTIAL_STORES)",
        "find_credential_store_no_acl (credential_store_id, &store)",
        "\"credential_store_id\", credential_store_id",
        "\"credential_store_id\", get_default_credential_store_id ())",
        "\"vault_id\", vault_id",
        "\"host_identifier\", host_identifier",
        "\"privacy_host_identifier\", privacy_host_identifier",
        "lsc_crypt_encrypt (crypt_ctx,",
        "\"password\", given_password",
        "\"private_key\", key_private",
        "\"community\", community",
        "\"privacy_password\"",
        "set_credential_data (new_credential, \"secret\", secret)",
        "disable_encrypted_credentials",
        "lsc_user_keys_create (generated_password, &generated_private_key)",
        "sql_commit ();",
    ] {
        assert!(
            create.contains(required),
            "create_credential missing {required}"
        );
    }

    let create_gsad = inherited_function(GSAD_GMP_C, "create_credential_gmp");
    for required in [
        "CHECK_VARIABLE_INVALID (name, \"Create Credential\")",
        "CHECK_LOGIN_NAME_INVALID_CREATE",
        "<create_credential>",
        "<password>%s</password>",
        "<key>",
        "<private>%s</private>",
        "<certificate>%s</certificate>",
        "<community>%s</community>",
        "<credential_store_id>%s</credential_store_id>",
        "<vault_id>%s</vault_id>",
        "<host_identifier>%s</host_identifier>",
        "<privacy_host_identifier>%s</privacy_host_identifier>",
        "<allow_insecure>1</allow_insecure>",
    ] {
        assert!(
            create_gsad.contains(required),
            "create_credential_gmp missing {required}"
        );
    }
}

#[test]
fn inherited_credential_modify_and_copy_preserve_secret_and_rbac_semantics() {
    let modify = inherited_function(MANAGE_SQL_C, "modify_credential");
    for required in [
        "acl_user_may (\"modify_credential\") == 0",
        "find_credential_with_permission (credential_id, &credential,\n                                       \"modify_credential\")",
        "resource_with_name_exists (name, \"credential\", credential)",
        "return 17",
        "validate_credential_username (login) == 0",
        "truncate_certificate (certificate)",
        "gvm_ssh_public_from_private (",
        "set_credential_password (credential, password)",
        "set_credential_private_key (",
        "set_credential_snmp_secret",
        "\"credential_store_id\",\n                                   credential_store_id",
        "\"vault_id\",\n                                   vault_id",
        "\"host_identifier\",\n                                   host_identifier",
        "\"privacy_host_identifier\",\n                                    NULL",
        "\"privacy_host_identifier\",\n                                    privacy_host_identifier",
        "sql_commit ();",
    ] {
        assert!(
            modify.contains(required),
            "modify_credential missing {required}"
        );
    }

    let copy = inherited_function(MANAGE_SQL_C, "copy_credential");
    for required in [
        "copy_resource (\"credential\", name, comment, credential_id",
        "INSERT INTO credentials_data (credential, type, value)",
        "SELECT %llu, type, value FROM credentials_data",
    ] {
        assert!(
            copy.contains(required),
            "copy_credential missing {required}"
        );
    }

    let save_gsad = inherited_function(GSAD_GMP_C, "save_credential_gmp");
    for required in [
        "CHECK_VARIABLE_INVALID (credential_id, \"Save Credential\")",
        "<modify_credential credential_id=\\\"%s\\\">\"",
        "<allow_insecure>1</allow_insecure>",
        "<password>%s</password>",
        "<key>",
        "<private>%s</private>",
        "<certificate>%s</certificate>",
        "<community>%s</community>",
        "<credential_store_id>%s</credential_store_id>",
        "<vault_id>%s</vault_id>",
        "<host_identifier>%s</host_identifier>",
        "</modify_credential>",
    ] {
        assert!(
            save_gsad.contains(required),
            "save_credential_gmp missing {required}"
        );
    }
}

#[test]
fn inherited_credential_delete_restore_export_and_download_touch_secret_payloads_and_references() {
    let delete = inherited_function(MANAGE_SQL_C, "delete_credential");
    for required in [
        "acl_user_may (\"delete_credential\") == 0",
        "find_credential_with_permission (credential_id, &credential,\n                                       \"delete_credential\")",
        "find_trash (\"credential\", credential_id, &credential)",
        "trash_credential_in_use (credential)",
        "credential_in_use (credential)",
        "INSERT INTO credentials_trash",
        "INSERT INTO credentials_trash_data",
        "FROM credentials_data",
        "UPDATE targets_trash_login_data",
        "UPDATE scanners_trash",
        "permissions_set_locations (\"credential\"",
        "tags_set_locations (\"credential\"",
        "DELETE FROM credentials_data WHERE credential = %llu;",
        "DELETE FROM credentials WHERE id = %llu;",
    ] {
        assert!(
            delete.contains(required),
            "delete_credential missing {required}"
        );
    }

    for required in [
        "INSERT INTO credentials\"\n           \" (uuid, owner, name, comment, creation_time,",
        "INSERT INTO credentials_data",
        "FROM credentials_trash_data",
        "UPDATE targets_trash_login_data",
        "UPDATE scanners_trash",
        "DELETE FROM credentials_trash_data WHERE credential = %llu;",
        "DELETE FROM credentials_trash WHERE id = %llu;",
    ] {
        assert!(
            MANAGE_SQL_C.contains(required),
            "credential restore path missing {required}"
        );
    }

    let download = inherited_function(GSAD_GMP_C, "download_credential_gmp");
    for required in [
        "<get_credentials",
        "\" format=\\\"%s\\\"/>\"",
        "g_base64_decode (package_encoded, &len)",
        "entity_child (credential_entity, \"certificate\")",
        "entity_child (credential_entity, \"public_key\")",
        "attachment; filename=credential-%s.%s",
    ] {
        assert!(
            download.contains(required),
            "download_credential_gmp missing {required}"
        );
    }

    for required in [
        "return move_resource_to_trash (connection, \"credential\"",
        "return export_resource (connection, \"credential\"",
        "return export_many (connection, \"credential\"",
        "ELSE (download_credential)",
        "ELSE (export_credential)",
        "ELSE (export_credentials)",
        "ELSE (clone)",
        "ELSE (delete_credential)",
    ] {
        assert!(
            GSAD_GMP_C.contains(required),
            "gsad credential control/export surface missing {required}"
        );
    }
}

#[test]
fn gsa_credential_command_still_carries_inherited_secret_write_download_surface() {
    for required in [
        "cmd: 'create_credential'",
        "cmd: 'save_credential'",
        "cmd: 'download_credential'",
        "credential_login: credentialLogin",
        "lsc_password: password",
        "passphrase",
        "private_key: saveFile(privateKey)",
        "public_key: saveFile(publicKey)",
        "vault_id",
        "host_identifier",
        "privacy_host_identifier",
        "httpRequestWithRejectionTransform<ArrayBuffer>",
        "responseType: 'arraybuffer'",
    ] {
        assert!(
            GSA_CREDENTIAL_COMMAND.contains(required),
            "GSA credential command missing {required}"
        );
    }

    for required in [
        "cmd: 'clone'",
        "resource_type: this.name",
        "cmd: 'delete_' + this.name",
        "cmd: 'bulk_export'",
    ] {
        assert!(
            GSA_ENTITY_COMMAND.contains(required),
            "generic GSA entity command missing inherited credential {required} surface"
        );
    }
}

#[test]
fn native_credential_secret_transfer_and_broad_mutation_routes_remain_closed() {
    for path in [
        "/api/v1/credentials",
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc",
    ] {
        assert!(
            direct_api_v1_path_is_allowed(path),
            "credential read path must remain direct allowlisted: {path}"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "credential read path must allow GET without write control: {path}"
        );
        for method in [Method::POST, Method::PUT, Method::DELETE] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "credential native mutation must remain closed for {method} {path}"
            );
        }
        if path.ends_with("123456789abc") {
            assert!(
                direct_api_v1_method_is_allowed(&Method::PATCH, path, true),
                "credential detail PATCH is now limited direct metadata write-control"
            );
        }
    }

    for path in [
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/download",
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/clone",
        "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/restore",
    ] {
        assert!(
            !direct_api_v1_path_is_allowed(path),
            "credential secret/control path must not be direct allowlisted: {path}"
        );
        assert!(
            !direct_api_v1_method_is_allowed(&Method::GET, path, true),
            "credential secret/control path must not be reachable: {path}"
        );
    }

    let export_path = "/api/v1/credentials/12345678-1234-1234-1234-123456789abc/export";
    assert!(
        direct_api_v1_path_is_allowed(export_path),
        "redacted credential metadata export is scriptable native JSON"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::GET, export_path, false),
        "credential metadata export must allow GET without write-control"
    );
    assert!(
        direct_api_v1_method_is_allowed(&Method::GET, export_path, true),
        "credential metadata export must remain GET-able with write-control enabled"
    );
    for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
        assert!(
            !direct_api_v1_method_is_allowed(&method, export_path, true),
            "{method} credential metadata export must stay closed; secret export/download semantics remain inherited"
        );
    }

    for (path, replaces) in [
        ("/credentials", "credential-redacted-metadata-list-read"),
        (
            "/credentials/{credential_id}",
            "credential-redacted-metadata-detail-read",
        ),
        (
            "/credentials/{credential_id}/export",
            "credential-redacted-metadata-export-read",
        ),
    ] {
        let block = openapi_path_block(path);
        for required in [
            "x-turbovas-exposure: direct-read",
            replaces,
            "credential-secrets-writes-and-deletes",
            "credential secrets",
            "credential-store secret selectors",
        ] {
            assert!(block.contains(required), "{path} missing {required}");
        }
        if path == "/credentials/{credential_id}/export" {
            assert!(
                block.contains("inherited secret export semantics"),
                "{path} must distinguish redacted metadata export from inherited secret export"
            );
        } else {
            assert!(
                block.contains("export/download behavior"),
                "{path} must leave inherited export/download behavior out of native reads"
            );
        }
        for forbidden in ["    post:", "    put:", "    delete:"] {
            assert!(
                !block.contains(forbidden),
                "{path} must not declare credential mutation method {forbidden}"
            );
        }
        if path == "/credentials/{credential_id}" {
            assert!(block.contains("    patch:"));
            for forbidden in [
                "credential_store_id:",
                "vault_id:",
                "host_identifier:",
                "password:",
                "private_key:",
                "community:",
                "credential_type:",
            ] {
                assert!(
                    !block.contains(forbidden),
                    "credential patch OpenAPI must not expose secret/control field {forbidden}"
                );
            }
        } else {
            assert!(!block.contains("    patch:"));
        }
    }
}
