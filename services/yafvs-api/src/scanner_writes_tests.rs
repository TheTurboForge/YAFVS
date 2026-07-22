// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    errors::ApiError,
    scanner_write_db::{
        ScannerWriteState, ensure_scanner_clone_source_allowed,
        ensure_scanner_live_task_count_allows_replace, ensure_scanner_metadata_patch_allowed,
    },
    scanner_write_sql::*,
    scanner_write_validation::{
        MAX_SCANNER_CA_PUB_BYTES, MAX_SCANNER_TEXT_BYTES, ScannerCloneRequest,
        ScannerConfigurationRequest, ScannerPatchRequest, validate_scanner_clone_request,
        validate_scanner_configuration_request, validate_scanner_patch_request,
    },
};
use yafvs_domain::ScannerType;

const CREDENTIAL_ID: &str = "12345678-1234-1234-1234-123456789abc";
const CERTIFICATE_SHAPED_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nMAgwADAAAwIAAA==\n-----END CERTIFICATE-----";

fn patch_request(name: Option<&str>, comment: Option<&str>) -> ScannerPatchRequest {
    ScannerPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn clone_request(name: Option<&str>, comment: Option<&str>) -> ScannerCloneRequest {
    ScannerCloneRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

fn configuration_request(host: &str, port: i64) -> ScannerConfigurationRequest {
    ScannerConfigurationRequest {
        name: " scanner ".to_string(),
        comment: " comment ".to_string(),
        host: host.to_string(),
        port,
        scanner_type: i64::from(ScannerType::Openvas.database_value()),
        ca_pub: Some(CERTIFICATE_SHAPED_PEM.to_string()),
        credential_id: Some(CREDENTIAL_ID.to_string()),
    }
}

#[test]
fn scanner_clone_request_accepts_defaults_and_bounded_metadata_overrides() {
    let default = validate_scanner_clone_request(clone_request(None, None))
        .expect("default scanner clone request");
    assert_eq!(default.name, None);
    assert_eq!(default.comment, None);

    let named =
        validate_scanner_clone_request(clone_request(Some("  Scanner copy  "), Some("  copied  ")))
            .expect("scanner clone metadata overrides");
    assert_eq!(named.name.as_deref(), Some("Scanner copy"));
    assert_eq!(named.comment.as_deref(), Some("copied"));
    assert!(matches!(
        validate_scanner_clone_request(clone_request(Some("  "), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(
        serde_json::from_value::<ScannerCloneRequest>(serde_json::json!({"host": "bad"})).is_err()
    );
}

#[test]
fn scanner_configuration_validates_network_and_unix_socket_shapes() {
    for host in ["127.0.0.1", "2001:db8::1", "scanner.example.test"] {
        let validated = validate_scanner_configuration_request(configuration_request(host, 9390))
            .expect("network scanner configuration");
        assert_eq!(validated.name, "scanner");
        assert_eq!(validated.comment, "comment");
        assert_eq!(validated.port, 9390);
        assert_eq!(
            validated.scanner_type,
            ScannerType::Openvas.database_value()
        );
        assert_eq!(validated.ca_pub.as_deref(), Some(CERTIFICATE_SHAPED_PEM));
        assert_eq!(validated.credential_id.as_deref(), Some(CREDENTIAL_ID));
        assert!(!validated.unix_socket);
    }

    let unix = validate_scanner_configuration_request(configuration_request(
        "/run/ospd/ospd-openvas.sock",
        0,
    ))
    .expect("Unix socket scanner configuration");
    assert!(unix.unix_socket);
    assert_eq!(unix.port, 0);
    assert_eq!(unix.ca_pub, None);
    assert_eq!(unix.credential_id, None);
}

#[test]
fn scanner_clone_allows_default_or_human_owned_but_rejects_cve_and_ownerless_custom() {
    for state in [
        ScannerWriteState {
            internal_id: 1,
            uuid: "08b69003-5fc2-4037-a479-93b440211c73".to_string(),
            owner_id: None,
        },
        ScannerWriteState {
            internal_id: 2,
            uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
            owner_id: Some(42),
        },
    ] {
        assert!(ensure_scanner_clone_source_allowed(&state).is_ok());
    }
    for state in [
        ScannerWriteState {
            internal_id: 3,
            uuid: "6acd0832-df90-11e4-b9d5-28d24461215b".to_string(),
            owner_id: None,
        },
        ScannerWriteState {
            internal_id: 4,
            uuid: "12345678-1234-1234-1234-123456789abd".to_string(),
            owner_id: None,
        },
    ] {
        assert!(matches!(
            ensure_scanner_clone_source_allowed(&state),
            Err(ApiError::Forbidden)
        ));
    }
}

#[test]
fn scanner_configuration_rejects_bad_hosts_ports_types_and_unknown_fields() {
    for (host, port) in [
        ("bad host", 9390),
        ("-scanner.example", 9390),
        ("scanner..example", 9390),
        ("/", 0),
        ("/run//unsafe.sock", 0),
        ("/run/./unsafe.sock", 0),
        ("/run/../unsafe.sock", 0),
        ("scanner.example", 0),
        ("scanner.example", 65_536),
        ("/run/ospd.sock", 9390),
    ] {
        assert!(matches!(
            validate_scanner_configuration_request(configuration_request(host, port)),
            Err(ApiError::BadRequest(_))
        ));
    }
    for scanner_type in [0, 1, i64::from(ScannerType::Cve.database_value()), 4, 7, 9] {
        assert!(matches!(
            validate_scanner_configuration_request(ScannerConfigurationRequest {
                scanner_type,
                ..configuration_request("scanner.example", 9390)
            }),
            Err(ApiError::BadRequest(_))
        ));
    }
    assert!(
        serde_json::from_value::<ScannerConfigurationRequest>(serde_json::json!({
            "name": "Scanner",
            "comment": "",
            "host": "scanner.example",
            "port": 9390,
            "scanner_type": 2,
            "relay_host": "relay.example"
        }))
        .is_err()
    );
}

#[test]
fn scanner_configuration_requires_bounded_certificate_shaped_pem() {
    for ca_pub in [
        "",
        "not a certificate",
        "-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----",
    ] {
        assert!(matches!(
            validate_scanner_configuration_request(ScannerConfigurationRequest {
                ca_pub: Some(ca_pub.to_string()),
                ..configuration_request("scanner.example", 9390)
            }),
            Err(ApiError::BadRequest(_))
        ));
    }
    assert!(matches!(
        validate_scanner_configuration_request(ScannerConfigurationRequest {
            ca_pub: Some("x".repeat(MAX_SCANNER_CA_PUB_BYTES + 1)),
            ..configuration_request("scanner.example", 9390)
        }),
        Err(ApiError::BadRequest(_))
    ));

    let bundle = format!("{CERTIFICATE_SHAPED_PEM}\n{CERTIFICATE_SHAPED_PEM}");
    let validated = validate_scanner_configuration_request(ScannerConfigurationRequest {
        ca_pub: Some(bundle.clone()),
        ..configuration_request("scanner.example", 9390)
    })
    .expect("certificate bundle");
    assert_eq!(validated.ca_pub.as_deref(), Some(bundle.as_str()));

    for trailing in [
        format!("{CERTIFICATE_SHAPED_PEM}\ntrailing junk"),
        format!(
            "{CERTIFICATE_SHAPED_PEM}\n-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----"
        ),
    ] {
        assert!(matches!(
            validate_scanner_configuration_request(ScannerConfigurationRequest {
                ca_pub: Some(trailing),
                ..configuration_request("scanner.example", 9390)
            }),
            Err(ApiError::BadRequest(_))
        ));
    }
}

#[test]
fn scanner_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_scanner_patch_request(patch_request(Some("  "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scanner_patch_request_allows_blank_comment_clear() {
    let patch = validate_scanner_patch_request(patch_request(None, Some("  ")))
        .expect("blank comment should clear after trimming");
    assert_eq!(patch.comment.as_deref(), Some(""));
}

#[test]
fn scanner_patch_request_rejects_empty_body_unknown_fields_and_controls() {
    assert!(matches!(
        validate_scanner_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(
        serde_json::from_value::<ScannerPatchRequest>(serde_json::json!({
            "name": "Scanner",
            "host": "127.0.0.1"
        }))
        .is_err()
    );
    assert!(matches!(
        validate_scanner_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_scanner_patch_request(ScannerPatchRequest {
            name: Some("s".repeat(MAX_SCANNER_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scanner_patch_blocks_builtin_or_ownerless_scanners() {
    let mutable = ScannerWriteState {
        internal_id: 1,
        uuid: "12345678-1234-1234-1234-123456789abc".to_string(),
        owner_id: Some(42),
    };
    assert!(ensure_scanner_metadata_patch_allowed(&mutable).is_ok());

    let other_human_owned = ScannerWriteState {
        internal_id: 1,
        uuid: mutable.uuid.clone(),
        owner_id: Some(7),
    };
    assert!(ensure_scanner_metadata_patch_allowed(&other_human_owned).is_ok());

    for uuid in [
        "08b69003-5fc2-4037-a479-93b440211c73",
        "6acd0832-df90-11e4-b9d5-28d24461215b",
    ] {
        let builtin = ScannerWriteState {
            internal_id: 1,
            uuid: uuid.to_string(),
            owner_id: Some(42),
        };
        assert!(matches!(
            ensure_scanner_metadata_patch_allowed(&builtin),
            Err(ApiError::Forbidden)
        ));
    }

    let null_owner = ScannerWriteState {
        internal_id: 1,
        uuid: mutable.uuid,
        owner_id: None,
    };
    assert!(matches!(
        ensure_scanner_metadata_patch_allowed(&null_owner),
        Err(ApiError::Forbidden)
    ));
}

#[test]
fn scanner_patch_handler_requires_operator_and_allows_mutation_only_after_guard() {
    let source = include_str!("scanner_writes.rs");
    let handler = source
        .split_once("pub(crate) async fn patch_scanner")
        .expect("patch scanner handler must exist")
        .1;

    assert!(handler.contains("let operator = require_scanner_write_operator(operator)?;"));
    assert!(handler.contains("resolve_scanner_write_operator_owner(&tx, &operator).await?"));
    assert!(handler.contains("ensure_scanner_metadata_patch_allowed"));
    assert!(
        handler
            .find("ensure_scanner_metadata_patch_allowed")
            .unwrap()
            < handler.find("execute_scanner_patch_transaction").unwrap(),
        "scanner patch must verify human-owner/builtin guard before metadata mutation"
    );
}

#[test]
fn scanner_patch_sql_is_metadata_only_and_preserves_secret_control_fields() {
    let state = scanner_write_state_sql();
    assert!(state.contains("owner::integer"));
    let update = scanner_update_metadata_sql();
    assert!(update.contains("SET name = coalesce($2, name)"));
    assert!(update.contains("comment = coalesce($3, comment)"));
    assert!(update.contains("modification_time = m_now()"));
    for forbidden in [
        "host",
        "port",
        "type",
        "ca_pub",
        "credential",
        "relay_host",
        "relay_port",
        "verify",
        "DELETE",
        "INSERT",
    ] {
        assert!(
            !update
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase()),
            "scanner metadata patch must not touch {forbidden}"
        );
    }
}

#[test]
fn scanner_configuration_sql_has_bounded_complete_shape_and_preserves_relays() {
    let credential = scanner_credential_state_sql();
    for required in ["owner::integer", "type::text", "WHERE uuid = $1"] {
        assert!(credential.contains(required));
    }

    let create = scanner_create_configuration_sql();
    for required in [
        "make_uuid()",
        "uuid, owner, name, comment, host, port, type, ca_pub, credential",
        "relay_host, relay_port",
        "$1, $2, $3, $4, $5, $6, $7, $8, NULL, 0",
        "m_now(), m_now()",
        "RETURNING uuid::text",
    ] {
        assert!(
            create.contains(required),
            "scanner create SQL missing {required}"
        );
    }

    let replace = scanner_replace_configuration_sql();
    for required in [
        "name = $2",
        "comment = $3",
        "host = $4",
        "port = $5",
        "type = $6",
        "ca_pub = $7",
        "credential = $8",
        "modification_time = m_now()",
        "WHERE id = $1",
        "RETURNING uuid::text",
    ] {
        assert!(
            replace.contains(required),
            "scanner replace SQL missing {required}"
        );
    }
    for preserved in ["relay_host", "relay_port"] {
        assert!(
            !replace.contains(preserved),
            "scanner replacement must preserve {preserved}"
        );
    }
}

#[test]
fn scanner_configuration_replace_rejects_live_non_hidden_task_references() {
    assert!(ensure_scanner_live_task_count_allows_replace(0).is_ok());
    assert!(matches!(
        ensure_scanner_live_task_count_allows_replace(1),
        Err(ApiError::Conflict(_))
    ));

    let in_use = scanner_live_task_count_sql();
    for required in [
        "FROM tasks",
        "scanner = $1",
        "coalesce(scanner_location, 0) = 0",
        "coalesce(hidden, 0) = 0",
    ] {
        assert!(
            in_use.contains(required),
            "scanner in-use SQL missing {required}"
        );
    }
}

#[test]
fn scanner_lifecycle_sql_preserves_references_and_losslessly_round_trips_relays() {
    let clone = scanner_clone_metadata_sql();
    for required in [
        "make_uuid()",
        "uniquify('scanner', name, $2, ' Clone')",
        "host",
        "port",
        "type",
        "ca_pub",
        "credential",
        "NULL",
        "RETURNING id::integer, uuid::text",
    ] {
        assert!(
            clone.contains(required),
            "scanner clone SQL missing {required}"
        );
    }
    assert!(clone.contains("credential,\n            NULL,\n            0,\n            m_now()"));
    assert!(!clone.contains("SELECT\n            make_uuid(),\n            uniquify('scanner', name, $2, ' Clone'),\n            host,\n            port,\n            type,\n            ca_pub,\n            credential,\n            relay_host"));

    let clone_tags = scanner_clone_tags_sql();
    for required in [
        "INSERT INTO tag_resources",
        "resource_type = 'scanner'",
        "resource_location = 0",
        "$2, $3, 0",
    ] {
        assert!(clone_tags.contains(required));
    }

    let trash = scanner_trash_insert_sql();
    let restore = scanner_restore_metadata_sql();
    for required in ["relay_host", "relay_port", "credential_location"] {
        assert!(
            trash.contains(required),
            "scanner trash SQL missing {required}"
        );
    }
    for required in ["relay_host", "relay_port", "credential"] {
        assert!(
            restore.contains(required),
            "scanner restore SQL missing {required}"
        );
    }
    assert!(scanner_trash_task_relink_sql().contains("scanner_location = 1"));
    assert!(scanner_restore_task_relink_sql().contains("scanner_location = 0"));
    assert!(scanner_tag_locations_to_trash_sql().contains("resource_location = 1"));
    assert!(scanner_tag_locations_to_live_sql().contains("resource_location = 0"));
    assert!(scanner_delete_live_metadata_sql().contains("DELETE FROM scanners WHERE id = $1"));
    assert!(
        scanner_delete_trash_metadata_sql().contains("DELETE FROM scanners_trash WHERE id = $1")
    );
}

#[test]
fn scanner_lifecycle_handlers_guard_before_atomic_mutation() {
    let source = include_str!("scanner_writes.rs");
    for (name, guard, mutation) in [
        (
            "clone_scanner",
            "ensure_scanner_clone_source_allowed",
            "execute_scanner_clone_transaction",
        ),
        (
            "delete_scanner",
            "ensure_scanner_not_in_use_for_delete",
            "execute_scanner_trash_transaction",
        ),
        (
            "restore_scanner",
            "ensure_trash_scanner_credential_is_live",
            "execute_scanner_restore_transaction",
        ),
        (
            "hard_delete_scanner",
            "ensure_trash_scanner_not_in_use",
            "execute_scanner_hard_delete_transaction",
        ),
    ] {
        let handler = source
            .split_once(&format!("pub(crate) async fn {name}"))
            .unwrap_or_else(|| panic!("{name} handler"))
            .1;
        assert!(handler.contains("require_scanner_write_operator(operator)?"));
        assert!(handler.contains("resolve_scanner_write_operator_owner"));
        assert!(handler.find(guard).unwrap() < handler.find(mutation).unwrap());
        assert!(handler.find(mutation).unwrap() < handler.find("tx.commit()").unwrap());
    }
}

#[test]
fn scanner_create_and_replace_are_guarded_before_atomic_mutation() {
    let source = include_str!("scanner_writes.rs");
    let create = source
        .split_once("pub(crate) async fn create_scanner")
        .expect("create scanner handler")
        .1
        .split_once("pub(crate) async fn replace_scanner_configuration")
        .expect("create scanner handler end")
        .0;
    for required in [
        "require_scanner_write_operator(operator)?",
        "validate_scanner_configuration_request(request)?",
        "LOCK TABLE users, credentials, scanners IN SHARE ROW EXCLUSIVE MODE",
        "resolve_scanner_write_operator_owner",
        "ensure_unique_scanner_name",
        "resolve_scanner_credential",
        "execute_scanner_create_transaction",
        "tx.commit()",
        "StatusCode::CREATED",
        "scanner_write_location_headers",
    ] {
        assert!(
            create.contains(required),
            "scanner create handler missing {required}"
        );
    }

    let replace = source
        .split_once("pub(crate) async fn replace_scanner_configuration")
        .expect("replace scanner handler")
        .1
        .split_once("pub(crate) async fn patch_scanner")
        .expect("replace scanner handler end")
        .0;
    for required in [
        "require_scanner_write_operator(operator)?",
        "validate_scanner_configuration_request(request)?",
        "LOCK TABLE users, credentials, scanners, tasks IN SHARE ROW EXCLUSIVE MODE",
        "load_scanner_write_state",
        "ensure_scanner_metadata_patch_allowed",
        "ensure_scanner_not_in_use_for_configuration_replace",
        "ensure_unique_scanner_name",
        "resolve_scanner_credential",
        "execute_scanner_replace_transaction",
        "tx.commit()",
    ] {
        assert!(
            replace.contains(required),
            "scanner replace handler missing {required}"
        );
    }
    assert!(
        replace
            .find("ensure_scanner_metadata_patch_allowed")
            .unwrap()
            < replace
                .find("ensure_scanner_not_in_use_for_configuration_replace")
                .unwrap()
    );
    assert!(
        replace
            .find("ensure_scanner_not_in_use_for_configuration_replace")
            .unwrap()
            < replace.find("execute_scanner_replace_transaction").unwrap()
    );
}

#[test]
fn scanner_credential_resolution_accepts_any_human_owner_and_requires_cc_without_secret_reads() {
    let db = include_str!("scanner_write_db.rs");
    let loader = db
        .split_once("pub(crate) async fn load_human_owned_scanner_credential")
        .expect("scanner credential loader")
        .1
        .split_once("pub(crate) async fn query_scanner_write_record")
        .expect("scanner credential loader end")
        .0;
    for required in [
        "parse_uuid(credential_id)?",
        "owner_id.is_none()",
        "credential_type != \"cc\"",
        "ApiError::Forbidden",
        "ApiError::BadRequest",
    ] {
        assert!(
            loader.contains(required),
            "credential loader missing {required}"
        );
    }
    for forbidden in ["credentials_data", "password", "private_key", "secret"] {
        assert!(!scanner_credential_state_sql().contains(forbidden));
    }
}
