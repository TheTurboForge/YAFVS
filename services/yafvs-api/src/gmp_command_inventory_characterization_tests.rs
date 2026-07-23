// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: original

use std::collections::BTreeSet;

const GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
const MANAGE_COMMANDS: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const MANAGE_ALERTS: &str = include_str!("../../../components/gvmd/src/manage_alerts.c");
const MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_ALERTS: &str = include_str!("../../../components/gvmd/src/manage_sql_alerts.c");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_HEADER: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GSA_INFO_ENTITY: &str =
    include_str!("../../../components/gsa/src/gmp/commands/info-entity.ts");
const GSA_INFO_ENTITIES: &str =
    include_str!("../../../components/gsa/src/gmp/commands/info-entities.ts");
const GSA_ENTITIES: &str = include_str!("../../../components/gsa/src/gmp/commands/entities.ts");
const GSA_OMP: &str = include_str!("../../../components/gsa/src/web/pages/Omp.jsx");
const GSA_DETAIL_COMMANDS: [&str; 5] = [
    include_str!("../../../components/gsa/src/gmp/commands/cpe.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/cve.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/nvt.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/cert-bund-advisory.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/dfn-cert-advisory.ts"),
];
const GSA_LIST_COMMANDS: [&str; 5] = [
    include_str!("../../../components/gsa/src/gmp/commands/cpes.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/cves.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/nvts.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/cert-bund-advisories.ts"),
    include_str!("../../../components/gsa/src/gmp/commands/dfn-cert-advisories.ts"),
];
const READ_API_ROUTES: &str = include_str!("read_api_routes.rs");
const MANAGE: &str = include_str!("../../../components/gvmd/src/manage.c");
const MANAGE_SQL_SECINFO: &str = include_str!("../../../components/gvmd/src/manage_sql_secinfo.c");
const MANAGE_SQL_NVTS: &str = include_str!("../../../components/gvmd/src/manage_sql_nvts.c");

fn advertised_commands() -> BTreeSet<String> {
    let block = MANAGE_COMMANDS
        .split_once("command_t gmp_commands[]")
        .expect("public GMP command inventory must exist")
        .1
        .split_once("{NULL, NULL}")
        .expect("public GMP command inventory must terminate")
        .0;

    block
        .lines()
        .filter_map(|line| {
            let start = line.find("{\"")? + 2;
            let tail = &line[start..];
            let end = tail.find('"')?;
            Some(tail[..end].to_string())
        })
        .collect()
}

#[test]
fn get_info_is_native_only_authority_not_public_transport() {
    let advertised = advertised_commands();
    let accepted = authenticated_parser_commands();

    assert!(!advertised.contains("GET_INFO"));
    assert!(!accepted.contains("GET_INFO"));
    assert!(native_acl_operations().contains("GET_INFO"));
    assert!(!GMP.contains("CLIENT_GET_INFO"));
    assert!(!GMP.contains("get_info_data"));
    assert!(!GMP.contains("handle_get_info"));
    assert!(!GMP.contains("strcasecmp (\"GET_INFO\""));
    assert!(!GMP_SCHEMA.contains("<name>get_info</name>"));
    assert!(GMP_SCHEMA.contains("<command>GET_INFO</command>"));

    for retained in ["AUTHENTICATE", "HELP", "GET_AGGREGATES", "GET_NVTS"] {
        assert!(advertised.contains(retained));
        assert!(accepted.contains(retained));
    }
}

#[test]
fn gsad_get_info_and_generic_raw_export_paths_fail_closed() {
    assert!(!GSAD_GMP.contains("get_info_gmp"));
    assert!(!GSAD_GMP_HEADER.contains("get_info_gmp"));
    assert!(!GSAD_GMP.contains("ELSE (get_info)"));
    assert!(!GSAD_VALIDATOR.contains("|(get_info)"));
    assert!(!GSAD_GMP.contains("<get_info"));

    let bulk_export = GSAD_GMP
        .split_once("bulk_export_gmp (")
        .expect("bulk export handler must remain")
        .1
        .split_once("/**\n * @brief Modify an asset")
        .expect("bulk export handler must terminate before asset modification")
        .0;
    let rejection = bulk_export
        .find("g_ascii_strcasecmp (type, \"info\")")
        .expect("generic info export must be rejected case-insensitively");
    let selection = bulk_export
        .find("if (bulk_select")
        .expect("retained generic selection handling must remain");
    let filter_mutation = bulk_export
        .find("params_add (params, \"filter\"")
        .expect("retained generic filter construction must remain");

    assert!(bulk_export.contains("MHD_HTTP_BAD_REQUEST"));
    assert!(bulk_export.contains("Catalog XML bulk export is no longer supported"));
    assert!(rejection < selection);
    assert!(rejection < filter_mutation);
}

#[test]
fn catalog_browser_commands_are_native_and_raw_bases_are_fail_closed() {
    for base in [GSA_INFO_ENTITY, GSA_INFO_ENTITIES] {
        assert!(!base.contains("get_info"));
        assert!(!base.contains("delete_info"));
        assert!(!base.contains("bulk_export"));
        assert!(base.contains("requires a native API implementation"));
    }
    assert!(GSA_INFO_ENTITY.contains("Catalog entries cannot be deleted"));
    assert!(GSA_INFO_ENTITIES.contains("extends EntitiesCommand"));
    assert!(GSA_INFO_ENTITIES.contains("setDefaultParam('info_type'"));
    assert!(GSA_ENTITIES.contains("async getAggregates"));

    for command in GSA_DETAIL_COMMANDS {
        assert!(command.contains("async get("));
        assert!(command.contains("async export("));
        assert!(command.contains("fetchNative"));
        assert!(command.contains("exportNative"));
        assert!(!command.contains("get_info"));
    }
    for command in GSA_LIST_COMMANDS {
        for method in [
            "async get(",
            "async getAll(",
            "exportByIds(",
            "async exportByFilter(",
        ] {
            assert!(command.contains(method));
        }
        assert!(command.contains("fetchNative"));
        assert!(command.contains("exportNative"));
        assert!(!command.contains("get_info"));
    }

    assert!(GSA_DETAIL_COMMANDS[2].contains("fetchNativeScanConfig"));
    assert!(GSA_DETAIL_COMMANDS[2].contains("Promise.all"));
    assert!(GSA_DETAIL_COMMANDS[2].contains("configuredTimeout"));
    assert!(GSA_DETAIL_COMMANDS[2].contains("preferences"));
}

#[test]
fn catalog_redirect_routes_and_internal_semantics_remain() {
    assert!(GSA_OMP.contains("/omp?cmd=get_info"));
    assert!(GSA_OMP.contains("cmd !== 'get_info'"));
    for route in [
        "/api/v1/cpes",
        "/api/v1/cves",
        "/api/v1/nvts",
        "/api/v1/cert-bund-advisories",
        "/api/v1/dfn-cert-advisories",
    ] {
        assert!(READ_API_ROUTES.contains(route));
    }

    for symbol in [
        "init_cpe_info_iterator",
        "cpe_info_count",
        "init_cve_info_iterator",
        "cve_info_count",
        "init_cert_bund_adv_info_iterator",
        "cert_bund_adv_info_count",
        "init_dfn_cert_adv_info_iterator",
        "dfn_cert_adv_info_count",
        "update_scap_cpes",
        "update_scap_cves",
        "update_cert_bund_advisories",
    ] {
        assert!(MANAGE_SQL_SECINFO.contains(symbol));
    }
    for symbol in [
        "init_nvt_info_iterator",
        "nvt_info_count",
        "update_or_rebuild_nvts",
    ] {
        assert!(MANAGE_SQL_NVTS.contains(symbol));
    }
    for symbol in [
        "manage_sync_scap",
        "manage_sync_cert",
        "manage_rebuild_gvmd_data_from_feed",
        "manage_read_info",
        "cve_scan_report_host_json",
        "host_details_cpe",
        "make_cve_result",
        "init_resource_tag_iterator (&tags, \"nvt\"",
    ] {
        assert!(MANAGE.contains(symbol));
    }

    assert!(GMP.contains("send_nvt ("));
    assert!(GMP.contains("result_iterator_nvt_oid"));
    assert!(GMP.contains("handle_get_resource_names"));
    assert!(GMP.contains("acl_user_may (\"get_info\")"));
    assert!(GMP.contains("init_resource_tag_iterator"));
}

#[test]
fn get_version_is_retired_while_authenticate_help_and_gsad_login_remain() {
    let advertised = advertised_commands();
    let accepted = authenticated_parser_commands();

    assert!(!advertised.contains("GET_VERSION"));
    assert!(!accepted.contains("GET_VERSION"));
    assert!(!GMP.contains("CLIENT_GET_VERSION"));
    assert!(!GMP.contains("handle_get_version"));
    assert!(!MANAGE_COMMANDS.contains("strcasecmp (name, \"GET_VERSION\")"));
    assert!(GMP.contains("Only command AUTHENTICATE is"));
    assert!(GMP.contains("allowed before authentication"));

    assert!(advertised.contains("AUTHENTICATE"));
    assert!(advertised.contains("HELP"));
    assert!(accepted.contains("AUTHENTICATE"));
    assert!(accepted.contains("HELP"));
    assert!(GMP_SCHEMA.contains("<name>authenticate</name>"));
    assert!(GSAD_GMP.contains("<help format=\\\"XML\\\" type=\\\"brief\\\"/>"));
}

#[test]
fn get_assets_is_a_native_only_acl_key_not_public_transport() {
    assert!(!advertised_commands().contains("GET_ASSETS"));
    assert!(!authenticated_parser_commands().contains("GET_ASSETS"));
    assert!(native_acl_operations().contains("GET_ASSETS"));
    assert!(!GMP.contains("CLIENT_GET_ASSETS"));
    assert!(!GMP.contains("handle_get_assets"));
    assert!(!GMP_SCHEMA.contains("<name>get_assets</name>"));
    assert!(GMP_SCHEMA.contains("instead use the GET_ASSETS command"));
    assert!(GMP_SCHEMA.contains("GET_ASSETS should be used instead"));
}

fn authenticated_parser_commands() -> BTreeSet<String> {
    let block = GMP
        .split_once("case CLIENT_AUTHENTIC:")
        .expect("authenticated parser entry state must exist")
        .1
        .split_once("case CLIENT_AUTHENTICATE:")
        .expect("authenticated parser entry state must terminate")
        .0;
    let mut commands = BTreeSet::new();

    for line in block.lines() {
        if let Some(tail) = line.strip_prefix("        else if (strcasecmp (\"") {
            let end = tail
                .find('"')
                .expect("top-level command comparison must close its name");
            commands.insert(tail[..end].to_string());
        } else if let Some(tail) = line.strip_prefix("        ELSE_GET_START (") {
            let end = tail
                .find(',')
                .expect("generic GET parser macro must name its resource");
            commands.insert(format!("GET_{}", tail[..end].trim().to_ascii_uppercase()));
        }
    }

    commands
}

fn native_acl_operations() -> BTreeSet<String> {
    let block = MANAGE_COMMANDS
        .split_once("static const char *native_acl_operations[]")
        .expect("native-only ACL operation inventory must exist")
        .1
        .split_once("NULL")
        .expect("native-only ACL operation inventory must terminate")
        .0;

    block
        .lines()
        .filter_map(|line| {
            let tail = line.trim().strip_prefix('"')?;
            let end = tail.find('"')?;
            Some(tail[..end].to_string())
        })
        .collect()
}

#[test]
fn advertised_gmp_commands_match_the_authenticated_parser() {
    let advertised = advertised_commands();
    let mut accepted = authenticated_parser_commands();

    for intentionally_unadvertised in ["GET_RESOURCE_NAMES", "LOGOUT"] {
        assert!(
            accepted.remove(intentionally_unadvertised),
            "documented internal parser command {intentionally_unadvertised} must remain accepted"
        );
        assert!(!advertised.contains(intentionally_unadvertised));
    }

    assert_eq!(
        advertised, accepted,
        "GMP HELP must advertise exactly the authenticated public parser surface"
    );
}

#[test]
fn retired_public_commands_keep_only_live_native_authority_keys() {
    let advertised = advertised_commands();
    let native_acl = native_acl_operations();
    let retained_native = [
        "CREATE_USER",
        "CREATE_PORT_LIST",
        "CREATE_REPORT_FORMAT",
        "DELETE_ALERT",
        "DELETE_USER",
        "EMPTY_TRASHCAN",
        "GET_ALERTS",
        "GET_USERS",
        "MODIFY_USER",
        "TEST_ALERT",
        "DELETE_SCHEDULE",
        "GET_SCHEDULES",
        "GET_TARGETS",
    ];

    for command in [
        "DELETE_SCHEDULE",
        "GET_SCHEDULES",
        "GET_TARGETS",
        "CREATE_FILTER",
        "CREATE_PORT_LIST",
        "CREATE_PORT_RANGE",
        "CREATE_REPORT",
        "CREATE_REPORT_FORMAT",
        "CREATE_SCOPE",
        "CREATE_USER",
        "DELETE_ALERT",
        "DELETE_FILTER",
        "DELETE_PORT_LIST",
        "DELETE_PORT_RANGE",
        "DELETE_REPORT_FORMAT",
        "DELETE_SCOPE",
        "DELETE_USER",
        "DESCRIBE_AUTH",
        "EMPTY_TRASHCAN",
        "GET_ALERTS",
        "GET_USERS",
        "MODIFY_AUTH",
        "MODIFY_FILTER",
        "MODIFY_PORT_LIST",
        "MODIFY_REPORT_FORMAT",
        "MODIFY_SCOPE",
        "MODIFY_USER",
        "SYNC_CONFIG",
        "TEST_ALERT",
        "VERIFY_REPORT_FORMAT",
    ] {
        assert!(
            !advertised.contains(command),
            "retired command {command} must not remain in public GMP HELP"
        );
        assert_eq!(
            native_acl.contains(command),
            retained_native.contains(&command),
            "retired command {command} has the wrong native authority classification"
        );
    }

    for command in ["DELETE_ALERT", "GET_ALERTS", "TEST_ALERT"] {
        let lower = command.to_ascii_lowercase();
        assert!(
            !GMP.contains(&format!("strcasecmp (\"{command}\"")),
            "raw GMP parser still accepts retired command {command}"
        );
        assert!(
            !MANAGE_COMMANDS.contains(&format!("{{\"{command}\",")),
            "GMP HELP still advertises retired command {command}"
        );
        assert!(
            !GMP_SCHEMA.contains(&format!("<name>{lower}</name>")),
            "live GMP schema still documents retired command {command}"
        );
        assert!(
            native_acl.contains(command),
            "native authorization must retain {command}"
        );
    }

    assert!(MANAGE_SQL_ALERTS.contains("delete_alert ("));
    assert!(MANAGE_ALERTS.contains("manage_test_alert"));
    assert!(MANAGE_SQL_ALERTS.contains("\"delete_alert\""));
    assert!(MANAGE_ALERTS.contains("\"test_alert\""));
    assert!(MANAGE_SQL.contains("\"get_alerts\""));
    assert!(GMP_SCHEMA.contains("<command>GET_ALERTS</command>"));
}

#[test]
fn get_targets_is_a_native_only_acl_key_not_public_transport() {
    assert!(!advertised_commands().contains("GET_TARGETS"));
    assert!(!authenticated_parser_commands().contains("GET_TARGETS"));
    assert!(native_acl_operations().contains("GET_TARGETS"));
    assert!(!GMP.contains("CLIENT_GET_TARGETS"));
    assert!(!GMP_SCHEMA.contains("<name>get_targets</name>"));
    assert!(GMP_SCHEMA.contains("<command>GET_TARGETS</command>"));
}

#[test]
fn retired_schedule_transport_has_no_gsad_or_live_gmp_surface() {
    for alias in [
        "get_schedule_gmp",
        "get_schedules_gmp",
        "export_schedule_gmp",
        "export_schedules_gmp",
        "delete_schedule_gmp",
    ] {
        assert!(!GSAD_GMP.contains(alias));
        assert!(!GSAD_GMP_HEADER.contains(alias));
    }
    for dispatch in [
        "ELSE (get_schedule)",
        "ELSE (get_schedules)",
        "ELSE (export_schedule)",
        "ELSE (export_schedules)",
        "ELSE (delete_schedule)",
    ] {
        assert!(!GSAD_GMP.contains(dispatch));
    }
    for token in [
        "|(get_schedule)",
        "|(get_schedules)",
        "|(export_schedule)",
        "|(export_schedules)",
        "|(delete_schedule)",
    ] {
        assert!(!GSAD_VALIDATOR.contains(token));
    }
    for command in ["DELETE_SCHEDULE", "GET_SCHEDULES"] {
        let lower = command.to_ascii_lowercase();
        assert!(!GMP.contains(&format!("strcasecmp (\"{command}\"")));
        assert!(!GMP.contains(&format!("CLIENT_{command}")));
        assert!(!MANAGE_COMMANDS.contains(&format!("{{\"{command}\"")));
        assert!(!GMP_SCHEMA.contains(&format!("<name>{lower}</name>")));
        assert!(native_acl_operations().contains(command));
    }
    assert!(GMP_SCHEMA.contains("<command>GET_SCHEDULES</command>"));
}
