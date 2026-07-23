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
    ];

    for command in [
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
