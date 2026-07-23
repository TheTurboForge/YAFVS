// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: original

use std::path::Path;
use yafvs_domain::{DATABASE_VERSION, SCHEMA_FINGERPRINT};

const GVM_LIBS_CMAKE: &str = include_str!("../../../components/gvm-libs/CMakeLists.txt");
const GVMD_CMAKE: &str = include_str!("../../../components/gvmd/CMakeLists.txt");
const GVMD_SOURCE_CMAKE: &str = include_str!("../../../components/gvmd/src/CMakeLists.txt");
const GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GMP_SCHEMA: &str = include_str!("../../../components/gvmd/src/schema_formats/XML/GMP.xml.in");
const GVMD: &str = include_str!("../../../components/gvmd/src/gvmd.c");
const MANAGE: &str = include_str!("../../../components/gvmd/src/manage.c");
const MANAGE_COMMANDS: &str = include_str!("../../../components/gvmd/src/manage_commands.c");
const MANAGE_MIGRATORS: &str = include_str!("../../../components/gvmd/src/manage_migrators.c");
const MANAGE_OPENVASD: &str = include_str!("../../../components/gvmd/src/manage_openvasd.c");
const MANAGE_OSP: &str = include_str!("../../../components/gvmd/src/manage_osp.c");
const MANAGE_PG: &str = include_str!("../../../components/gvmd/src/manage_pg.c");
const MANAGE_RUNTIME_FLAGS: &str =
    include_str!("../../../components/gvmd/src/manage_runtime_flags.c");
const MANAGE_SETTINGS: &str = include_str!("../../../components/gvmd/src/manage_settings.h");
const MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_SETTINGS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_settings.c");
const GVMD_CONFIG: &str = include_str!("../../../components/gvmd/config/gvmd.conf.in");
const GVMD_FEATURE_DOCS: &str = include_str!("../../../components/gvmd/docs/feature-flags.md");
const GSA_FEATURES: &str = include_str!("../../../components/gsa/src/gmp/capabilities/features.ts");
const GSA_GENERAL_SETTINGS: &str =
    include_str!("../../../components/gsa/src/web/pages/user-settings/GeneralSettings.tsx");
const DATABASE_COMPATIBILITY: &str = include_str!("database_compatibility.rs");
const MANAGER_INIT: &str =
    include_str!("../../../tools/yafvsctl-rs/src/commands/feed_generation/manager_init.rs");

#[test]
fn security_intelligence_export_surface_is_retired() {
    let live_sources = [
        ("gvm-libs CMake", GVM_LIBS_CMAKE),
        ("gvmd CMake", GVMD_CMAKE),
        ("gvmd source CMake", GVMD_SOURCE_CMAKE),
        ("GMP parser", GMP),
        ("GMP schema", GMP_SCHEMA),
        ("gvmd daemon", GVMD),
        ("manager", MANAGE),
        ("manager commands", MANAGE_COMMANDS),
        ("openvasd completion", MANAGE_OPENVASD),
        ("OSP completion", MANAGE_OSP),
        ("fresh schema", MANAGE_PG),
        ("runtime flags", MANAGE_RUNTIME_FLAGS),
        ("settings identifiers", MANAGE_SETTINGS),
        ("manager SQL", MANAGE_SQL),
        ("settings SQL", MANAGE_SQL_SETTINGS),
        ("gvmd config", GVMD_CONFIG),
        ("feature documentation", GVMD_FEATURE_DOCS),
        ("GSA feature inventory", GSA_FEATURES),
        ("GSA general settings", GSA_GENERAL_SETTINGS),
    ];
    let retired_markers = [
        "enable_security_intelligence",
        "security_intelligence_export",
        "get_integration_configs",
        "modify_integration_config",
        "report_exports",
        "integration_configs",
        "manage_report_export_scheduler",
        "manage_sql_report_exports",
        "gvm_security_intelligence",
        "report_export_max_retries",
    ];

    for (name, source) in live_sources {
        let source = source.to_ascii_lowercase();
        for marker in retired_markers {
            assert!(
                !source.contains(marker),
                "{name} retains retired Security Intelligence Export marker {marker}"
            );
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for retired_path in [
        "components/gvm-libs/security_intelligence/CMakeLists.txt",
        "components/gvm-libs/security_intelligence/security_intelligence.c",
        "components/gvm-libs/security_intelligence/security_intelligence.h",
        "components/gvmd/src/gmp_integration_configs.c",
        "components/gvmd/src/manage_integration_configs.c",
        "components/gvmd/src/manage_report_export_scheduler.c",
        "components/gvmd/src/manage_sql_integration_configs.c",
        "components/gvmd/src/manage_sql_report_exports.c",
    ] {
        assert!(
            !root.join(retired_path).exists(),
            "retired Security Intelligence Export path still exists: {retired_path}"
        );
    }
}

#[test]
fn ordinary_scan_finalization_remains_without_export_queueing() {
    for (name, source) in [
        ("manager", MANAGE),
        ("OSP completion", MANAGE_OSP),
        ("openvasd completion", MANAGE_OPENVASD),
    ] {
        assert!(
            source.contains("set_task_run_status (task, TASK_STATUS_DONE)"),
            "{name} lost ordinary terminal task-state handling"
        );
        assert!(
            source.contains("set_report_scan_run_status (global_current_report, TASK_STATUS_DONE)"),
            "{name} lost ordinary terminal report-state handling"
        );
        assert!(!source.contains("enqueue_report"));
        assert!(!source.contains("report_exports"));
    }

    assert!(MANAGE.contains("manage_process_report_finalizations ()"));
    assert!(MANAGE.contains("process_report_finalization (report)"));
}

#[test]
fn database_288_removes_only_empty_legacy_export_state() {
    assert!(GVMD_CMAKE.contains(&format!("set(GVMD_DATABASE_VERSION {DATABASE_VERSION})")));
    assert_eq!(DATABASE_VERSION, "288");
    assert_eq!(
        SCHEMA_FINGERPRINT,
        "c9b9aed02c7ac9313957f17adfe1a6658f18b63c7600731e64d5bb2dd7135d62"
    );
    assert!(DATABASE_COMPATIBILITY.contains("public_schema_fingerprint_sql"));
    assert!(MANAGER_INIT.contains("public_schema_fingerprint_sql"));
    assert!(!MANAGE_PG.contains("CREATE TABLE IF NOT EXISTS report_exports"));
    assert!(!MANAGE_PG.contains("CREATE TABLE IF NOT EXISTS integration_configs"));

    let migration = MANAGE_MIGRATORS
        .split_once("migrate_287_to_288 ()")
        .expect("287 to 288 migration must exist")
        .1
        .split_once("migrate_205_to_206 ()")
        .expect("287 to 288 migration must precede older exported migrators")
        .0;

    for required in [
        "manage_db_version () != 287",
        "SELECT count(*) FROM integration_configs",
        "SELECT count(*) FROM report_exports",
        "e15e8a57-0285-439b-929a-068880b410b4",
        "8f0602d4-431a-4321-bfd7-cfb7eb0af55f",
        "Refusing to remove Security Intelligence Export",
        "sql_rollback ()",
        "DROP TABLE report_exports",
        "DROP TABLE integration_configs",
        "set_db_version (288)",
        "sql_commit ()",
    ] {
        assert!(
            migration.contains(required),
            "287 to 288 migration is missing fail-closed evidence: {required}"
        );
    }
    assert!(MANAGE_MIGRATORS.contains("{288, migrate_287_to_288}"));
}
