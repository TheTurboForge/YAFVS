// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const GSA_TRASHCAN: &str = include_str!("../../../components/gsa/src/gmp/commands/trashcan.ts");
const GSA_NATIVE_TRASHCAN: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/trashcan.ts");
const GSA_TRASH_ACTIONS: &str =
    include_str!("../../../components/gsa/src/web/pages/extras/TrashActions.jsx");
const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GVMD_MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const GVMD_REPORT_FORMATS: &str =
    include_str!("../../../components/gvmd/src/manage_sql_report_formats.c");
const GVMD_REPORT_FORMATS_HEADER: &str =
    include_str!("../../../components/gvmd/src/manage_sql_report_formats.h");

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
fn trashcan_restore_allowlists_remain_narrow_and_typed() {
    let gsa_restore = GSA_TRASHCAN
        .split_once("const LEGACY_RESTORE_RESOURCE_TYPES = {")
        .expect("typed GSA legacy restore map must exist")
        .1
        .split_once("} as const")
        .expect("typed GSA legacy restore map must terminate")
        .0;
    for (entity_type, resource_type) in [
        ("alert", "alert"),
        ("credential", "credential"),
        ("task", "task"),
    ] {
        assert!(
            gsa_restore.contains(&format!("{entity_type}: '{resource_type}'")),
            "GSA legacy restore map missing {entity_type} -> {resource_type}"
        );
    }
    assert_eq!(gsa_restore.matches(':').count(), 3);
    assert!(!gsa_restore.contains("reportformat"));

    let native_paths = GSA_NATIVE_TRASHCAN
        .split_once("const RESTORE_PATHS: Partial<Record<EntityType, string>> = {")
        .expect("native restore map must exist")
        .1
        .split_once("};")
        .expect("native restore map must terminate")
        .0;
    for entity_type in [
        "filter",
        "override",
        "portlist",
        "scanconfig",
        "scanner",
        "schedule",
        "tag",
        "target",
    ] {
        assert!(
            native_paths.contains(&format!("{entity_type}:")),
            "native restore map missing {entity_type}"
        );
    }
    assert_eq!(native_paths.matches(':').count(), 8);

    let allowlist = inherited_function(GSAD_GMP, "trashcan_restore_resource_type_is_supported");
    let restore_allowlist = allowlist
        .split_once("\nstatic gboolean\ntrashcan_delete_resource_type_is_supported")
        .expect("gsad restore allowlist must end before the delete allowlist")
        .0;
    for resource_type in ["alert", "credential", "task"] {
        assert!(
            restore_allowlist.contains(&format!("g_strcmp0 (resource_type, \"{resource_type}\")")),
            "gsad trashcan restore allowlist missing {resource_type}"
        );
    }
    assert_eq!(
        restore_allowlist
            .matches("g_strcmp0 (resource_type,")
            .count(),
        3
    );
    assert!(!restore_allowlist.contains("report_format"));

    let restore = inherited_function(GSAD_GMP, "restore_gmp");
    assert!(restore.contains("trashcan_restore_resource_type_is_supported (resource_type)"));
}

#[test]
fn trashcan_permanent_delete_allowlists_remain_narrow_and_fail_closed() {
    let gsa_delete = GSA_TRASHCAN
        .split_once("async delete(")
        .expect("GSA delete method must exist")
        .1
        .split_once("  async emptyPreview(")
        .expect("GSA delete method must end before empty preview")
        .0;
    assert!(gsa_delete.contains("supportsNativeTrashcanDelete(entityType)"));
    assert!(gsa_delete.contains("if (!canUseNativeApi(this.http))"));
    assert!(gsa_delete.contains("Native Trashcan permanent delete is unavailable"));
    assert!(gsa_delete.contains("Trashcan permanent delete is unavailable"));
    assert!(gsa_delete.contains("resource_type: resourceType"));
    assert!(gsa_delete.contains("[`${resourceType}_id`]: id"));
    assert!(!gsa_delete.contains("apiType("));
    assert!(!gsa_delete.contains("cmdApiType"));
    assert!(GSA_TRASHCAN.contains("reportformat: 'report_format'"));

    let delete_from_trash = inherited_function(GSAD_GMP, "delete_from_trash_gmp");
    assert!(
        delete_from_trash.contains("trashcan_delete_resource_type_is_supported (resource_type)")
    );
    let delete_allowlist =
        inherited_function(GSAD_GMP, "trashcan_delete_resource_type_is_supported");
    assert!(
        delete_allowlist.contains("trashcan_restore_resource_type_is_supported (resource_type)")
    );
    assert!(delete_allowlist.contains("g_strcmp0 (resource_type, \"report_format\")"));
    assert!(delete_from_trash.contains("Unsupported resource_type for the trash delete"));
    assert!(
        delete_from_trash
            .contains("delete_resource (connection, resource_type, credentials, params, TRUE")
    );
}

#[test]
fn retired_executable_report_formats_cannot_be_restored() {
    assert!(!GVMD_MANAGE_SQL.contains("restore_report_format (id)"));
    assert!(!GVMD_REPORT_FORMATS.contains("restore_report_format ("));
    assert!(!GVMD_REPORT_FORMATS_HEADER.contains("restore_report_format ("));

    let report_format_actions = GSA_TRASH_ACTIONS
        .split_once("reportformat: entity => {")
        .expect("report-format trash action policy must exist")
        .1
        .split_once("  },")
        .expect("report-format trash action policy must terminate")
        .0;
    assert!(report_format_actions.contains("restorable: false"));
    assert!(report_format_actions.contains("deletable: !entity.isInUse()"));
}

#[test]
fn restore_bridge_requires_type_and_stays_fail_closed() {
    let gsa_restore = GSA_TRASHCAN
        .split_once("async restore(")
        .expect("GSA restore method must exist")
        .1
        .split_once("  async delete(")
        .expect("GSA restore method must end before delete")
        .0;
    assert!(gsa_restore.contains("entityType: EntityType"));
    assert!(gsa_restore.contains("resource_type: resourceType"));
    assert!(gsa_restore.contains("if (!canUseNativeApi(this.http))"));
    assert!(gsa_restore.contains("Native Trashcan restore is unavailable"));
    assert!(gsa_restore.contains("Trashcan restore is unavailable"));

    let restore = inherited_function(GSAD_GMP, "restore_gmp");
    assert!(restore.contains("params_value (params, \"resource_type\")"));
    assert!(restore.contains("CHECK_VARIABLE_INVALID (resource_type, \"Restore\")"));
    assert!(restore.contains("Unsupported resource_type for the restore"));
    assert!(restore.contains("<restore"));
    assert!(restore.contains("id=\\\"%s\\\"/>"));
    assert!(
        !restore.contains("resource_type=\"%s\""),
        "declared compatibility type must not alter gvmd's generic UUID restore XML"
    );
}
