// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const GSA_TRASHCAN: &str = include_str!("../../../components/gsa/src/gmp/commands/trashcan.ts");
const GSA_NATIVE_TRASHCAN: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/trashcan.ts");
const GSA_TRASHCAN_PAGE: &str =
    include_str!("../../../components/gsa/src/web/pages/trashcan/TrashCanPage.tsx");
const GSA_TRASH_ACTIONS: &str =
    include_str!("../../../components/gsa/src/web/pages/extras/TrashActions.jsx");
const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");
const GSAD_GMP_HEADER: &str = include_str!("../../../components/gsad/src/gsad_gmp.h");
const GSAD_VALIDATOR: &str = include_str!("../../../components/gsad/src/gsad_validator.c");
const GVMD_GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GVMD_GMP_GET: &str = include_str!("../../../components/gvmd/src/gmp_get.c");
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
fn trashcan_inventory_is_native_only_and_has_no_gmp_fallback() {
    let get_inventory = GSA_TRASHCAN
        .split_once("async get()")
        .expect("GSA Trashcan inventory method must exist")
        .1
        .split_once("\n  }\n}")
        .expect("GSA Trashcan inventory method must terminate")
        .0;
    assert!(get_inventory.contains("if (!canUseNativeApi(this.http))"));
    assert!(get_inventory.contains("Native Trashcan inventory is unavailable"));
    assert!(get_inventory.contains("fetchNativeTrashcanItems(this.http)"));
    assert!(!get_inventory.contains("httpGetWithTransform"));
    assert!(!GSA_TRASHCAN.contains("cmd: 'get_trash_"));
    assert!(!GSA_TRASHCAN.contains("Promise.allSettled"));
    assert!(!GSA_TRASHCAN.contains("get_tags_response"));
    assert!(!GSA_TRASHCAN.contains("failedRequests"));
    assert!(!GSA_TRASHCAN_PAGE.contains("failedRequests"));
    assert!(!GSA_TRASHCAN_PAGE.contains("showErrorNotification"));

    assert!(!GSAD_GMP.contains("GET_TRASH_RESOURCE"));
    for resource in [
        "alerts",
        "configs",
        "credentials",
        "filters",
        "overrides",
        "port_lists",
        "report_formats",
        "scanners",
        "schedules",
        "tags",
        "targets",
        "tasks",
    ] {
        let handler = format!("get_trash_{resource}_gmp");
        let dispatch = format!("ELSE (get_trash_{resource})");
        let validator = format!("|(get_trash_{resource})");
        assert!(!GSAD_GMP.contains(&handler), "gsad still defines {handler}");
        assert!(
            !GSAD_GMP_HEADER.contains(&handler),
            "gsad still declares {handler}"
        );
        assert!(
            !GSAD_GMP.contains(&dispatch),
            "gsad still dispatches {dispatch}"
        );
        assert!(
            !GSAD_VALIDATOR.contains(&validator),
            "gsad still accepts {validator}"
        );
    }
    assert!(!GSAD_GMP_HEADER.contains("get_trash_gmp"));

    let normalized_gvmd_gmp = GVMD_GMP.split_whitespace().collect::<Vec<_>>().join(" ");
    for (data, resource_type) in [
        ("get_alerts_data", "alert"),
        ("get_configs_data", "config"),
        ("get_credentials_data", "credential"),
        ("get_overrides_data", "override"),
        ("get_port_lists_data", "port_list"),
        ("get_scanners_data", "scanner"),
        ("get_schedules_data", "schedule"),
        ("get_tags_data", "tag"),
        ("get_targets_data", "target"),
        ("get_tasks_data", "task"),
    ] {
        let parser = format!(
            "get_data_parse_attributes (&{data}->get, \"{resource_type}\", attribute_names, attribute_values);"
        );
        assert!(
            normalized_gvmd_gmp.contains(&parser),
            "raw manager trash compatibility lost {resource_type} attribute parsing"
        );
    }
    assert!(!GVMD_GMP.contains("get_report_formats_data"));
    assert!(
        !GVMD_GMP.contains("get_filters_data"),
        "saved-filter trash inventory and lifecycle are native; GET_FILTERS must stay retired"
    );
    let normalized_gmp_get = GVMD_GMP_GET
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        normalized_gmp_get
            .contains("find_attribute (attribute_names, attribute_values, \"trash\", &attribute)")
    );
    assert!(normalized_gmp_get.contains("data->trash = strcmp (attribute, \"0\")"));
}

#[test]
fn trashcan_restore_allowlists_remain_narrow_and_typed() {
    assert!(!GSA_TRASHCAN.contains("LEGACY_RESTORE_RESOURCE_TYPES"));
    assert!(!GSA_TRASHCAN.contains("cmd: 'restore'"));

    let native_common_paths = GSA_NATIVE_TRASHCAN
        .split_once("const NATIVE_TRASH_PATHS: Partial<Record<EntityType, string>> = {")
        .expect("native common trash map must exist")
        .1
        .split_once("};")
        .expect("native common trash map must terminate")
        .0;
    for entity_type in [
        "alert",
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
            native_common_paths.contains(&format!("{entity_type}:")),
            "native common trash map missing {entity_type}"
        );
    }
    assert_eq!(native_common_paths.matches(':').count(), 9);

    let native_restore_paths = GSA_NATIVE_TRASHCAN
        .split_once("const RESTORE_PATHS: Partial<Record<EntityType, string>> = {")
        .expect("native restore map must exist")
        .1
        .split_once("};")
        .expect("native restore map must terminate")
        .0;
    assert!(native_restore_paths.contains("...NATIVE_TRASH_PATHS"));
    assert!(native_restore_paths.contains("credential: 'credentials'"));
    assert!(native_restore_paths.contains("task: 'tasks'"));
    assert_eq!(native_restore_paths.matches(':').count(), 2);
    assert!(!GSAD_GMP.contains("trashcan_restore_resource_type_is_supported"));
    assert!(!GSAD_GMP.contains("\nrestore_gmp ("));
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
    assert!(!gsa_delete.contains("resource_type"));
    assert!(!gsa_delete.contains("delete_from_trash"));
    assert!(!gsa_delete.contains("apiType("));
    assert!(!gsa_delete.contains("cmdApiType"));
    assert!(!GSA_TRASHCAN.contains("reportformat: 'report_format'"));

    let native_delete_paths = GSA_NATIVE_TRASHCAN
        .split_once("const DELETE_PATHS: Partial<Record<EntityType, string>> = {")
        .expect("native delete map must exist")
        .1
        .split_once("};")
        .expect("native delete map must terminate")
        .0;
    assert!(native_delete_paths.contains("...NATIVE_TRASH_PATHS"));
    assert!(native_delete_paths.contains("credential: 'credentials'"));
    assert!(native_delete_paths.contains("task: 'tasks'"));
    assert!(!GSAD_GMP.contains("delete_from_trash_gmp"));
    assert!(!GSAD_GMP.contains("trashcan_delete_resource_type_is_supported"));
    assert!(!GSAD_GMP.contains("ELSE (delete_from_trash)"));
    assert!(!GSAD_GMP_HEADER.contains("delete_from_trash_gmp"));
    assert!(!GSAD_VALIDATOR.contains("|(delete_from_trash)"));
}

#[test]
fn retired_executable_report_formats_have_no_individual_trash_lifecycle_actions() {
    assert!(!GVMD_GMP.contains("DELETE_REPORT_FORMAT"));
    assert!(!GVMD_GMP.contains("delete_report_format"));
    assert!(!GVMD_MANAGE_SQL.contains("restore_report_format (id)"));
    assert!(!GVMD_REPORT_FORMATS.contains("restore_report_format ("));
    assert!(!GVMD_REPORT_FORMATS_HEADER.contains("restore_report_format ("));

    let report_format_actions = GSA_TRASH_ACTIONS
        .split_once("reportformat: () => {")
        .expect("report-format trash action policy must exist")
        .1
        .split_once("  },")
        .expect("report-format trash action policy must terminate")
        .0;
    assert!(report_format_actions.contains("restorable: false"));
    assert!(report_format_actions.contains("deletable: false"));

    let owner_scoped_cleanup =
        inherited_function(GVMD_REPORT_FORMATS, "empty_trashcan_report_formats");
    for required in [
        "DELETE FROM report_format_param_options_trash",
        "DELETE FROM report_format_params_trash",
        "DELETE FROM report_formats_trash",
        "current_credentials.uuid",
        "report_format_trash_dir",
        "gvm_file_remove_recurse",
    ] {
        assert!(
            owner_scoped_cleanup.contains(required),
            "report-format trash cleanup missing {required}"
        );
    }
}

#[test]
fn retired_restore_bridge_stays_absent_and_native_restore_fails_closed() {
    let gsa_restore = GSA_TRASHCAN
        .split_once("async restore(")
        .expect("GSA restore method must exist")
        .1
        .split_once("  async delete(")
        .expect("GSA restore method must end before delete")
        .0;
    assert!(gsa_restore.contains("entityType: EntityType"));
    assert!(gsa_restore.contains("supportsNativeTrashcanRestore(entityType)"));
    assert!(gsa_restore.contains("restoreNativeTrashcanEntity(this.http, {id, entityType})"));
    assert!(gsa_restore.contains("if (!canUseNativeApi(this.http))"));
    assert!(gsa_restore.contains("Native Trashcan restore is unavailable"));
    assert!(gsa_restore.contains("Trashcan restore is unavailable"));
    assert!(!gsa_restore.contains("resource_type"));
    assert!(!gsa_restore.contains("cmd: 'restore'"));
    assert!(!GSAD_GMP.contains("\nrestore_gmp ("));
    assert!(!GSAD_GMP_HEADER.contains("restore_gmp"));
    assert!(!GSAD_VALIDATOR.contains("\"(restore)\""));
}
