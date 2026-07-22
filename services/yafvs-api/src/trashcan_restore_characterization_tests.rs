// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const GSA_TRASHCAN: &str = include_str!("../../../components/gsa/src/gmp/commands/trashcan.ts");
const GSA_NATIVE_TRASHCAN: &str =
    include_str!("../../../components/gsa/src/gmp/native-api/trashcan.ts");
const GSAD_GMP: &str = include_str!("../../../components/gsad/src/gsad_gmp.c");

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
        ("reportformat", "report_format"),
        ("task", "task"),
    ] {
        assert!(
            gsa_restore.contains(&format!("{entity_type}: '{resource_type}'")),
            "GSA legacy restore map missing {entity_type} -> {resource_type}"
        );
    }
    assert_eq!(gsa_restore.matches(':').count(), 4);

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

    let restore = inherited_function(GSAD_GMP, "restore_gmp");
    for resource_type in ["alert", "credential", "report_format", "task"] {
        assert!(
            restore.contains(&format!("g_strcmp0 (resource_type, \"{resource_type}\")")),
            "gsad restore allowlist missing {resource_type}"
        );
    }
    assert_eq!(restore.matches("g_strcmp0 (resource_type,").count(), 4);
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
