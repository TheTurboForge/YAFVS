// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::Method;
use serde_json::json;

use crate::direct_api::direct_api_v1_method_is_allowed;
use crate::scan_config_families::ensure_scan_config_family_nvts_exist;
use crate::scan_config_payloads::{
    ScanConfigFamilyNvtItem, ScanConfigFamilyNvtsPayload, ScanConfigNvtPreference,
    ScanConfigPreferenceNvt, ScanConfigPreferences, ScanConfigScannerPreference,
    redact_scan_config_preference_values,
};
use crate::scan_config_query_sql::{
    scan_config_families_exists_sql, scan_config_families_sql, scan_config_family_nvts_exists_sql,
    scan_config_family_nvts_sql, scan_config_preferences_sql,
};

const GMP: &str = include_str!("../../../components/gvmd/src/gmp.c");
const GMP_CONFIGS: &str = include_str!("../../../components/gvmd/src/gmp_configs.c");
const MANAGE_SQL: &str = include_str!("../../../components/gvmd/src/manage_sql.c");
const MANAGE_SQL_CONFIGS: &str = include_str!("../../../components/gvmd/src/manage_sql_configs.c");
const MANAGE_SQL_NVTS: &str = include_str!("../../../components/gvmd/src/manage_sql_nvts.c");
const OPENAPI: &str = include_str!("../../../api/openapi/turbovas-v1.yaml");
const READ_API_ROUTES: &str = include_str!("read_api_routes.rs");

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

fn openapi_schema_block(name: &str) -> String {
    let marker = format!("    {name}:");
    let start = OPENAPI
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} schema block must exist"));
    let tail = &OPENAPI[start..];
    tail.lines()
        .enumerate()
        .skip(1)
        .find_map(|(index, line)| {
            if line.starts_with("    ") && !line.starts_with("      ") && line.ends_with(':') {
                Some(tail.lines().take(index).collect::<Vec<_>>().join("\n"))
            } else {
                None
            }
        })
        .unwrap_or_else(|| tail.to_string())
}

#[test]
fn inherited_scan_config_create_surface_remains_import_broad_and_scan_only() {
    let parse_config_entity = inherited_function(GMP_CONFIGS, "parse_config_entity");
    for required in [
        "entity_child (config, \"nvt_selectors\")",
        "entity_child (config, \"preferences\")",
        "Preference in an OpenVAS config:",
        "Scanner preference (for OpenVAS or OSP configs):",
        "Use directly from imported config.",
    ] {
        assert!(
            parse_config_entity.contains(required),
            "parse_config_entity missing {required}"
        );
    }

    let create_config_run = inherited_function(GMP_CONFIGS, "create_config_run");
    for required in [
        "get_configs_response = entity_child (entity, \"get_configs_response\")",
        "entity_child (get_configs_response, \"config\")",
        "usage_type = entity_child (entity, \"usage_type\")",
        "parse_config_entity (config, NULL, &import_name, &comment,",
        "create_config (NULL,                  /* Generate a UUID. */",
        "copy = entity_child (entity, \"copy\")",
        "copy_config (entity_text (name)",
    ] {
        assert!(
            create_config_run.contains(required),
            "create_config_run missing {required}"
        );
    }

    let create_config_internal = inherited_function(MANAGE_SQL_CONFIGS, "create_config_internal");
    for required in [
        "acl_user_may (\"create_config\")",
        "INSERT INTO configs (uuid, name, owner, nvt_selector, comment,",
        "insert_nvt_selectors (selector_uuid, selectors, allow_errors)",
        "config_insert_preferences (*config, preferences)",
        "update_config_caches (*config)",
        "actual_usage_type = \"scan\"",
        "MANAGE_NVT_SELECTOR_UUID_ALL",
    ] {
        assert!(
            create_config_internal.contains(required),
            "create_config_internal missing {required}"
        );
    }

    let copy_config = inherited_function(MANAGE_SQL_CONFIGS, "copy_config");
    for required in [
        "copy_resource_lock (\"config\", name, comment, config_id",
        "UPDATE configs SET predefined = 0",
        "INSERT INTO config_preferences (config, type, name, value,",
        "UPDATE configs SET nvt_selector = make_uuid ()",
        "UPDATE configs SET usage_type = 'scan'",
        "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)",
        "sql_commit ()",
    ] {
        assert!(
            copy_config.contains(required),
            "copy_config missing {required}"
        );
    }
}

#[test]
fn inherited_scan_config_modify_surface_stays_task_gated_and_rewrites_selectors_and_preferences() {
    let modify_config_run = inherited_function(GMP_CONFIGS, "modify_config_run");
    for required in [
        "acl_user_may (\"modify_config\")",
        "config_predefined_uuid (config_id)",
        "manage_modify_config_start (config_id, &config)",
        "modify_config_handle_basic_fields",
        "modify_config_handle_family_selection",
        "modify_config_handle_nvt_selection",
        "modify_config_handle_preference",
        "manage_modify_config_cancel ()",
        "manage_modify_config_commit ()",
        "log_event (\"config\", \"Scan Config\", config_id, \"modified\")",
    ] {
        assert!(
            modify_config_run.contains(required),
            "modify_config_run missing {required}"
        );
    }

    let modify_basic_fields = inherited_function(GMP_CONFIGS, "modify_config_handle_basic_fields");
    for required in [
        "manage_set_config (config, name, comment)",
        "Name must be unique",
        "XML_INTERNAL_ERROR (\"modify_config\")",
    ] {
        assert!(
            modify_basic_fields.contains(required),
            "modify_config_handle_basic_fields missing {required}"
        );
    }

    let modify_family_selection =
        inherited_function(GMP_CONFIGS, "modify_config_handle_family_selection");
    for required in [
        "manage_set_config_families",
        "Config is in use",
        "Family &quot;%s&quot; must be growing",
    ] {
        assert!(
            modify_family_selection.contains(required),
            "modify_config_handle_family_selection missing {required}"
        );
    }

    let modify_nvt_selection =
        inherited_function(GMP_CONFIGS, "modify_config_handle_nvt_selection");
    for required in [
        "manage_set_config_nvts",
        "Config is in use",
        "Attempt to modify NVT in whole-only family %s",
    ] {
        assert!(
            modify_nvt_selection.contains(required),
            "modify_config_handle_nvt_selection missing {required}"
        );
    }

    let modify_preference = inherited_function(GMP_CONFIGS, "modify_config_handle_preference");
    for required in [
        "manage_set_config_preference",
        "Config is in use",
        "Empty radio value for preference %s",
    ] {
        assert!(
            modify_preference.contains(required),
            "modify_config_handle_preference missing {required}"
        );
    }

    let manage_modify_config_start =
        inherited_function(MANAGE_SQL_CONFIGS, "manage_modify_config_start");
    for required in [
        "sql_begin_immediate ()",
        "find_config_with_permission (config_id, config_out, \"modify_config\")",
        "sql_rollback ()",
    ] {
        assert!(
            manage_modify_config_start.contains(required),
            "manage_modify_config_start missing {required}"
        );
    }

    let manage_set_config_families =
        inherited_function(MANAGE_SQL_CONFIGS, "manage_set_config_families");
    for required in [
        "SELECT count(*) FROM tasks",
        "config_families_growing (config)",
        "nvt_selector_remove (quoted_selector",
        "nvt_selector_add (quoted_selector",
        "UPDATE configs SET nvt_count = nvt_count - %i + %i",
        "family_count = family_count + %i",
        "nvts_growing = %i",
        "modification_time = m_now ()",
    ] {
        assert!(
            manage_set_config_families.contains(required),
            "manage_set_config_families missing {required}"
        );
    }

    let manage_set_config_nvts = inherited_function(MANAGE_SQL_CONFIGS, "manage_set_config_nvts");
    for required in [
        "family_whole_only (family)",
        "SELECT count(*) FROM tasks",
        "nvt_selector_family_growing (selector",
        "DELETE FROM nvt_selectors",
        "INSERT INTO nvt_selectors",
        "UPDATE configs SET family_count = family_count + %i",
        "nvt_count = nvt_count - %i",
        "MAX (new_nvt_count, 0)",
        "modification_time = m_now ()",
    ] {
        assert!(
            manage_set_config_nvts.contains(required),
            "manage_set_config_nvts missing {required}"
        );
    }

    let manage_set_config_preference =
        inherited_function(MANAGE_SQL_CONFIGS, "manage_set_config_preference");
    for required in [
        "SELECT count(*) FROM tasks",
        "modify_config_preference (config, nvt, name, value_64)",
        "DELETE FROM config_preferences",
    ] {
        assert!(
            manage_set_config_preference.contains(required),
            "manage_set_config_preference missing {required}"
        );
    }

    let modify_config_preference =
        inherited_function(MANAGE_SQL_CONFIGS, "modify_config_preference");
    for required in [
        "g_base64_decode (value_64",
        "DELETE FROM config_preferences",
        "INSERT INTO config_preferences",
    ] {
        assert!(
            modify_config_preference.contains(required),
            "modify_config_preference missing {required}"
        );
    }
}

#[test]
fn inherited_scan_config_delete_and_restore_remain_trash_permissions_tags_and_task_rebinding() {
    let delete_config = inherited_function(MANAGE_SQL_CONFIGS, "delete_config");
    for required in [
        "acl_user_may (\"delete_config\")",
        "find_config_with_permission (config_id, &config, \"delete_config\")",
        "find_trash (\"config\", config_id, &config)",
        "SELECT count(*) FROM tasks",
        "config_location = ",
        "INSERT INTO configs_trash",
        "INSERT INTO config_preferences_trash",
        "UPDATE tasks",
        "permissions_set_locations (\"config\"",
        "tags_set_locations (\"config\"",
        "permissions_set_orphans (\"config\"",
        "tags_remove_resource (\"config\"",
        "DELETE FROM nvt_selectors",
        "DELETE FROM config_preferences",
        "DELETE FROM configs",
    ] {
        assert!(
            delete_config.contains(required),
            "delete_config missing {required}"
        );
    }

    let manage_restore = inherited_function(MANAGE_SQL, "manage_restore");
    for required in [
        "acl_user_may (\"restore\")",
        "find_trash (\"config\", id, &resource)",
        "scanner_location = ",
        "LOCATION_TRASH",
        "SELECT count(*) FROM configs",
        "INSERT INTO configs",
        "INSERT INTO config_preferences",
        "UPDATE tasks",
        "permissions_set_locations (\"config\"",
        "tags_set_locations (\"config\"",
        "DELETE FROM config_preferences_trash",
        "DELETE FROM configs_trash",
        "sql_commit ()",
    ] {
        assert!(
            manage_restore.contains(required),
            "manage_restore missing {required}"
        );
    }
}

#[test]
fn native_direct_api_allows_scan_config_write_control_paths() {
    let detail_path = "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc";
    let restore_path = "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/restore";
    let hard_delete_path = "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/trash";
    for path in [
        "/api/v1/scan-configs",
        "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families",
    ] {
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, false),
            "GET {path} must remain allowlisted"
        );
        assert!(
            direct_api_v1_method_is_allowed(&Method::GET, path, true),
            "GET {path} must remain allowlisted under write control"
        );
        for method in [Method::DELETE, Method::PUT] {
            assert!(
                !direct_api_v1_method_is_allowed(&method, path, true),
                "{method} {path} must remain closed"
            );
        }
    }

    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scan-configs",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scan-configs",
        false
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families",
        true
    ));

    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        detail_path,
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        detail_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        detail_path,
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        detail_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/clone",
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/clone",
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::POST,
        restore_path,
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::POST,
        restore_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::DELETE,
        hard_delete_path,
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::DELETE,
        hard_delete_path,
        false
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families",
        true
    ));

    let list = openapi_path_block("/scan-configs");
    assert!(list.contains("get:"));
    assert!(list.contains("post:"));
    assert!(list.contains("x-turbovas-replaces: scan-config-create-from-base"));
    assert!(list.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!list.contains(
        "x-turbovas-inherited-still-owns: scan-config-preference-selector-mutation-import-export-blank-create"
    ));
    assert!(!list.contains("\n  patch:"));
    assert!(!list.contains("\n  delete:"));

    let detail = openapi_path_block("/scan-configs/{scan_config_id}");
    assert!(detail.contains("get:"));
    assert!(detail.contains("patch:"));
    assert!(detail.contains("delete:"));
    assert!(!detail.contains("\n  post:"));
    assert!(detail.contains("x-turbovas-exposure: direct-write"));
    assert!(detail.contains("x-turbovas-replaces: scan-config-family-mode-mutation"));
    assert!(detail.contains("x-turbovas-replaces: scan-config-trash-move"));
    assert!(detail.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!detail.contains(
        "x-turbovas-inherited-still-owns: scan-config-preference-selector-mutation-import-export-blank-create"
    ));

    let clone = openapi_path_block("/scan-configs/{scan_config_id}/clone");
    assert!(clone.contains("post:"));
    assert!(clone.contains("x-turbovas-replaces: scan-config-clone"));
    assert!(clone.contains("x-turbovas-safety-contract: write-control-v1"));
    assert!(!clone.contains(
        "x-turbovas-inherited-still-owns: scan-config-preference-selector-mutation-import-export-blank-create"
    ));

    let restore = openapi_path_block("/scan-configs/{scan_config_id}/restore");
    assert!(restore.contains("post:"));
    assert!(restore.contains("x-turbovas-replaces: scan-config-restore"));
    assert!(restore.contains("x-turbovas-safety-contract: write-control-v1"));

    let hard_delete = openapi_path_block("/scan-configs/{scan_config_id}/trash");
    assert!(hard_delete.contains("delete:"));
    assert!(hard_delete.contains("x-turbovas-replaces: scan-config-hard-delete"));
    assert!(hard_delete.contains("x-turbovas-safety-contract: write-control-v1"));

    let families = openapi_path_block("/scan-configs/{scan_config_id}/families");
    assert!(families.contains("get:"));
    assert!(!families.contains(
        "x-turbovas-inherited-still-owns: scan-config-preference-selector-mutation-import-export-blank-create"
    ));
    assert!(!families.contains("\n  post:"));
    assert!(!families.contains("\n  patch:"));
    assert!(!families.contains("\n  delete:"));
}

#[test]
fn native_scan_config_family_query_is_family_context_only() {
    let list_sql = scan_config_families_sql();
    let exists_sql = scan_config_families_exists_sql();
    let combined = format!("{list_sql}\n{exists_sql}");

    for required in [
        "WITH config_row AS (",
        "coalesce(c.nvt_selector, '') AS nvt_selector",
        "coalesce(c.family_count, 0)::bigint AS family_count",
        "coalesce(c.families_growing, 0)::integer AS families_growing",
        "FROM nvts n",
        "FROM nvt_selectors ns",
        "n.family != 'Credentials'",
        "ORDER BY lower(name), name",
        "SELECT EXISTS (SELECT 1 FROM configs",
    ] {
        assert!(
            combined.contains(required),
            "scan-config family SQL missing {required}"
        );
    }
    assert!(!list_sql.contains("all_mode_families"));
    assert!(!list_sql.contains("static_mode_families"));

    let combined_lower = combined.to_ascii_lowercase();
    for forbidden in ["insert ", "update ", "delete ", "grant ", "drop "] {
        assert!(
            !combined_lower.contains(forbidden),
            "scan-config family SQL must not include {forbidden}"
        );
    }
}

#[test]
fn inherited_scan_config_details_define_preference_filtering_fallback_and_redaction_anchors() {
    let get_configs = inherited_function(GMP, "handle_get_configs");
    for required in [
        "get_configs_data->preferences || get_configs_data->get.details",
        "init_nvt_preference_iterator (&prefs, NULL, TRUE)",
        "buffer_config_preference_xml (buffer, &prefs, config, 1)",
    ] {
        assert!(
            get_configs.contains(required),
            "get_configs missing {required}"
        );
    }

    let preference_iterator =
        inherited_function(MANAGE_SQL_CONFIGS, "init_nvt_preference_iterator");
    for required in [
        "name != 'cache_folder'",
        "name != 'include_folders'",
        "name != 'nasl_no_signature_check'",
        "name != 'network_targets'",
        "name != 'ntp_save_sessions'",
        "'server_info_%%'",
        "name != 'max_checks'",
        "name != 'max_hosts'",
    ] {
        assert!(
            preference_iterator.contains(required),
            "inherited preference filter missing {required}"
        );
    }

    let preference_xml = inherited_function(GMP, "buffer_config_preference_xml");
    for required in [
        "nvt_preference_iterator_config_value (prefs, config)",
        "nvt_preference_iterator_value (prefs)",
        "strcmp (type, \"password\") == 0",
        "<value></value>",
        "<default></default>",
    ] {
        assert!(
            preference_xml.contains(required),
            "inherited preference output missing {required}"
        );
    }
}

#[test]
fn native_scan_config_preference_sql_matches_inherited_read_contract() {
    let sql = scan_config_preferences_sql();
    for required in [
        "FROM config_preferences config_value",
        "config_value.config = c.internal_id",
        "config_value.name = np.name",
        "coalesce(cp.value, np.value, '')",
        "coalesce(np.value, '')",
        "ELSE coalesce(np.pref_name, '')",
        "END AS preference_name",
        "THEN 'Timeout'",
        "END AS preference_hr_name",
        "lower(coalesce(np.pref_type, '')) IN ('password', 'file')",
        "THEN ''",
        "cp.id IS NOT NULL AS configured",
        "np.name NOT ILIKE 'server_info_%'",
        "np.name != 'max_checks'",
        "np.name != 'max_hosts'",
        "ORDER BY np.name ASC",
    ] {
        assert!(sql.contains(required), "preference SQL missing {required}");
    }
    for hidden in [
        "cache_folder",
        "include_folders",
        "nasl_no_signature_check",
        "network_targets",
        "ntp_save_sessions",
    ] {
        assert!(sql.contains(hidden), "preference SQL must hide {hidden}");
    }
    assert!(sql.contains("JOIN nvt_preferences np ON true"));
    assert!(!sql.contains("config_only_preferences"));
    assert!(!sql.contains("UNION"));

    let sql_lower = sql.to_ascii_lowercase();
    for forbidden in ["insert ", "update ", "delete ", "grant ", "drop "] {
        assert!(
            !sql_lower.contains(forbidden),
            "preference SQL must not include {forbidden}"
        );
    }
}

#[test]
fn native_scan_config_preference_payload_is_exact_and_scalar() {
    let payload = ScanConfigPreferences {
        scanner: vec![ScanConfigScannerPreference {
            name: "safe_checks".into(),
            value: "yes".into(),
            default: "no".into(),
            configured: true,
            redacted: false,
        }],
        nvt: vec![ScanConfigNvtPreference {
            nvt: ScanConfigPreferenceNvt {
                oid: "1.3.6.1.4.1.25623.1.0.100001".into(),
                name: "Example NVT".into(),
            },
            id: 7,
            name: "Credential file".into(),
            hr_name: "Credential file".into(),
            preference_type: "file".into(),
            value: String::new(),
            default: String::new(),
            configured: true,
            redacted: true,
        }],
    };

    assert_eq!(
        serde_json::to_value(payload).expect("preferences serialize"),
        json!({
            "scanner": [{
                "name": "safe_checks",
                "value": "yes",
                "default": "no",
                "configured": true,
                "redacted": false
            }],
            "nvt": [{
                "nvt": {
                    "oid": "1.3.6.1.4.1.25623.1.0.100001",
                    "name": "Example NVT"
                },
                "id": 7,
                "name": "Credential file",
                "hr_name": "Credential file",
                "type": "file",
                "value": "",
                "default": "",
                "configured": true,
                "redacted": true
            }]
        })
    );
}

#[test]
fn native_scan_config_preference_redaction_never_preserves_sensitive_values() {
    for preference_type in ["password", "Password", "file", "FILE"] {
        assert_eq!(
            redact_scan_config_preference_values(
                preference_type,
                "configured-secret".into(),
                "feed-secret".into(),
            ),
            (String::new(), String::new(), true)
        );
    }
    assert_eq!(
        redact_scan_config_preference_values("entry", "configured".into(), "feed".into()),
        ("configured".into(), "feed".into(), false)
    );
}

#[test]
fn native_scan_config_timeout_and_radio_preferences_preserve_gsa_values() {
    let timeout = ScanConfigNvtPreference {
        nvt: ScanConfigPreferenceNvt {
            oid: "1.3.6.1.4.1.25623.1.0.100001".into(),
            name: "Example NVT".into(),
        },
        id: 0,
        name: "timeout".into(),
        hr_name: "Timeout".into(),
        preference_type: "entry".into(),
        value: "600".into(),
        default: "300".into(),
        configured: true,
        redacted: false,
    };
    let radio = ScanConfigNvtPreference {
        nvt: ScanConfigPreferenceNvt {
            oid: "1.3.6.1.4.1.25623.1.0.100002".into(),
            name: "Radio NVT".into(),
        },
        id: 4,
        name: "mode".into(),
        hr_name: "mode".into(),
        preference_type: "radio".into(),
        value: "enabled;disabled".into(),
        default: "disabled;enabled".into(),
        configured: false,
        redacted: false,
    };

    assert_eq!(
        serde_json::to_value(timeout).expect("timeout preference serializes"),
        json!({
            "nvt": {"oid": "1.3.6.1.4.1.25623.1.0.100001", "name": "Example NVT"},
            "id": 0,
            "name": "timeout",
            "hr_name": "Timeout",
            "type": "entry",
            "value": "600",
            "default": "300",
            "configured": true,
            "redacted": false
        })
    );
    let radio = serde_json::to_value(radio).expect("radio preference serializes");
    assert_eq!(radio["value"], "enabled;disabled");
    assert_eq!(radio["default"], "disabled;enabled");
    assert_eq!(radio["configured"], false);
}

#[test]
fn inherited_and_native_family_nvt_selection_cover_growing_and_static_representations() {
    let inherited = inherited_function(MANAGE_SQL_NVTS, "select_config_nvts");
    for required in [
        "config_nvts_growing (config)",
        "config_families_growing (config)",
        "nvt_selectors.exclude = 1",
        "nvt_selectors.exclude = 0",
        "NVT_SELECTOR_TYPE_FAMILY",
        "NVT_SELECTOR_TYPE_NVT",
        "The number of NVT's is static",
    ] {
        assert!(
            inherited.contains(required),
            "inherited selector source missing {required}"
        );
    }

    let sql = scan_config_family_nvts_sql();
    for required in [
        "coalesce(c.nvts_growing, 0)::integer AS nvts_growing",
        "WHEN c.nvts_growing = 0 THEN 0",
        "WHEN c.families_growing <> 0 THEN",
        "ns.type = 1",
        "ns.type = 2",
        "ns.exclude = 1",
        "ns.exclude = 0",
        "WHEN f.growing <> 0 THEN NOT EXISTS",
        "JOIN nvts n ON n.family = $2",
        "n.cvss_base::double precision",
        "END AS selected",
    ] {
        assert!(sql.contains(required), "family NVT SQL missing {required}");
    }

    let combined = format!("{sql}\n{}", scan_config_family_nvts_exists_sql());
    let combined_lower = combined.to_ascii_lowercase();
    for forbidden in ["insert ", "update ", "delete ", "grant ", "drop "] {
        assert!(
            !combined_lower.contains(forbidden),
            "family NVT SQL must not include {forbidden}"
        );
    }
}

#[test]
fn native_scan_config_family_nvt_payload_and_not_found_contract_are_exact() {
    let payload = ScanConfigFamilyNvtsPayload {
        scan_config_id: "12345678-1234-1234-1234-123456789abc".into(),
        family: "General".into(),
        items: vec![ScanConfigFamilyNvtItem {
            oid: "1.3.6.1.4.1.25623.1.0.100001".into(),
            name: "Example NVT".into(),
            severity: 7.5,
            selected: true,
        }],
    };
    assert_eq!(
        serde_json::to_value(payload).expect("family NVT payload serializes"),
        json!({
            "scan_config_id": "12345678-1234-1234-1234-123456789abc",
            "family": "General",
            "items": [{
                "oid": "1.3.6.1.4.1.25623.1.0.100001",
                "name": "Example NVT",
                "severity": 7.5,
                "selected": true
            }]
        })
    );

    assert!(ensure_scan_config_family_nvts_exist(true, true).is_ok());
    assert!(matches!(
        ensure_scan_config_family_nvts_exist(false, true),
        Err(crate::errors::ApiError::NotFound)
    ));
    assert!(matches!(
        ensure_scan_config_family_nvts_exist(true, false),
        Err(crate::errors::ApiError::NotFound)
    ));
}

#[test]
fn native_scan_config_family_nvt_routes_and_openapi_are_read_and_guarded_write() {
    let direct_path =
        "/api/v1/scan-configs/12345678-1234-1234-1234-123456789abc/families/Port%20scanners/nvts";
    assert!(
        READ_API_ROUTES.contains("\"/api/v1/scan-configs/:scan_config_id/families/:family/nvts\"")
    );
    assert!(READ_API_ROUTES.contains("get(scan_config_asset_family_nvts)"));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        direct_path,
        false
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::GET,
        direct_path,
        true
    ));
    assert!(direct_api_v1_method_is_allowed(
        &Method::PATCH,
        direct_path,
        true
    ));
    assert!(!direct_api_v1_method_is_allowed(
        &Method::PATCH,
        direct_path,
        false
    ));
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        assert!(!direct_api_v1_method_is_allowed(&method, direct_path, true));
    }

    let detail = openapi_path_block("/scan-configs/{scan_config_id}");
    assert!(detail.contains(
        "x-turbovas-replaces: scan-config-detail-info-tags-task-backlinks-and-preferences-read"
    ));
    assert!(detail.contains(
        "x-turbovas-inherited-still-owns: scan-config-preference-mutations-import-xml-export-and-blank-create"
    ));

    let path = openapi_path_block("/scan-configs/{scan_config_id}/families/{family}/nvts");
    for required in [
        "get:",
        "operationId: getScanConfigsByScanConfigIdFamiliesByFamilyNvts",
        "x-turbovas-direct: true",
        "x-turbovas-exposure: direct-read",
        "x-turbovas-maturity: live-read",
        "x-turbovas-replaces: scan-config-family-nvt-selection-read",
        "#/components/parameters/ScanConfigFamilyName",
        "#/components/schemas/ScanConfigFamilyNvts",
        "'404':",
        "patch:",
        "operationId: patchScanConfigsByScanConfigIdFamiliesByFamilyNvts",
        "x-turbovas-replaces: scan-config-family-nvt-selection-mutation",
        "x-turbovas-safety-contract: write-control-v1",
        "#/components/schemas/ScanConfigFamilyNvtsPatchRequest",
        "'204':",
        "'409':",
    ] {
        assert!(
            path.contains(required),
            "family NVT OpenAPI missing {required}"
        );
    }
    for forbidden in ["\n    post:", "\n    put:", "\n    delete:"] {
        assert!(
            !path.contains(forbidden),
            "family NVT path contains {forbidden}"
        );
    }
    assert_eq!(
        OPENAPI
            .matches("operationId: getScanConfigsByScanConfigIdFamiliesByFamilyNvts")
            .count(),
        1
    );
    let family_parameter = openapi_schema_block("ScanConfigFamilyName");
    assert!(family_parameter.contains("maxLength: 256"));
    assert!(!family_parameter.contains("maxLength: 512"));

    for schema in [
        "ScanConfigPreferences",
        "ScanConfigScannerPreference",
        "ScanConfigPreferenceNvt",
        "ScanConfigNvtPreference",
        "ScanConfigFamilyNvt",
        "ScanConfigFamilyNvts",
        "ScanConfigFamilyNvtsPatchRequest",
        "ScanConfigFamilyNvtSelectionChange",
    ] {
        let block = openapi_schema_block(schema);
        assert!(
            block.contains("additionalProperties: false"),
            "{schema} must reject undeclared fields"
        );
    }
    let detail_schema = openapi_schema_block("ScanConfigAssetDetail");
    assert!(detail_schema.contains("required: [preferences]"));
    assert!(detail_schema.contains("#/components/schemas/ScanConfigPreferences"));
    let patch_schema = openapi_schema_block("ScanConfigFamilyNvtsPatchRequest");
    assert!(patch_schema.contains("maxItems: 1024"));

    for schema in ["ScanConfigScannerPreference", "ScanConfigNvtPreference"] {
        let block = openapi_schema_block(schema);
        assert!(block.contains("configured"));
        assert!(block.contains("explicit override row"));
        assert!(block.contains("redacted"));
    }
}
