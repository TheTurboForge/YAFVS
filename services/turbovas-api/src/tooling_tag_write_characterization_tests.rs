// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const CREATE_TAGS_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/create-tags-from-csv.gmp.py");

#[test]
fn inherited_create_tags_from_csv_resolves_supported_resource_types_by_name() {
    for required in [
        "gmp.get_scan_configs(filter_string=\"rows=-1, name= \" + config_name)",
        "gmp.get_alerts(filter_string=\"rows=-1, name=\" + alert_name)",
        "gmp.get_credentials(filter_string=\"rows=-1, name=\" + credName)",
        "gmp.get_targets(filter_string=\"rows=-1, name=\" + targetName)",
        "gmp.get_tasks(filter_string=\"rows=-1, name=\" + taskName)",
        "gmp.get_tags(filter_string=\"rows=-1, name=\" + tagName)",
        "gmp.get_scanners(filter_string=\"rows=-1, name=\" + scanner_name)",
        "gmp.get_schedules(filter_string=\"rows=-1, name=\" + schedule_name)",
        "content = csv.reader(csvFile, delimiter=\",\")",
        "tagType = row[0]",
        "tagName = row[1]",
        "tagDescription = row[2]",
        "tagNameFull = tagName + \":\" + tagDescription + \":\" + tagType",
        "if tag_id(gmp, tagNameFull):",
    ] {
        assert!(
            CREATE_TAGS_CSV.contains(required),
            "create-tags-from-csv missing {required}"
        );
    }
}

#[test]
fn inherited_create_tags_from_csv_maps_resource_types_and_report_filter_branch() {
    for required in [
        "elif tagType.upper() == \"ALERT\":",
        "resource_type = gmp.types.EntityType.ALERT",
        "elif tagType.upper() == \"CONFIG\":",
        "resource_type = gmp.types.EntityType.SCAN_CONFIG",
        "elif tagType.upper() == \"CREDENTIAL\":",
        "resource_type = gmp.types.EntityType.CREDENTIAL",
        "elif tagType.upper() == \"REPORT\":",
        "filter = \"~\" + tagName",
        "resource_type = gmp.types.EntityType.REPORT",
        "elif tagType.upper() == \"SCANNER\":",
        "resource_type = gmp.types.EntityType.SCANNER",
        "elif tagType.upper() == \"SCHEDULE\":",
        "resource_type = gmp.types.EntityType.SCHEDULE",
        "elif tagType.upper() == \"TARGET\":",
        "resource_type = gmp.types.EntityType.TARGET",
        "elif tagType.upper() == \"TASK\":",
        "resource_type = gmp.types.EntityType.TASK",
        "Only alert, config, credential, report, scanner, schedule, target, and task supported",
    ] {
        assert!(
            CREATE_TAGS_CSV.contains(required),
            "create-tags-from-csv type mapping missing {required}"
        );
    }
}

#[test]
fn inherited_create_tags_from_csv_collects_up_to_ten_resource_columns() {
    for required in [
        "# Up to ten resources (rows 3 - 12)",
        "tagResources = []",
        "if len(row[3]) >= 1:",
        "tagResource = getUUID(gmp, row[3])",
        "if len(row[8]) >= 1:",
        "tagResource = getUUID(gmp, row[8])",
        "if len(row[9]) >= 1:\n                    tagResource = getUUID(gmp, row[9])\n                    tagResources.append(tagResource)\n                    tagResource = getUUID(gmp, row[10])",
        "if len(row[10]) >= 1:\n                    tagResources.append(tagResource)",
        "if len(row[11]) >= 1:",
        "tagResource = getUUID(gmp, row[11])",
        "if len(row[12]) >= 1:",
        "tagResource = getUUID(gmp, row[12])",
    ] {
        assert!(
            CREATE_TAGS_CSV.contains(required),
            "create-tags-from-csv resource column handling missing {required}"
        );
    }
}

#[test]
fn inherited_create_tags_from_csv_uses_filter_for_reports_and_ids_for_other_types() {
    for required in [
        "if tagType.upper() == \"REPORT\":",
        "resource_filter=filter",
        "else:",
        "resource_ids=tagResources",
        "comment = f\"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}\"",
        "name=tagNameFull",
        "comment=comment",
        "value=tagName",
        "resource_type=resource_type",
        "except GvmResponseError as gvmerr:",
        "error_and_exit(f\"Failed to read tag_csv_file: {str(e)} (exit)\")",
        "error_and_exit(\"tag file is empty (exit)\")",
    ] {
        assert!(
            CREATE_TAGS_CSV.contains(required),
            "create-tags-from-csv create-tag branch missing {required}"
        );
    }
}
