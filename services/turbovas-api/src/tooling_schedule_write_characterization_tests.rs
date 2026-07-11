// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const BULK_MODIFY_SCHEDULES: &str =
    include_str!("../../../components/gvm-tools/scripts/bulk-modify-schedules.gmp.py");
const TURBOVASCTL: &str = include_str!("../../../tools/turbovasctl");

#[test]
fn inherited_create_schedules_from_csv_script_is_retired() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/gvm-tools/scripts/create-schedules-from-csv.gmp.py");
    assert!(
        !script.is_file(),
        "retired schedule CSV script still exists: {script:?}"
    );
}

#[test]
fn inherited_bulk_modify_schedules_preserves_existing_fields_when_args_empty() {
    for required in [
        "get_response = gmp.get_schedules(filter_string=filter_term)",
        "schedules = get_response.findall(\"schedule\")",
        "uuid = schedule.attrib[\"id\"]",
        "name = schedule.find(\"name\").text",
        "comment = schedule.find(\"comment\").text",
        "if new_timezone:",
        "timezone = schedule.find(\"timezone\").text",
        "if new_icalendar:",
        "icalendar = schedule.find(\"icalendar\").text",
        "gmp.modify_schedule(",
        "name=name",
        "comment=comment",
        "timezone=timezone",
        "icalendar=icalendar",
    ] {
        assert!(
            BULK_MODIFY_SCHEDULES.contains(required),
            "bulk-modify-schedules missing {required}"
        );
    }
}

#[test]
fn inherited_send_schedules_xml_import_is_retired_for_guarded_native_tooling() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/gvm-tools/scripts/send-schedules.gmp.py");
    assert!(
        !script.is_file(),
        "retired XML schedule script still exists: {script:?}"
    );
    for required in [
        "def load_native_schedule_xml_rows",
        "ET.parse(xml_file).getroot()",
        "root.findall(\"schedule\")",
        "def command_native_schedules_from_xml",
        "native-schedules-from-xml",
        "--allow-write-control",
        "native_schedule_csv_safe_summary",
    ] {
        assert!(
            TURBOVASCTL.contains(required),
            "native XML schedule import missing {required}"
        );
    }
}
