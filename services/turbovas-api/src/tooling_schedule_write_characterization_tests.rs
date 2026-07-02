// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const CREATE_SCHEDULES_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/create-schedules-from-csv.gmp.py");
const BULK_MODIFY_SCHEDULES: &str =
    include_str!("../../../components/gvm-tools/scripts/bulk-modify-schedules.gmp.py");
const SEND_SCHEDULES: &str =
    include_str!("../../../components/gvm-tools/scripts/send-schedules.gmp.py");

#[test]
fn inherited_create_schedules_from_csv_maps_rows_to_schedule_create() {
    for required in [
        "gmp.get_schedules(filter_string=\"rows=-1, name=\" + schedule_name)",
        "content = csv.reader(csvFile, delimiter=\",\")",
        "sched_name = row[0]",
        "sched_tz = row[1]",
        "sched_ical = row[2]",
        "comment = f\"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}\"",
        "if schedule_id(gmp, sched_name):",
        "gmp.create_schedule(",
        "name=sched_name",
        "timezone=sched_tz",
        "icalendar=sched_ical",
        "comment=comment",
        "except GvmResponseError as gvmerr:",
        "error_and_exit(f\"Failed to read sched_file: {str(e)} (exit)\")",
        "error_and_exit(\"schedules file is empty (exit)\")",
    ] {
        assert!(
            CREATE_SCHEDULES_CSV.contains(required),
            "create-schedules-from-csv missing {required}"
        );
    }
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
fn inherited_send_schedules_imports_xml_schedules_after_protocol_check() {
    for required in [
        "major, minor = gmp.get_protocol_version()",
        "if major < 21 and minor < 5:",
        "xml_tree = create_xml_tree(xml_doc)",
        "for schedule in xml_tree.xpath(\"schedule\"):",
        "name = schedule.find(\"name\").text",
        "comment = schedule.find(\"comment\").text",
        "if comment is None:\n            comment = \"\"",
        "ical = schedule.find(\"icalendar\").text",
        "timezone = schedule.find(\"timezone\").text",
        "gmp.create_schedule(",
        "name=name, comment=comment, timezone=timezone, icalendar=ical",
    ] {
        assert!(
            SEND_SCHEDULES.contains(required),
            "send-schedules missing {required}"
        );
    }
}
