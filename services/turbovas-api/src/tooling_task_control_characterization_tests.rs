// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const NVT_SCAN: &str = include_str!("../../../components/gvm-tools/scripts/nvt-scan.gmp.py");
const START_NVT_SCAN: &str =
    include_str!("../../../components/gvm-tools/scripts/start-nvt-scan.gmp.py");
const SCAN_NEW_SYSTEM: &str =
    include_str!("../../../components/gvm-tools/scripts/scan-new-system.gmp.py");
const START_SCANS_FROM_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/start-scans-from-csv.py");
const STOP_SCANS_FROM_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/stop-scans-from-csv.py");
const STOP_ALL_SCANS: &str =
    include_str!("../../../components/gvm-tools/scripts/stop-all-scans.gmp.py");

#[test]
fn inherited_nvt_scan_creates_or_reuses_config_target_and_starts_default_scanner_task() {
    for required in [
        "if len_args != 2:",
        "copy_id = \"085569ce-73ed-11df-83c3-002264764cea\"",
        "config_name = nvt_oid",
        "gmp.create_scan_config(copy_id, config_name)",
        "gmp.get_scan_config_nvt(nvt_oid)",
        "gmp.modify_scan_config_set_nvt_selection(",
        "nvt_oids=[nvt_oid]",
        "family = \"Port scanners\"",
        "1.3.6.1.4.1.25623.1.0.14259",
        "1.3.6.1.4.1.25623.1.0.100315",
        "except GvmError:",
        "gmp.get_scan_configs(filter_string=f\"name={config_name}\")",
        "gmp.create_target(name, hosts=[name])",
        "gmp.get_targets(filter_string=f\"name={name} hosts={name}\")",
        "scanner_id = \"08b69003-5fc2-4037-a479-93b440211c73\"",
        "task_name = f\"{name}_{nvt_oid}_{date_time}\"",
        "gmp.create_task(",
        "gmp.start_task(task_id=task_id)",
    ] {
        assert!(NVT_SCAN.contains(required), "nvt-scan missing {required}");
    }
}
#[test]
fn inherited_start_nvt_scan_is_interactive_and_can_clone_config_target_and_choose_scanner() {
    for required in [
        "if len_args != 2:",
        "res = gmp.get_scan_configs()",
        "Choose your config or create new one",
        "chosen_config == \"n\"",
        "res = gmp.clone_scan_config(copy_id)",
        "gmp.get_scan_config_nvt(nvt_oid=nvt_oid)",
        "gmp.modify_scan_config(",
        "\"nvt_selection\"",
        "gmp.get_targets()",
        "chosen_target == \"n\"",
        "gmp.create_target(name, hosts=hosts.split(\",\"))",
        "res = gmp.get_scanners()",
        "Choose your scanner",
        "gmp.create_task(",
        "comment=task_comment",
        "gmp.start_task(task_id)",
    ] {
        assert!(
            START_NVT_SCAN.contains(required),
            "start-nvt-scan missing {required}"
        );
    }
}
#[test]
fn inherited_scan_new_system_creates_target_task_and_starts_full_fast_openvas_scan() {
    for required in [
        "if len_args != 2:",
        "name = f\"Suspect Host {ipaddress} {str(datetime.datetime.now())}\"",
        "gmp.create_target(",
        "hosts=[ipaddress]",
        "port_list_id=port_list_id",
        "name = f\"Scan Suspect Host {ipaddress}\"",
        "gmp.create_task(",
        "config_id=scan_config_id",
        "target_id=target_id",
        "scanner_id=scanner_id",
        "response = gmp.start_task(task_id)",
        "return response[0].text",
        "full_and_fast_scan_config_id = \"daba56c8-73ec-11df-a475-002264764cea\"",
        "openvas_scanner_id = \"08b69003-5fc2-4037-a479-93b440211c73\"",
    ] {
        assert!(
            SCAN_NEW_SYSTEM.contains(required),
            "scan-new-system missing {required}"
        );
    }
}

#[test]
fn inherited_csv_start_and_stop_scripts_resolve_task_names_with_status_filters() {
    for required in [
        "csv.reader(csvFile, delimiter=\",\")",
        "if len(row) == 0:",
        "continue",
        "except GvmResponseError as gvmerr:",
        "error_and_exit(f\"Failed to read task_file: {str(e)} (exit)\")",
    ] {
        assert!(
            START_SCANS_FROM_CSV.contains(required),
            "start-scans-from-csv missing shared behavior {required}"
        );
        assert!(
            STOP_SCANS_FROM_CSV.contains(required),
            "stop-scans-from-csv missing shared behavior {required}"
        );
    }

    for required in [
        "not status=Running",
        "not status=Requested",
        "status=Queued ",
        "and name=",
        "status_text = gmp.start_task(task_start).xpath(\"@status_text\")[",
        "is either in status Requested, Queued, Running",
    ] {
        assert!(
            START_SCANS_FROM_CSV.contains(required),
            "start-scans-from-csv missing {required}"
        );
    }
    for required in [
        "status=Running ",
        "or status=Requested ",
        "or status=Queued ",
        "and name=",
        "status_text = gmp.stop_task(task_stop).xpath(\"@status_text\")[0]",
        "if len(row) == 0:\n        error_and_exit(\"tasks file is empty (exit)\")",
    ] {
        assert!(
            STOP_SCANS_FROM_CSV.contains(required),
            "stop-scans-from-csv missing {required}"
        );
    }
}

#[test]
fn inherited_stop_all_scans_stops_running_requested_and_queued_tasks_by_id() {
    for required in [
        "filter_string=\"rows=-1 status=Running or status=Requested or status=Queued\"",
        "for task_id in tasks.xpath(\"task/@id\"):",
        "print(f\"Stopping task {task_id} ... \")",
        "status_text = gmp.stop_task(task_id).xpath(\"@status_text\")[0]",
        "except Exception as e:",
        "print(f\"{e=}\")",
    ] {
        assert!(
            STOP_ALL_SCANS.contains(required),
            "stop-all-scans missing {required}"
        );
    }
}
