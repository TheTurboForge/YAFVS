// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const NVT_SCAN: &str = include_str!("../../../components/gvm-tools/scripts/nvt-scan.gmp.py");
const START_NVT_SCAN: &str =
    include_str!("../../../components/gvm-tools/scripts/start-nvt-scan.gmp.py");
const SCAN_NEW_SYSTEM: &str =
    include_str!("../../../components/gvm-tools/scripts/scan-new-system.gmp.py");

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
