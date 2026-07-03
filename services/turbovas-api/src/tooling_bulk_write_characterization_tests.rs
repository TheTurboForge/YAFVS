// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const CREATE_TARGETS_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/create-targets-from-csv.gmp.py");
const CREATE_TASKS_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/create-tasks-from-csv.gmp.py");
const UPDATE_TASK_TARGET: &str =
    include_str!("../../../components/gvm-tools/scripts/update-task-target.gmp.py");

#[test]
fn inherited_create_targets_from_csv_maps_rows_to_target_credentials_and_alive_test() {
    for required in [
        "ports.set_defaults(\n        port_list_id=\"730ef368-57e2-11e1-a90f-406186ea4fc5\"",
        "gmp.get_credentials(filter_string=\"rows=-1, name=\" + credName)",
        "gmp.get_targets(filter_string=\"rows=-1, name=\" + targetName)",
        "content = csv.reader(csvFile, delimiter=\",\")",
        "name = row[0]",
        "hosts = [row[1]]",
        "smbCred = credential_id(gmp, row[2])",
        "sshCred = credential_id(gmp, row[3])",
        "aliveTest = row[6]",
        "aliveTest = \"Scan Config Default\"",
        "alive_test = gmp.types.AliveTest((aliveTest))",
        "if target_id(gmp, name):",
        "gmp.create_target(",
        "port_list_id=port_list_id",
        "smb_credential_id=smbCred",
        "ssh_credential_id=sshCred",
        "alive_test=alive_test",
        "except GvmResponseError as gvmerr:",
        "error_and_exit(f\"Failed to read target_csv_file: {str(e)} (exit)\")",
        "error_and_exit(\"Host file is empty (exit)\")",
    ] {
        assert!(
            CREATE_TARGETS_CSV.contains(required),
            "create-targets-from-csv missing {required}"
        );
    }
}

#[test]
fn inherited_create_tasks_from_csv_resolves_references_ordering_alerts_and_duplicate_names() {
    for required in [
        "gmp.get_scan_configs(filter_string=f'rows=-1, name=\"{config_name}\"')",
        "gmp.get_alerts(filter_string=f'rows=-1, name=\"{alert_name}\"')",
        "gmp.get_targets(filter_string=f'rows=-1, name=\"{target_name}\"')",
        "gmp.get_scanners(filter_string=f'rows=-1, name=\"{scanner_name}\"')",
        "gmp.get_schedules(filter_string=f'rows=-1, name=\"{schedule_name}\"')",
        "gmp.get_tasks(filter_string=f'rows=-1, name=\"{taskName}\"')",
        "content = csv.reader(csvFile, delimiter=\",\")",
        "name = row[0]",
        "targetId = target_id(gmp, row[1])",
        "scannerId = scanner_id(gmp, row[2])",
        "configId = config_id(gmp, row[3])",
        "scheduleId = schedule_id(gmp, row[4])",
        "newOrder = row[5].upper()",
        "gmp.types.HostsOrdering.RANDOM",
        "gmp.types.HostsOrdering.SEQUENTIAL",
        "gmp.types.HostsOrdering.REVERSE",
        "if len(row[10]) > 1:",
        "if task_id(gmp, name):",
        "gmp.create_task(",
        "hosts_ordering=scanOrder",
        "schedule_id=scheduleId",
        "alert_ids=alerts",
        "except GvmResponseError as gvmerr:",
        "error_and_exit(f\"Failed to read task_csv_file: {str(e)} (exit)\")",
    ] {
        assert!(
            CREATE_TASKS_CSV.contains(required),
            "create-tasks-from-csv missing {required}"
        );
    }
}

#[test]
fn inherited_update_task_target_clones_old_target_rebinds_task_and_deletes_unused_old_target() {
    for required in [
        "hosts_args = parser.add_mutually_exclusive_group()",
        "keywords = {\"hosts\": host_list}",
        "This target was automatically modified:",
        "old_target = gmp.get_target(target_id=old_target_id)[0]",
        "objects = (\"reverse_lookup_only\", \"reverse_lookup_unify\", \"name\")",
        "old_target.xpath(f\"{obj}/text()\")[0]",
        "if var == \"0\":\n            var = \"\"",
        "old_target.xpath(\"port_list/@id\")[0]",
        "keywords[\"name\"] += \"_copy\"",
        "new_target_id = gmp.create_target(**keywords).xpath(\"@id\")[0]",
        "gmp.modify_task(task_id=task_id, target_id=new_target_id)",
        "target = gmp.get_target(target_id=target_id)[0]",
        "if \"0\" in target.xpath(\"in_use/text()\"):",
        "gmp.delete_target(target_id=target_id)",
        "task = gmp.get_task(task_id=task_id)[1]",
        "old_target_id = task.xpath(\"target/@id\")[0]",
        "error_and_exit(\"The given task doesn't have an existing target.\")",
    ] {
        assert!(
            UPDATE_TASK_TARGET.contains(required),
            "update-task-target missing {required}"
        );
    }
}
