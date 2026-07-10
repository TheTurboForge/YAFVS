// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const UPDATE_TASK_TARGET: &str =
    include_str!("../../../components/gvm-tools/scripts/update-task-target.gmp.py");

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
