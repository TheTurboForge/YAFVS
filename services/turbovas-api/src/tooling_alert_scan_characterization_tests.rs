// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const START_ALERT_SCAN: &str =
    include_str!("../../../components/gvm-tools/scripts/start-alert-scan.gmp.py");

#[test]
fn inherited_start_alert_scan_selects_template_config_and_default_scanner() {
    for required in [
        "res = gmp.get_scan_configs(filter_string=\"rows=-1\")",
        "if config < 0 or config > 4:",
        "raise ValueError(\"Wrong config identifier. Choose between [0,4].\")",
        "template_abbreviation_mapper = {",
        "0: config_list[0]",
        "4: config_list[4]",
        "if template_abbreviation_mapper.get(config) == name:",
        "res = gmp.get_scanners()",
        "return scanner_ids[1]  # \"default scanner\"",
    ] {
        assert!(
            START_ALERT_SCAN.contains(required),
            "start-alert-scan config/scanner behavior missing {required}"
        );
    }
}

#[test]
fn inherited_start_alert_scan_creates_unique_target_and_optional_port_list() {
    for required in [
        "targets = gmp.get_targets(filter_string=target_name)",
        "existing_targets.append(str(target.find(\"name\").text))",
        "tmp_name = f\"{target_name} ({str(counter)})\"",
        "if not port_list_id:",
        "port_lists_tree = gmp.get_port_lists()",
        "existing_port_lists.append(str(plist.find(\"name\").text))",
        "port_list = gmp.create_port_list(name=port_list_name, port_range=ports)",
        "port_list_id = port_list.xpath(\"@id\")[0]",
        "res = gmp.create_target(target_name, hosts=hosts, port_list_id=port_list_id)",
    ] {
        assert!(
            START_ALERT_SCAN.contains(required),
            "start-alert-scan target/port-list behavior missing {required}"
        );
    }
}

#[test]
fn inherited_start_alert_scan_creates_email_alert_with_fixed_payload() {
    for required in [
        "alert_object = gmp.get_alerts(filter_string=f\"name={alert_name}\")",
        "if len(alert) == 0:",
        "gmp.create_alert(",
        "event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED",
        "event_data={\"status\": \"Done\"}",
        "condition=gmp.types.AlertCondition.ALWAYS",
        "method=gmp.types.AlertMethod.EMAIL",
        "\"2\": \"notice\"",
        "sender_email: \"from_address\"",
        "\"[OpenVAS-Manager] Task\": \"subject\"",
        "\"c402cc3e-b531-11e1-9163-406186ea4fc5\": \"notice_attach_format\"",
        "recipient_email: \"to_address\"",
        "alert_object = gmp.get_alerts(filter_string=f\"name={recipient_email}\")",
    ] {
        assert!(
            START_ALERT_SCAN.contains(required),
            "start-alert-scan alert payload behavior missing {required}"
        );
    }
}

#[test]
fn inherited_start_alert_scan_creates_and_starts_task_with_required_args() {
    for required in [
        "target = parser.add_mutually_exclusive_group(required=True)",
        "++target-id",
        "++target-name",
        "ports = parser.add_mutually_exclusive_group()",
        "++port-list-id",
        "++ports",
        "config = parser.add_mutually_exclusive_group()",
        "+C",
        "++scan-config-id",
        "++scanner-id",
        "+R",
        "required=True",
        "+S",
        "if script_args.alert_name is None:",
        "script_args.alert_name = script_args.recipient_email",
        "res = gmp.create_task(",
        "alert_ids=[alert_id]",
        "task_id = res.xpath(\"@id\")[0]",
        "gmp.start_task(task_id)",
        "gmp.stop_task(task_id=task_id)",
        "print(f\"Task started: {task_name}\\n\")",
    ] {
        assert!(
            START_ALERT_SCAN.contains(required),
            "start-alert-scan parser/task-start behavior missing {required}"
        );
    }
}
