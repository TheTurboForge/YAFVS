// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const SEND_TASKS: &str = include_str!("../../../components/gvm-tools/scripts/send-tasks.gmp.py");

#[test]
fn inherited_send_tasks_interactively_resolves_required_config_scanner_and_target() {
    for required in [
        "options_dict[\"config\"] = gmp.get_scan_configs()",
        "options_dict[\"scanner\"] = gmp.get_scanners()",
        "options_dict[\"target\"] = gmp.get_targets()",
        "object_id = task.find(option_key).get(\"id\")",
        "if object_id in object_dict.values():",
        "keywords[f\"{option_key}_id\"] = object_id",
        "response = yes_or_no(",
        "Would you like to select from available options, or exit",
        "print(f\"{option_key.capitalize()} options:\")",
        "answer = numerical_option(",
        "keywords[f\"{option_key}_id\"] = object_dict[object_list[answer - 1]]",
        "error_and_exit(",
        "Failed to detect {option_key}_id",
    ] {
        assert!(
            SEND_TASKS.contains(required),
            "send-tasks interactive option handling missing {required}"
        );
    }
}

#[test]
fn inherited_send_tasks_imports_xml_tasks_with_schedule_preferences_and_created_ids() {
    for required in [
        "xml_tree = create_xml_tree(script_args.xml)",
        "task_xml_elements = xml_tree.xpath(\"task\")",
        "error_and_exit(\"No tasks found.\")",
        "keywords = {\"name\": task.find(\"name\").text}",
        "keywords[\"comment\"] = task.find(\"comment\").text",
        "keywords[\"schedule_periods\"] = int(task.find(\"schedule_periods\").text)",
        "keywords[\"schedule_id\"] = task.xpath(\"schedule/@id\")[0]",
        "for preference in task.xpath(\"preferences/preference\"):",
        "scanner_name_list.append(preference.find(\"scanner_name\").text)",
        "value_list.append(preference.find(\"value\").text)",
        "preferences[\"scanner_name\"] = scanner_name_list",
        "preferences[\"value\"] = value_list",
        "keywords[\"preferences\"] = preferences",
        "new_task = gmp.create_task(**keywords)",
        "tasks.append(new_task.xpath(\"//@id\")[0])",
    ] {
        assert!(
            SEND_TASKS.contains(required),
            "send-tasks task import mapping missing {required}"
        );
    }
}

#[test]
fn inherited_send_tasks_requires_xml_file_argument_and_prints_created_task_ids() {
    for required in [
        "parser.add_argument(",
        "\"+x\"",
        "\"++xml-file\"",
        "dest=\"xml\"",
        "required=True",
        "print(\"\\nSending task(s)...\")",
        "for task in tasks:\n        print(task)",
        "print(\"\\nTask(s) sent!\\n\")",
    ] {
        assert!(
            SEND_TASKS.contains(required),
            "send-tasks CLI/output behavior missing {required}"
        );
    }
}
