// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const SEND_TARGETS: &str =
    include_str!("../../../components/gvm-tools/scripts/send-targets.gmp.py");

#[test]
fn inherited_send_targets_imports_xml_targets_and_checks_credentials() {
    for required in [
        "xml_tree = create_xml_tree(xml_doc)",
        "for target in xml_tree.xpath(\"target\"):",
        "keywords[\"name\"] = target.find(\"name\").text",
        "keywords[\"hosts\"] = target.find(\"hosts\").text.split(\",\")",
        "exclude_hosts = target.find(\"exclude_hosts\").text",
        "keywords[\"exclude_hosts\"] = exclude_hosts.split(\",\")",
        "credentials = gmp.get_credentials()[0].xpath(\"//credential/@id\")",
        "credential_options = [",
        "\"ssh_credential\"",
        "\"smb_credential\"",
        "\"esxi_credential\"",
        "\"snmp_credential\"",
        "if cred_id not in credentials:",
        "response = yes_or_no(",
        "if response is False:",
        "sys.exit()",
        "keywords[key] = cred_id",
        "keywords[port_key] = elem_path.find(\"port\").text",
    ] {
        assert!(
            SEND_TARGETS.contains(required),
            "send-targets missing {required}"
        );
    }
}

#[test]
fn inherited_send_targets_maps_alive_reverse_port_list_and_creates_target() {
    for required in [
        "alive_test = gmp.types.AliveTest.from_string(target.find(\"alive_tests\").text)",
        "keywords[\"alive_test\"] = alive_test",
        "reverse_lookup_only = target.find(\"reverse_lookup_only\").text",
        "keywords[\"reverse_lookup_only\"] = 1",
        "reverse_lookup_unify = target.find(\"reverse_lookup_unify\").text",
        "keywords[\"reverse_lookup_unify\"] = 1",
        "port_range = target.find(\"port_range\")",
        "keywords[\"port_range\"] = port_range.text",
        "port_list = target.xpath(\"port_list/@id\")[0]",
        "keywords[\"port_list_id\"] = port_list",
        "print(keywords)",
        "gmp.create_target(**keywords)",
    ] {
        assert!(
            SEND_TARGETS.contains(required),
            "send-targets target creation mapping missing {required}"
        );
    }
}
