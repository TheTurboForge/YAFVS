// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const LIST_USERS: &str = include_str!("../../../components/gvm-tools/scripts/list-users.gmp.py");

#[test]
fn inherited_list_users_fetches_all_users_and_prints_name_id_table() {
    for required in [
        "response_xml = gmp.get_users(filter_string=\"rows=-1\")",
        "users_xml = response_xml.xpath(\"user\")",
        "heading = [\"#\", \"Name\", \"Id\"]",
        "print(\"Listing users.\\n\")",
        "for user in users_xml:",
        "numberRows = numberRows + 1",
        "rowNumber = str(numberRows)",
        "name = \"\".join(user.xpath(\"name/text()\"))",
        "user_id = user.get(\"id\")",
        "rows.append([rowNumber, name, user_id])",
        "print(Table(heading=heading, rows=rows))",
    ] {
        assert!(
            LIST_USERS.contains(required),
            "list-users missing {required}"
        );
    }
}
