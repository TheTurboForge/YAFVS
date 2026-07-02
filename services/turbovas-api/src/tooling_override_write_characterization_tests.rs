// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const DELETE_OVERRIDES_BY_FILTER: &str =
    include_str!("../../../components/gvm-tools/scripts/delete-overrides-by-filter.gmp.py");

#[test]
fn inherited_delete_overrides_by_filter_filters_deletes_and_sleeps_between_rows() {
    for required in [
        "if len_args != 1:",
        "filter_value = args.script[1]",
        "filters = gmp.get_overrides(filter_string=filter_value)",
        "if not filters.xpath(\"override\"):",
        "print(f\"No overrides with filter: {filter_value}\")",
        "for f_id in filters.xpath(\"override/@id\"):",
        "print(f\"Delete override: {f_id}\", end=\"\")",
        "res = gmp.delete_override(f_id)",
        "if \"OK\" in res.xpath(\"@status_text\")[0]:",
        "print(\" OK\")",
        "print(\" ERROR\")",
        "time.sleep(60)",
    ] {
        assert!(
            DELETE_OVERRIDES_BY_FILTER.contains(required),
            "delete-overrides-by-filter missing {required}"
        );
    }
}
