// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const EMPTY_TRASH: &str = include_str!("../../../components/gvm-tools/scripts/empty-trash.gmp.py");

#[test]
fn inherited_empty_trash_invokes_global_trashcan_empty_and_prints_status() {
    for required in [
        "print(\"Emptying Trash...\\n\")",
        "status_text = gmp.empty_trashcan().xpath(\"@status_text\")[0]",
        "print(status_text)",
        "except Exception as e:",
        "print(f\"{e=}\")",
    ] {
        assert!(
            EMPTY_TRASH.contains(required),
            "empty-trash missing {required}"
        );
    }
}
