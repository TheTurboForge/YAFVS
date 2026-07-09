// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{fs, path::Path};

#[test]
fn inherited_create_tags_from_csv_script_is_retired_after_native_exact_resource_helper() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        !repo_root
            .join("components/gvm-tools/scripts/create-tags-from-csv.gmp.py")
            .exists(),
        "use tools/turbovasctl native-tags-from-csv instead of the inherited GMP CSV tag script"
    );

    let turbovasctl = fs::read_to_string(repo_root.join("tools/turbovasctl"))
        .expect("tools/turbovasctl must be readable");
    for required in [
        "native-tags-from-csv",
        "resource_filter=~tagName",
        "exact report UUID resource columns",
        "\"resource_ids\"",
        "direct_native_api_curl(repo_root, \"/api/v1/tags\"",
    ] {
        assert!(
            turbovasctl.contains(required),
            "native CSV tag helper must preserve retirement contract: {required}"
        );
    }
}
