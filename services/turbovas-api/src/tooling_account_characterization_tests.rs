// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[test]
fn inherited_list_users_script_is_retired_after_redacted_native_users_read() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/gvm-tools/scripts/list-users.gmp.py");
    assert!(
        !path.exists(),
        "list-users.gmp.py should stay retired; use /api/v1/users redacted native reads"
    );
}
