// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[test]
fn cfg_gen_for_certs_is_retired_while_native_reporting_surfaces_remain() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/gvm-tools/scripts/cfg-gen-for-certs.gmp.py");
    assert!(
        !script.exists(),
        "retired cfg-gen-for-certs script must remain absent"
    );

    let openapi = include_str!("../../../api/openapi/turbovas-v1.yaml");
    for surface in [
        "  /cert-bund-advisories:",
        "  /cves:",
        "  /nvts:",
        "  /scan-configs:",
    ] {
        assert!(
            openapi.contains(surface),
            "native CERT/CVE/NVT/scan-config surface missing {surface}"
        );
    }
}
