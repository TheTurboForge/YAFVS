// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const CFG_GEN_FOR_CERTS: &str =
    include_str!("../../../components/gvm-tools/scripts/cfg-gen-for-certs.gmp.py");

#[test]
fn inherited_cfg_gen_for_certs_requires_cert_argument_and_loads_cves() {
    for required in [
        "len_args != 1",
        "This script creates a new scan config with nvts from a given CERT-Bund",
        "cert_bund_name = args.script[1]",
        "gmp.get_info(\n        info_id=cert_bund_name, info_type=gmp.types.InfoType.CERT_BUND_ADV\n    )",
        "info/cert_bund_adv/raw_data/Advisory/CVEList/CVE/text()",
    ] {
        assert!(
            CFG_GEN_FOR_CERTS.contains(required),
            "cfg-gen-for-certs CERT/CVE lookup behavior missing {required}"
        );
    }
}

#[test]
fn inherited_cfg_gen_for_certs_maps_cves_to_nvts_and_families() {
    for required in [
        "WHOLE_ONLY_FAMILIES = [",
        "gmp.get_info(info_id=cve, info_type=gmp.types.InfoType.CVE)",
        "nvts = cve_info.xpath(\"info/cve/nvts/nvt\")",
        "oid = nvt.xpath(\"@oid\")[0]",
        "nvt_data = gmp.get_scan_config_nvt(oid)",
        "family = nvt_data.xpath(\"nvt/family/text()\")[0]",
        "whole_families.add(family)",
        "nvt_dict[family] = [oid]",
    ] {
        assert!(
            CFG_GEN_FOR_CERTS.contains(required),
            "cfg-gen-for-certs CVE/NVT family behavior missing {required}"
        );
    }
}

#[test]
fn inherited_cfg_gen_for_certs_clones_scan_config_and_sets_selectors() {
    for required in [
        "copy_id = \"085569ce-73ed-11df-83c3-002264764cea\"",
        "config_name = f\"scanconfig_for_{cert_bund_name}\"",
        "res = gmp.create_scan_config(copy_id, config_name)",
        "config_id = res.xpath(\"@id\")[0]",
        "gmp.modify_scan_config_set_nvt_selection(\n                    config_id=config_id, nvt_oids=nvt_oid, family=family\n                )",
        "Attempt to modify NVT in whole-only family",
        "gmp.modify_scan_config_set_family_selection(",
        "families=[(f, True, True) for f in whole_families]",
    ] {
        assert!(
            CFG_GEN_FOR_CERTS.contains(required),
            "cfg-gen-for-certs scan-config selector behavior missing {required}"
        );
    }
}

#[test]
fn inherited_cfg_gen_for_certs_forces_port_scanner_nvts_and_swallows_existing_config() {
    for required in [
        "family = \"Port scanners\"",
        "nvts = [\"1.3.6.1.4.1.25623.1.0.14259\", \"1.3.6.1.4.1.25623.1.0.100315\"]",
        "gmp.modify_scan_config_set_nvt_selection(\n            config_id=config_id, nvt_oids=nvts, family=family\n        )",
        "print(\"Finished\")",
        "except GvmError as e:",
        "print(\"Config exist \", e)",
    ] {
        assert!(
            CFG_GEN_FOR_CERTS.contains(required),
            "cfg-gen-for-certs required port-scanner/error behavior missing {required}"
        );
    }
}
