// SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// YAFVS-Derivation: original

use crate::gvmd_control::ScrubbedControlFrame;

#[test]
fn secret_wrappers_use_zeroize_instead_of_ordinary_fills() {
    let wrappers = [
        (
            "SensitiveBytes",
            include_str!("credential_write_validation.rs"),
            concat!(
                "impl Drop for SensitiveBytes {\n",
                "    fn drop(&mut self) {\n",
                "        self.0.zeroize();\n",
                "    }\n",
                "}"
            ),
        ),
        (
            "ScrubbedControlFrame",
            include_str!("gvmd_control.rs"),
            concat!(
                "pub(crate) fn scrub(&mut self) {\n",
                "        self.0.as_mut_slice().zeroize();\n",
                "    }"
            ),
        ),
        (
            "SensitiveAlertField",
            include_str!("alert_write_validation.rs"),
            concat!(
                "impl Drop for SensitiveAlertField {\n",
                "    fn drop(&mut self) {\n",
                "        self.0.zeroize();\n",
                "    }\n",
                "}"
            ),
        ),
        (
            "SensitiveScanConfigPreferenceValue",
            include_str!("scan_config_write_validation.rs"),
            concat!(
                "impl Drop for SensitiveScanConfigPreferenceValue {\n",
                "    fn drop(&mut self) {\n",
                "        self.0.zeroize();\n",
                "    }\n",
                "}"
            ),
        ),
    ];

    for (wrapper, source, zeroize_path) in wrappers {
        assert!(
            source.contains("use zeroize::Zeroize;"),
            "{wrapper} module must import zeroize::Zeroize"
        );
        assert!(
            source.contains(zeroize_path),
            "{wrapper} must zeroize its byte storage"
        );
        assert!(
            !source.contains("self.0.fill(0)"),
            "{wrapper} must not use an ordinary fill for secret cleanup"
        );
    }

    let control_source = include_str!("gvmd_control.rs");
    assert!(control_source.contains(concat!(
        "impl Drop for ScrubbedControlFrame {\n",
        "    fn drop(&mut self) {\n",
        "        self.scrub();\n",
        "    }\n",
        "}"
    )));
}

#[test]
fn scrubbed_control_frame_scrub_zeroes_bytes_without_changing_length() {
    let mut frame = ScrubbedControlFrame::new(vec![0x53, 0x45, 0x43, 0x52, 0x45, 0x54]);
    let original_len = frame.as_bytes().len();

    frame.scrub();

    assert_eq!(frame.as_bytes().len(), original_len);
    assert!(frame.as_bytes().iter().all(|byte| *byte == 0));
}
