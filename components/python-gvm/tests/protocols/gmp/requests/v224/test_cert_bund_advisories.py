# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.protocols.gmp.requests.v224 import CertBundAdvisories


class CertBundAdvisoriesTestCase(unittest.TestCase):
    def test_get_cert_bund_advisories(self):
        request = CertBundAdvisories.get_cert_bund_advisories()
        self.assertEqual(
            bytes(request),
            b'<get_info type="CERT_BUND_ADV"/>',
        )

    def test_get_cert_bund_advisories_with_filter_string(self):
        request = CertBundAdvisories.get_cert_bund_advisories(
            filter_string="filter_string"
        )
        self.assertEqual(
            bytes(request),
            b'<get_info type="CERT_BUND_ADV" filter="filter_string"/>',
        )

    def test_get_cert_bund_advisories_with_filter_id(self):
        request = CertBundAdvisories.get_cert_bund_advisories(
            filter_id="filter_id"
        )
        self.assertEqual(
            bytes(request),
            b'<get_info type="CERT_BUND_ADV" filt_id="filter_id"/>',
        )

    def test_get_cert_bund_advisories_with_name(self):
        request = CertBundAdvisories.get_cert_bund_advisories(name="name")
        self.assertEqual(
            bytes(request),
            b'<get_info type="CERT_BUND_ADV" name="name"/>',
        )

    def test_get_cert_bund_advisories_with_details(self):
        request = CertBundAdvisories.get_cert_bund_advisories(details=True)
        self.assertEqual(
            bytes(request),
            b'<get_info type="CERT_BUND_ADV" details="1"/>',
        )

        request = CertBundAdvisories.get_cert_bund_advisories(details=False)
        self.assertEqual(
            bytes(request),
            b'<get_info type="CERT_BUND_ADV" details="0"/>',
        )
