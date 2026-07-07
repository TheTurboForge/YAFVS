# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.protocols.gmp.requests.v224 import Vulnerabilities


class VulnerabilitiesTestCase(unittest.TestCase):
    def test_get_vulnerabilities(self):
        request = Vulnerabilities.get_vulnerabilities()
        self.assertEqual(bytes(request), b"<get_vulns/>")

    def test_get_vulnerabilities_with_filter_string(self):
        request = Vulnerabilities.get_vulnerabilities(
            filter_string="filter_string"
        )
        self.assertEqual(
            bytes(request),
            b'<get_vulns filter="filter_string"/>',
        )

    def test_get_vulnerabilities_with_filter_id(self):
        request = Vulnerabilities.get_vulnerabilities(filter_id="filter_id")
        self.assertEqual(
            bytes(request),
            b'<get_vulns filt_id="filter_id"/>',
        )
