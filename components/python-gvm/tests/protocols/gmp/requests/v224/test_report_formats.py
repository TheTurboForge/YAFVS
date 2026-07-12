# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.errors import RequiredArgument
from gvm.protocols.gmp.requests.v224 import ReportFormats, ReportFormatType


class ReportFormatsTestCase(unittest.TestCase):
    def test_get_report_formats(self):
        request = ReportFormats.get_report_formats()
        self.assertEqual(
            bytes(request),
            b"<get_report_formats/>",
        )

    def test_get_report_formats_with_filter_string(self):
        request = ReportFormats.get_report_formats(
            filter_string="filter_string"
        )
        self.assertEqual(
            bytes(request),
            b'<get_report_formats filter="filter_string"/>',
        )

    def test_get_report_formats_with_filter_id(self):
        request = ReportFormats.get_report_formats(filter_id="filter_id")
        self.assertEqual(
            bytes(request),
            b'<get_report_formats filt_id="filter_id"/>',
        )

    def test_get_report_formats_with_details(self):
        request = ReportFormats.get_report_formats(details=True)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats details="1"/>',
        )

        request = ReportFormats.get_report_formats(details=False)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats details="0"/>',
        )

    def test_get_report_formats_with_alerts(self):
        request = ReportFormats.get_report_formats(alerts=True)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats alerts="1"/>',
        )

        request = ReportFormats.get_report_formats(alerts=False)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats alerts="0"/>',
        )

    def test_get_report_formats_with_params(self):
        request = ReportFormats.get_report_formats(params=True)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats params="1"/>',
        )

        request = ReportFormats.get_report_formats(params=False)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats params="0"/>',
        )

    def test_get_report_formats_with_trash(self):
        request = ReportFormats.get_report_formats(trash=True)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats trash="1"/>',
        )

        request = ReportFormats.get_report_formats(trash=False)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats trash="0"/>',
        )

    def test_get_report_format(self):
        request = ReportFormats.get_report_format("report_format_id")
        self.assertEqual(
            bytes(request),
            b'<get_report_formats report_format_id="report_format_id" details="1"/>',
        )

        request = ReportFormats.get_report_format(ReportFormatType.PDF)
        self.assertEqual(
            bytes(request),
            b'<get_report_formats report_format_id="c402cc3e-b531-11e1-9163-406186ea4fc5" details="1"/>',
        )

    def test_get_report_format_missing_report_format_id(self):
        with self.assertRaises(RequiredArgument):
            ReportFormats.get_report_format(None)

        with self.assertRaises(RequiredArgument):
            ReportFormats.get_report_format("")
