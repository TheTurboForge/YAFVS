# SPDX-FileCopyrightText: 2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.errors import RequiredArgument
from gvm.protocols.gmp.requests.v226 import ReportConfigs, ReportFormatType
from gvm.protocols.gmp.requests.v226._report_configs import (
    ReportConfigParameter,
)


class ReportConfigsTestCase(unittest.TestCase):
    def test_create_report_config(self):
        request = ReportConfigs.create_report_config(
            "report-config1", "report_format_id"
        )
        self.assertEqual(
            bytes(request),
            b"<create_report_config>"
            b"<name>report-config1</name>"
            b'<report_format id="report_format_id"/>'
            b"</create_report_config>",
        )

    def test_create_report_config_with_comment(self):
        request = ReportConfigs.create_report_config(
            "report-config1", "report_format_id", comment="foo"
        )
        self.assertEqual(
            bytes(request),
            b"<create_report_config>"
            b"<name>report-config1</name>"
            b'<report_format id="report_format_id"/>'
            b"<comment>foo</comment>"
            b"</create_report_config>",
        )

    def test_create_report_config_with_params(self):
        request = ReportConfigs.create_report_config(
            "report-config1",
            "report_format_id",
            params=[
                ReportConfigParameter("name", "value"),
                ReportConfigParameter("name2", "value2", use_default=True),
                ReportConfigParameter("name3", use_default=True),
            ],
        )
        self.assertEqual(
            bytes(request),
            b"<create_report_config>"
            b"<name>report-config1</name>"
            b'<report_format id="report_format_id"/>'
            b'<param><name>name</name><value use_default="0">value</value></param>'
            b'<param><name>name2</name><value use_default="1"/></param>'
            b'<param><name>name3</name><value use_default="1"/></param>'
            b"</create_report_config>",
        )

    def test_create_report_config_missing_name(self):
        with self.assertRaises(RequiredArgument):
            ReportConfigs.create_report_config(None, "report_format_id")

        with self.assertRaises(RequiredArgument):
            ReportConfigs.create_report_config("", "report_format_id")

    def test_create_report_config_missing_report_format_id(self):
        with self.assertRaises(RequiredArgument):
            ReportConfigs.create_report_config("foo", None)

        with self.assertRaises(RequiredArgument):
            ReportConfigs.create_report_config("foo", "")

    def test_clone_report_config(self):
        request = ReportConfigs.clone_report_config("report_config_id")
        self.assertEqual(
            bytes(request),
            b"<create_report_config>"
            b"<copy>report_config_id</copy>"
            b"</create_report_config>",
        )

        request = ReportConfigs.clone_report_config(ReportFormatType.PDF)
        self.assertEqual(
            bytes(request),
            b"<create_report_config>"
            b"<copy>c402cc3e-b531-11e1-9163-406186ea4fc5</copy>"
            b"</create_report_config>",
        )

    def test_clone_report_config_missing_report_config_id(self):
        with self.assertRaises(RequiredArgument):
            ReportConfigs.clone_report_config(None)

        with self.assertRaises(RequiredArgument):
            ReportConfigs.clone_report_config("")

    def test_delete_report_config(self):
        request = ReportConfigs.delete_report_config("report_config_id")
        self.assertEqual(
            bytes(request),
            b'<delete_report_config report_config_id="report_config_id" ultimate="0"/>',
        )

        request = ReportConfigs.delete_report_config(ReportFormatType.PDF)
        self.assertEqual(
            bytes(request),
            b'<delete_report_config report_config_id="c402cc3e-b531-11e1-9163-406186ea4fc5" ultimate="0"/>',
        )

    def test_delete_report_config_with_ultimate(self):
        request = ReportConfigs.delete_report_config(
            "report_config_id", ultimate=True
        )
        self.assertEqual(
            bytes(request),
            b'<delete_report_config report_config_id="report_config_id" ultimate="1"/>',
        )

        request = ReportConfigs.delete_report_config(
            ReportFormatType.PDF, ultimate=False
        )
        self.assertEqual(
            bytes(request),
            b'<delete_report_config report_config_id="c402cc3e-b531-11e1-9163-406186ea4fc5" ultimate="0"/>',
        )

    def test_delete_report_config_missing_report_config_id(self):
        with self.assertRaises(RequiredArgument):
            ReportConfigs.delete_report_config(None)

        with self.assertRaises(RequiredArgument):
            ReportConfigs.delete_report_config("")

    def test_modify_report_config(self):
        request = ReportConfigs.modify_report_config("report_config_id")
        self.assertEqual(
            bytes(request),
            b'<modify_report_config report_config_id="report_config_id"/>',
        )

    def test_modify_report_config_with_name(self):
        request = ReportConfigs.modify_report_config(
            "report_config_id", name="foo"
        )
        self.assertEqual(
            bytes(request),
            b'<modify_report_config report_config_id="report_config_id">'
            b"<name>foo</name>"
            b"</modify_report_config>",
        )

    def test_modify_report_config_with_comment(self):
        request = ReportConfigs.modify_report_config(
            "report_config_id", comment="foo"
        )
        self.assertEqual(
            bytes(request),
            b'<modify_report_config report_config_id="report_config_id">'
            b"<comment>foo</comment>"
            b"</modify_report_config>",
        )

    def test_modify_report_config_with_params(self):
        request = ReportConfigs.modify_report_config(
            "report_config_id",
            params=[
                ReportConfigParameter("name", "value"),
                ReportConfigParameter("name2", "value2", use_default=True),
                ReportConfigParameter("name3", use_default=True),
            ],
        )
        self.assertEqual(
            bytes(request),
            b'<modify_report_config report_config_id="report_config_id">'
            b'<param><name>name</name><value use_default="0">value</value></param>'
            b'<param><name>name2</name><value use_default="1"/></param>'
            b'<param><name>name3</name><value use_default="1"/></param>'
            b"</modify_report_config>",
        )

    def test_modify_report_config_missing_report_config_id(self):
        with self.assertRaises(RequiredArgument):
            ReportConfigs.modify_report_config(None)

        with self.assertRaises(RequiredArgument):
            ReportConfigs.modify_report_config("")
