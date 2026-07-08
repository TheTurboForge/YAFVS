# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.errors import RequiredArgument
from gvm.protocols.gmp.requests.v226 import Scopes


class ScopesTestCase(unittest.TestCase):
    def test_create_scope(self):
        request = Scopes.create_scope(
            "Windows Desktop",
            comment="Workstations",
            protection_requirement="high",
            target_ids=["target-1", "target-2"],
            host_ids=["host-1"],
        )
        self.assertEqual(
            bytes(request),
            b'<create_scope name="Windows Desktop" comment="Workstations" '
            b'protection_requirement="high" target_ids="target-1 target-2" '
            b'host_ids="host-1"/>',
        )

    def test_create_scope_missing_name(self):
        with self.assertRaises(RequiredArgument):
            Scopes.create_scope("")

    def test_modify_scope(self):
        request = Scopes.modify_scope(
            "scope-1",
            name="Linux Server",
            protection_requirement="very_high",
            target_ids="target-1,target-2",
            host_ids="host-1 host-2",
        )
        self.assertEqual(
            bytes(request),
            b'<modify_scope scope_id="scope-1" name="Linux Server" '
            b'protection_requirement="very_high" target_ids="target-1,target-2" '
            b'host_ids="host-1 host-2"/>',
        )

    def test_modify_scope_missing_id(self):
        with self.assertRaises(RequiredArgument):
            Scopes.modify_scope("")

    def test_get_scopes(self):
        request = Scopes.get_scopes(details=False)
        self.assertEqual(bytes(request), b'<get_scopes details="0"/>')

    def test_delete_scope(self):
        request = Scopes.delete_scope("scope-1")
        self.assertEqual(bytes(request), b'<delete_scope scope_id="scope-1"/>')

    def test_generate_scope_report(self):
        request = Scopes.generate_scope_report("scope-1")
        self.assertEqual(
            bytes(request),
            b'<generate_scope_report scope_id="scope-1"/>',
        )

    def test_delete_scope_report(self):
        request = Scopes.delete_scope_report("report-1")
        self.assertEqual(
            bytes(request),
            b'<delete_scope_report scope_report_id="report-1"/>',
        )
