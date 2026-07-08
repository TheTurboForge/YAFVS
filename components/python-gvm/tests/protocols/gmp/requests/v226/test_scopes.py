# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.protocols.gmp.requests.v226 import Scopes


class ScopesTestCase(unittest.TestCase):
    def test_generate_scope_report(self):
        request = Scopes.generate_scope_report("scope-1")
        self.assertEqual(
            bytes(request),
            b'<generate_scope_report scope_id="scope-1"/>',
        )
