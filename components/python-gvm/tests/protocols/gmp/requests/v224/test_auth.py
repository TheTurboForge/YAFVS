# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.errors import RequiredArgument
from gvm.protocols.core import Request
from gvm.protocols.gmp.requests.v224 import Authentication


class AuthenticationTestCase(unittest.TestCase):
    def test_authenticate(self) -> None:
        request = Authentication.authenticate("admin", "admin")

        self.assertIsInstance(request, Request)
        self.assertEqual(
            bytes(request),
            b"<authenticate><credentials><username>admin</username>"
            b"<password>admin</password></credentials></authenticate>",
        )

    def test_authenticate_missing_username(self) -> None:
        with self.assertRaises(RequiredArgument):
            Authentication.authenticate(None, "foo")  # type: ignore

        with self.assertRaises(RequiredArgument):
            Authentication.authenticate("", "foo")

    def test_authenticate_missing_password(self) -> None:
        with self.assertRaises(RequiredArgument):
            Authentication.authenticate("bar", None)  # type: ignore

        with self.assertRaises(RequiredArgument):
            Authentication.authenticate("bar", "")
