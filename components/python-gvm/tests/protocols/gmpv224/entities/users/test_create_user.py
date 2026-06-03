# SPDX-FileCopyrightText: 2018-2024 Greenbone AG
# Modified by TurboVAS contributors, 2026.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from gvm.errors import RequiredArgument

class GmpCreateUserTestMixin:
    def test_create_user_missing_name(self):
        with self.assertRaises(RequiredArgument):
            self.gmp.create_user(name=None)

        with self.assertRaises(RequiredArgument):
            self.gmp.create_user(name="")

    def test_create_user(self):
        self.gmp.create_user(name="foo")

        self.connection.send.has_been_called_with(
            b"<create_user><name>foo</name></create_user>"
        )

    def test_create_user_with_password(self):
        self.gmp.create_user(name="foo", password="bar")

        self.connection.send.has_been_called_with(
            b"<create_user>"
            b"<name>foo</name>"
            b"<password>bar</password>"
            b"</create_user>"
        )
