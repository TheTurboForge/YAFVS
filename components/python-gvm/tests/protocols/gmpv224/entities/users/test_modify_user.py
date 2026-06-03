# SPDX-FileCopyrightText: 2018-2024 Greenbone AG
# Modified by TurboVAS contributors, 2026.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from gvm.errors import RequiredArgument
from gvm.protocols.gmp.requests.v224 import UserAuthType

class GmpModifyUserTestMixin:
    def test_modify_user(self):
        self.gmp.modify_user(user_id="u1")

        self.connection.send.has_been_called_with(
            b'<modify_user user_id="u1"/>'
        )

    def test_modify_user_missing_user_id(self):
        with self.assertRaises(RequiredArgument):
            self.gmp.modify_user(user_id=None)

        with self.assertRaises(RequiredArgument):
            self.gmp.modify_user(user_id="")

    def test_modify_user_with_new_name(self):
        self.gmp.modify_user(user_id="u1", name="foo")

        self.connection.send.has_been_called_with(
            b'<modify_user user_id="u1"><new_name>foo</new_name></modify_user>'
        )

    def test_modify_user_with_new_comment(self):
        self.gmp.modify_user(user_id="u1", comment="foo")

        self.connection.send.has_been_called_with(
            b'<modify_user user_id="u1"><comment>foo</comment></modify_user>'
        )

    def test_modify_user_with_password(self):
        self.gmp.modify_user(user_id="u1", password="foo")

        self.connection.send.has_been_called_with(
            b'<modify_user user_id="u1"><password>foo</password></modify_user>'
        )

    def test_modify_user_with_auth_source(self):
        self.gmp.modify_user(
            user_id="u1", auth_source=UserAuthType.LDAP_CONNECT
        )

        self.connection.send.has_been_called_with(
            b'<modify_user user_id="u1">'
            b"<sources><source>ldap_connect</source></sources>"
            b"</modify_user>"
        )
