# SPDX-FileCopyrightText: 2024 Greenbone AG
# Modified by TurboVAS contributors, 2026.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from gvm.errors import InvalidArgument, RequiredArgument
from gvm.protocols.gmp.requests.v224 import UserAuthType, Users

class UsersTestCase(unittest.TestCase):
    def test_get_users(self):
        request = Users().get_users()

        self.assertEqual(bytes(request), b"<get_users/>")

    def test_get_users_with_filter_string(self):
        request = Users().get_users(filter_string="foo=bar")

        self.assertEqual(bytes(request), b'<get_users filter="foo=bar"/>')

    def test_get_users_with_filter_id(self):
        request = Users().get_users(filter_id="f1")

        self.assertEqual(bytes(request), b'<get_users filt_id="f1"/>')

    def test_create_user(self):
        request = Users().create_user(name="foo")

        self.assertEqual(
            bytes(request), b"<create_user><name>foo</name></create_user>"
        )

    def test_create_user_with_password(self):
        request = Users().create_user(name="foo", password="bar")

        self.assertEqual(
            bytes(request),
            b"<create_user><name>foo</name><password>bar</password></create_user>",
        )

    def test_create_user_missing_name(self):
        with self.assertRaises(RequiredArgument):
            Users().create_user("")

        with self.assertRaises(RequiredArgument):
            Users().create_user(None)

    def test_modify_user(self):
        request = Users().modify_user(user_id="u1")

        self.assertEqual(bytes(request), b'<modify_user user_id="u1"/>')

    def test_modify_user_missing_user_id(self):
        with self.assertRaises(RequiredArgument):
            Users().modify_user(user_id=None)

        with self.assertRaises(RequiredArgument):
            Users().modify_user(user_id="")

    def test_modify_user_with_new_name(self):
        request = Users().modify_user(user_id="u1", name="foo")

        self.assertEqual(
            bytes(request),
            b'<modify_user user_id="u1"><new_name>foo</new_name></modify_user>',
        )

    def test_modify_user_with_new_comment(self):
        request = Users().modify_user(user_id="u1", comment="foo")

        self.assertEqual(
            bytes(request),
            b'<modify_user user_id="u1"><comment>foo</comment></modify_user>',
        )

    def test_modify_user_with_password(self):
        request = Users().modify_user(user_id="u1", password="bar")

        self.assertEqual(
            bytes(request),
            b'<modify_user user_id="u1"><password>bar</password></modify_user>',
        )

    def test_modify_user_with_auth_source(self):
        request = Users().modify_user(
            user_id="u1", auth_source=UserAuthType.LDAP_CONNECT
        )

        self.assertEqual(
            bytes(request),
            b'<modify_user user_id="u1">'
            b"<sources><source>ldap_connect</source></sources>"
            b"</modify_user>",
        )

        request = Users().modify_user(user_id="u1", auth_source="ldap_connect")

        self.assertEqual(
            bytes(request),
            b'<modify_user user_id="u1">'
            b"<sources><source>ldap_connect</source></sources>"
            b"</modify_user>",
        )

    def test_modify_user_invalid_auth_source(self):
        with self.assertRaises(InvalidArgument):
            Users().modify_user(user_id="u1", auth_source="foo")

    def test_clone_user(self):
        request = Users().clone_user(user_id="u1")

        self.assertEqual(
            bytes(request), b"<create_user><copy>u1</copy></create_user>"
        )

    def test_clone_user_missing_user_id(self):
        with self.assertRaises(RequiredArgument):
            Users().clone_user(user_id=None)

        with self.assertRaises(RequiredArgument):
            Users().clone_user(user_id="")

    def test_delete_user_with_user_id(self):
        request = Users().delete_user("u1")

        self.assertEqual(bytes(request), b'<delete_user user_id="u1"/>')

    def test_delete_user_with_name(self):
        request = Users().delete_user(name="foo")

        self.assertEqual(bytes(request), b'<delete_user name="foo"/>')

    def test_delete_user_with_inheritor_id(self):
        request = Users().delete_user("u1", inheritor_id="u2")

        self.assertEqual(
            bytes(request), b'<delete_user user_id="u1" inheritor_id="u2"/>'
        )

    def test_delete_user_with_inheritor_name(self):
        request = Users().delete_user("u1", inheritor_name="foo")

        self.assertEqual(
            bytes(request), b'<delete_user user_id="u1" inheritor_name="foo"/>'
        )

    def test_delete_user_missing_user_id_and_name(self):
        with self.assertRaises(RequiredArgument):
            Users().delete_user(None)

        with self.assertRaises(RequiredArgument):
            Users().delete_user("")

        with self.assertRaises(RequiredArgument):
            Users().delete_user(user_id="", name="")

    def test_get_user(self):
        request = Users().get_user("u1")

        self.assertEqual(bytes(request), b'<get_users user_id="u1"/>')

    def test_get_user_missing_user_id(self):
        with self.assertRaises(RequiredArgument):
            Users().get_user(user_id=None)

        with self.assertRaises(RequiredArgument):
            Users().get_user("")
