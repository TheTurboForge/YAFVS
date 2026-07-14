# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from gvm.errors import RequiredArgument
from gvm.protocols.core import Request
from gvm.xml import XmlCommand


class Authentication:
    @classmethod
    def authenticate(cls, username: str, password: str) -> Request:
        """Authenticate to gvmd.

        The generated authenticate command will be send to server.
        Afterwards the response is read, transformed and returned.

        Args:
            username: Username
            password: Password
        """
        cmd = XmlCommand("authenticate")

        if not username:
            raise RequiredArgument(
                function=cls.authenticate.__name__, argument="username"
            )

        if not password:
            raise RequiredArgument(
                function=cls.authenticate.__name__, argument="password"
            )

        credentials = cmd.add_element("credentials")
        credentials.add_element("username", username)
        credentials.add_element("password", password)
        return cmd
