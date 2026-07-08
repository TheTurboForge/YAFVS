# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from gvm.errors import RequiredArgument
from gvm.protocols.core import Request
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class Scopes:
    @classmethod
    def generate_scope_report(cls, scope_id: EntityID) -> Request:
        """Generate a persistent scope-report snapshot."""
        if not scope_id:
            raise RequiredArgument(
                function=cls.generate_scope_report.__name__, argument="scope_id"
            )

        cmd = XmlCommand("generate_scope_report")
        cmd.set_attribute("scope_id", str(scope_id))
        return cmd
