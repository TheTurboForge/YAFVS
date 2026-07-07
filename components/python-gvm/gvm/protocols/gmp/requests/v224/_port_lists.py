# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later


from gvm._enum import Enum
from gvm.protocols.core import Request
from gvm.utils import to_bool
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class PortRangeType(Enum):
    """Enum for port range type"""

    TCP = "TCP"
    UDP = "UDP"


class PortLists:
    @classmethod
    def get_port_lists(
        cls,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        details: bool | None = None,
        targets: bool | None = None,
        trash: bool | None = None,
    ) -> Request:
        """Request a list of port lists

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            details: Whether to include full port list details
            targets: Whether to include targets using this port list
            trash: Whether to get port lists in the trashcan instead
        """
        cmd = XmlCommand("get_port_lists")

        cmd.add_filter(filter_string, filter_id)

        if details is not None:
            cmd.set_attribute("details", to_bool(details))

        if targets is not None:
            cmd.set_attribute("targets", to_bool(targets))

        if trash is not None:
            cmd.set_attribute("trash", to_bool(trash))

        return cmd
