# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later


from gvm.protocols.core import Request
from gvm.utils import to_bool
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class Schedules:
    @staticmethod
    def get_schedules(
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        trash: bool | None = None,
        tasks: bool | None = None,
    ) -> Request:
        """Request a list of schedules

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            trash: Whether to get the trashcan schedules instead
            tasks: Whether to include tasks using the schedules
        """
        cmd = XmlCommand("get_schedules")

        cmd.add_filter(filter_string, filter_id)

        if trash is not None:
            cmd.set_attribute("trash", to_bool(trash))

        if tasks is not None:
            cmd.set_attribute("tasks", to_bool(tasks))

        return cmd
