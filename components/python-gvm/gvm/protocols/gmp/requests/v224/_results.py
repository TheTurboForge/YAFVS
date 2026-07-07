# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later


from gvm.protocols.core import Request
from gvm.utils import to_bool
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class Results:
    @staticmethod
    def get_results(
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        task_id: str | None = None,
        note_details: bool | None = None,
        override_details: bool | None = None,
        details: bool | None = None,
    ) -> Request:
        """Request a list of results

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            task_id: UUID of task for override handling
            note_details: If notes are included, whether to include note
                details
            override_details: If overrides are included, whether to include
                override details
            details: Whether to include additional details of the results
        """
        cmd = XmlCommand("get_results")

        cmd.add_filter(filter_string, filter_id)

        if task_id:
            cmd.set_attribute("task_id", task_id)

        if details is not None:
            cmd.set_attribute("details", to_bool(details))

        if note_details is not None:
            cmd.set_attribute("note_details", to_bool(note_details))

        if override_details is not None:
            cmd.set_attribute("override_details", to_bool(override_details))

        return cmd
