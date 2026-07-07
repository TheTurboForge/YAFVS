# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later


from gvm.protocols.core import Request
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class Vulnerabilities:
    @staticmethod
    def get_vulnerabilities(
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
    ) -> Request:
        """Request a list of vulnerabilities

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
        """
        cmd = XmlCommand("get_vulns")
        cmd.add_filter(filter_string, filter_id)
        return cmd
