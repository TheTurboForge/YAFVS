# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later


from gvm.protocols.core import Request
from gvm.utils import to_bool
from gvm.xml import XmlCommand

from .._entity_id import EntityID


class DfnCertAdvisories:
    @staticmethod
    def get_dfn_cert_advisories(
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        name: str | None = None,
        details: bool | None = None,
    ) -> Request:
        """Request a list of DFN-CERT Advisories

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            name: Name or identifier of the requested information
            details: Whether to include information about references to this
                information
        """
        cmd = XmlCommand("get_info")

        cmd.set_attribute("type", "DFN_CERT_ADV")

        cmd.add_filter(filter_string, filter_id)

        if name:
            cmd.set_attribute("name", name)

        if details is not None:
            cmd.set_attribute("details", to_bool(details))

        return cmd
