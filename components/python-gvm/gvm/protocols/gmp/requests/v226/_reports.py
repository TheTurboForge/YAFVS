# SPDX-FileCopyrightText: 2024 Greenbone AG
# Modified by TurboVAS contributors, 2026.
#
# SPDX-License-Identifier: GPL-3.0-or-later


from gvm.errors import RequiredArgument
from gvm.protocols.core import Request
from gvm.utils import to_bool
from gvm.xml import XmlCommand

from .._entity_id import EntityID
from ..v224._report_formats import ReportFormatType


class Reports:
    @classmethod
    def delete_report(cls, report_id: EntityID) -> Request:
        """Deletes an existing report

        Args:
            report_id: UUID of the report to be deleted.
        """
        if not report_id:
            raise RequiredArgument(
                function=cls.delete_report.__name__, argument="report_id"
            )

        cmd = XmlCommand("delete_report")
        cmd.set_attribute("report_id", str(report_id))

        return cmd

    @classmethod
    def get_report_metrics(cls, report_id: EntityID) -> Request:
        """Request CVSS Load and authenticated coverage metrics for a report."""
        if not report_id:
            raise RequiredArgument(
                function=cls.get_report_metrics.__name__, argument="report_id"
            )

        cmd = XmlCommand("get_report_metrics")
        cmd.set_attribute("report_id", str(report_id))
        return cmd

    @classmethod
    def get_report(
        cls,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        report_format_id: str | ReportFormatType | None = None,
        report_config_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> Request:
        """Request a single report

        Args:
            report_id: UUID of an existing report
            filter_string: Filter term to use to filter results in the report
            filter_id: UUID of filter to use to filter results in the report
            report_format_id: UUID of report format to use
                              or ReportFormatType (enum)
            report_config_id: UUID of report format config to use
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Request additional report information details
                     defaults to True
        """
        cmd = XmlCommand("get_reports")

        if not report_id:
            raise RequiredArgument(
                function=cls.get_report.__name__, argument="report_id"
            )

        cmd.set_attribute("report_id", str(report_id))
        cmd.set_attribute("usage_type", "scan")

        cmd.add_filter(filter_string, filter_id)

        if report_format_id:
            cmd.set_attribute("format_id", str(report_format_id))

        if report_config_id:
            cmd.set_attribute("config_id", str(report_config_id))

        if ignore_pagination is not None:
            cmd.set_attribute("ignore_pagination", to_bool(ignore_pagination))

        cmd.set_attribute("details", to_bool(details))

        return cmd

    @staticmethod
    def get_reports(
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        override_details: bool | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = None,
    ) -> Request:
        """Request a list of reports

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            override_details: If overrides are included, whether to include
                override details
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Whether to exclude results
        """
        cmd = XmlCommand("get_reports")
        cmd.set_attribute("usage_type", "scan")

        if filter_string:
            cmd.set_attribute("report_filter", filter_string)

        if filter_id:
            cmd.set_attribute("report_filt_id", str(filter_id))

        if override_details is not None:
            cmd.set_attribute("override_details", to_bool(override_details))

        if details is not None:
            cmd.set_attribute("details", to_bool(details))

        if ignore_pagination is not None:
            cmd.set_attribute("ignore_pagination", to_bool(ignore_pagination))

        return cmd
