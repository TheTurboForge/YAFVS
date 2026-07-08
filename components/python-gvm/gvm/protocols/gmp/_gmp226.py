# SPDX-FileCopyrightText: 2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Greenbone Management Protocol (GMP) version 22.6
"""

from collections.abc import Sequence

from .._protocol import T
from ._gmp225 import GMPv225
from .requests.v226 import (
    EntityID,
    Filters,
    FilterType,
    ReportFormatType,
    Reports,
    ResourceNames,
    ResourceType,
    Scopes,
)


class GMPv226(GMPv225[T]):
    """
    A class implementing the Greenbone Management Protocol (GMP) version 22.6

    Example:

        .. code-block:: python

            from gvm.protocols.gmp import GMPv226 as GMP

            with GMP(connection) as gmp:
                resp = gmp.get_tasks()
    """

    @staticmethod
    def get_protocol_version() -> tuple[int, int]:
        return (22, 6)

    def get_resource_names(
        self,
        resource_type: ResourceType,  # type: ignore[override]
        *,
        filter_string: str | None = None,
    ) -> T:
        """Request a list of resource names and IDs

        Arguments:
            resource_type: Type must be either ALERT, CERT_BUND_ADV,
                CONFIG, CPE, CREDENTIAL, CVE, DFN_CERT_ADV, FILTER,
                HOST, NVT, OS, OVERRIDE, PORT_LIST, REPORT_FORMAT,
                REPORT, REPORT_CONFIG, RESULT,
                SCANNER, SCHEDULE, TARGET, TASK, TLS_CERTIFICATE
                or USER
            filter_string: Filter term to use for the query
        """
        return self._send_request_and_transform_response(
            ResourceNames.get_resource_names(
                resource_type, filter_string=filter_string
            )
        )

    def get_resource_name(
        self,
        resource_id: str,
        resource_type: ResourceType,  # type: ignore[override]
    ) -> T:
        """Request a single resource name

        Arguments:
            resource_id: ID of an existing resource
            resource_type: Type must be either ALERT, CERT_BUND_ADV,
                CONFIG, CPE, CREDENTIAL, CVE, DFN_CERT_ADV, FILTER,
                HOST, NVT, OS, OVERRIDE, PORT_LIST, REPORT_FORMAT,
                REPORT, REPORT_CONFIG, RESULT,
                SCANNER, SCHEDULE, TARGET, TASK, TLS_CERTIFICATE
                or USER
        """
        return self._send_request_and_transform_response(
            ResourceNames.get_resource_name(resource_id, resource_type)
        )

    def delete_report(self, report_id: EntityID) -> T:
        """Deletes an existing scan report

        Args:
            report_id: UUID of the report to be deleted.
        """
        return self._send_request_and_transform_response(
            Reports.delete_report(report_id)
        )

    def get_report(
        self,
        report_id: EntityID,
        *,
        filter_string: str | None = None,
        filter_id: str | None = None,
        report_format_id: str | ReportFormatType | None = None,
        report_config_id: str | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = True,
    ) -> T:
        """Request a single scan report

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
        return self._send_request_and_transform_response(
            Reports.get_report(
                report_id,
                filter_string=filter_string,
                filter_id=filter_id,
                report_format_id=report_format_id,
                report_config_id=report_config_id,
                ignore_pagination=ignore_pagination,
                details=details,
            )
        )

    def get_reports(
        self,
        *,
        filter_string: str | None = None,
        filter_id: EntityID | None = None,
        override_details: bool | None = None,
        ignore_pagination: bool | None = None,
        details: bool | None = None,
    ) -> T:
        """Request a list of scan reports

        Args:
            filter_string: Filter term to use for the query
            filter_id: UUID of an existing filter to use for the query
            override_details: If overrides are included, whether to include
                override details
            ignore_pagination: Whether to ignore the filter terms "first" and
                "rows".
            details: Whether to exclude results
        """
        return self._send_request_and_transform_response(
                Reports.get_reports(
                    filter_string=filter_string,
                    filter_id=filter_id,
                    override_details=override_details,
                    ignore_pagination=ignore_pagination,
                    details=details,
            )
        )

    def get_report_metrics(self, report_id: EntityID) -> T:
        """Request CVSS Load and authenticated coverage metrics for a report."""
        return self._send_request_and_transform_response(
            Reports.get_report_metrics(report_id)
        )

    def create_scope(
        self,
        name: str,
        *,
        comment: str | None = None,
        protection_requirement: str | None = None,
        target_ids: Sequence[EntityID] | str | None = None,
        host_ids: Sequence[EntityID] | str | None = None,
    ) -> T:
        """Create a scope for operator-facing reporting."""
        return self._send_request_and_transform_response(
            Scopes.create_scope(
                name,
                comment=comment,
                protection_requirement=protection_requirement,
                target_ids=target_ids,
                host_ids=host_ids,
            )
        )

    def modify_scope(
        self,
        scope_id: EntityID,
        *,
        name: str | None = None,
        comment: str | None = None,
        protection_requirement: str | None = None,
        target_ids: Sequence[EntityID] | str | None = None,
        host_ids: Sequence[EntityID] | str | None = None,
    ) -> T:
        """Modify an existing scope."""
        return self._send_request_and_transform_response(
            Scopes.modify_scope(
                scope_id,
                name=name,
                comment=comment,
                protection_requirement=protection_requirement,
                target_ids=target_ids,
                host_ids=host_ids,
            )
        )

    def generate_scope_report(self, scope_id: EntityID) -> T:
        """Generate a persistent scope-report snapshot."""
        return self._send_request_and_transform_response(
            Scopes.generate_scope_report(scope_id)
        )

    def create_filter(
        self,
        name: str,
        *,
        filter_type: FilterType | None = None,  # type: ignore[override]
        comment: str | None = None,
        term: str | None = None,
    ) -> T:
        """Create a new filter

        Args:
            name: Name of the new filter
            filter_type: Filter for entity type
            comment: Comment for the filter
            term: Filter term e.g. 'name=foo'
        """
        # override create_filter because of the different FilterType enum
        # this avoids warnings with type checkers
        return self._send_request_and_transform_response(
            Filters.create_filter(
                name, filter_type=filter_type, comment=comment, term=term
            )
        )

    def modify_filter(
        self,
        filter_id: EntityID,
        *,
        comment: str | None = None,
        name: str | None = None,
        term: str | None = None,
        filter_type: FilterType | None = None,  # type: ignore[override]
    ) -> T:
        """Modifies an existing filter.

        Args:
            filter_id: UUID of the filter to be modified
            comment: Comment on filter.
            name: Name of filter.
            term: Filter term.
            filter_type: Resource type filter applies to.
        """
        # override create_filter because of the different FilterType enum
        # this avoids warnings with type checkers
        return self._send_request_and_transform_response(
            Filters.modify_filter(
                filter_id,
                comment=comment,
                name=name,
                term=term,
                filter_type=filter_type,
            )
        )
