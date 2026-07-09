#  SPDX-FileCopyrightText: 2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
#  SPDX-License-Identifier: GPL-3.0-or-later

from gvm.protocols.gmp.requests.next._credential_stores import CredentialStores
from gvm.protocols.gmp.requests.next._credentials import (
    Credentials,
    CredentialStoreCredentialType,
)
from gvm.protocols.gmp.requests.next._integration_configs import (
    IntegrationConfigs,
)
from gvm.protocols.gmp.requests.next._report_applications import (
    ReportApplications,
)
from gvm.protocols.gmp.requests.next._report_cves import (
    ReportCVEs,
)
from gvm.protocols.gmp.requests.next._report_errors import (
    ReportErrors,
)
from gvm.protocols.gmp.requests.next._report_hosts import (
    ReportHosts,
)
from gvm.protocols.gmp.requests.next._report_operating_systems import (
    ReportOperatingSystems,
)
from gvm.protocols.gmp.requests.next._report_ports import (
    ReportPorts,
)
from gvm.protocols.gmp.requests.next._report_tls_certificates import (
    ReportTlsCertificates,
)
from gvm.protocols.gmp.requests.next._report_vulnerabilities import (
    ReportVulnerabilities,
)
from gvm.protocols.gmp.requests.next._tasks import Tasks

from .._entity_id import EntityID
from .._version import Version
from ..v227 import (
    Aggregates,
    AggregateStatistic,
    AlertCondition,
    AlertEvent,
    AlertMethod,
    Alerts,
    AliveTest,
    Authentication,
    CertBundAdvisories,
    Cpes,
    CredentialFormat,
    CredentialType,
    Cves,
    DfnCertAdvisories,
    EntityType,
    Feed,
    FeedType,
    Filters,
    FilterType,
    Help,
    HelpFormat,
    Hosts,
    HostsOrdering,
    InfoType,
    Nvts,
    OperatingSystems,
    Overrides,
    PortLists,
    PortRangeType,
    ReportFormats,
    ReportFormatType,
    Reports,
    ResourceNames,
    ResourceType,
    Results,
    ScanConfigs,
    Scanners,
    ScannerType,
    Schedules,
    SecInfo,
    Severity,
    SnmpAuthAlgorithm,
    SnmpPrivacyAlgorithm,
    SortOrder,
    SystemReports,
    Targets,
    TLSCertificates,
    TrashCan,
    UserAuthType,
    Users,
    UserSettings,
    Vulnerabilities,
)

__all__ = (
    "AggregateStatistic",
    "Aggregates",
    "AlertCondition",
    "AlertEvent",
    "AlertMethod",
    "Alerts",
    "AliveTest",
    "Authentication",
    "CertBundAdvisories",
    "Cpes",
    "CredentialFormat",
    "CredentialStoreCredentialType",
    "CredentialStores",
    "CredentialType",
    "Credentials",
    "Cves",
    "DfnCertAdvisories",
    "EntityID",
    "EntityType",
    "Feed",
    "FeedType",
    "FilterType",
    "Filters",
    "Help",
    "HelpFormat",
    "Hosts",
    "HostsOrdering",
    "InfoType",
    "IntegrationConfigs",
    "Nvts",
    "OperatingSystems",
    "Overrides",
    "PortLists",
    "PortRangeType",
    "ReportApplications",
    "ReportCVEs",
    "ReportErrors",
    "ReportFormatType",
    "ReportFormats",
    "ReportHosts",
    "ReportOperatingSystems",
    "ReportPorts",
    "ReportTlsCertificates",
    "ReportVulnerabilities",
    "Reports",
    "ResourceNames",
    "ResourceType",
    "Results",
    "ScanConfigs",
    "ScannerType",
    "Scanners",
    "Schedules",
    "SecInfo",
    "Severity",
    "SnmpAuthAlgorithm",
    "SnmpPrivacyAlgorithm",
    "SortOrder",
    "SystemReports",
    "TLSCertificates",
    "Targets",
    "Tasks",
    "TrashCan",
    "UserAuthType",
    "UserSettings",
    "Users",
    "Version",
    "Vulnerabilities",
)
