# SPDX-FileCopyrightText: 2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Optional

from gvm._enum import Enum


class EntityType(Enum):
    """Enum for entity types"""

    ALERT = "alert"
    ASSET = "asset"
    CERT_BUND_ADV = "cert_bund_adv"
    CPE = "cpe"
    CREDENTIAL = "credential"
    CVE = "cve"
    DFN_CERT_ADV = "dfn_cert_adv"
    FILTER = "filter"
    HOST = "host"
    INFO = "info"
    NVT = "nvt"
    OPERATING_SYSTEM = "os"
    OVALDEF = "ovaldef"
    OVERRIDE = "override"
    PORT_LIST = "port_list"
    REPORT = "report"
    REPORT_FORMAT = "report_format"
    RESULT = "result"
    SCAN_CONFIG = "config"
    SCANNER = "scanner"
    SCHEDULE = "schedule"
    TAG = "tag"
    TARGET = "target"
    TASK = "task"
    TLS_CERTIFICATE = "tls_certificate"
    USER = "user"
    VULNERABILITY = "vuln"

    @classmethod
    def from_string(
        cls,
        entity_type: str | None,
    ) -> Optional["EntityType"]:
        """Convert a entity type string to an actual EntityType instance

        Arguments:
            entity_type: Entity type string to convert to a EntityType
        """
        if entity_type == "vuln":
            return cls.VULNERABILITY

        if entity_type == "os":
            return cls.OPERATING_SYSTEM

        if entity_type == "config":
            return cls.SCAN_CONFIG

        return super().from_string(entity_type)
