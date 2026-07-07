# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.vulnerabilities import GmpGetVulnerabilitiesTestMixin
from ...gmpv227 import GMPTestCase


class GMPGetVulnerabilitiesTestCase(
    GmpGetVulnerabilitiesTestMixin, GMPTestCase
):
    pass
