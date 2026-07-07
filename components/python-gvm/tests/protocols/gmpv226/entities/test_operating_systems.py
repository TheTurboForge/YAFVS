# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.operating_systems import (
    GmpDeleteOperatingSystemTestMixin,
    GmpGetOperatingSystemsTestMixin,
    GmpModifyOperatingSystemTestMixin,
)
from ...gmpv226 import GMPTestCase


class GMPDeleteOperatingSystemTestCase(
    GmpDeleteOperatingSystemTestMixin, GMPTestCase
):
    pass


class GMPGetOperatingSystemsTestCase(
    GmpGetOperatingSystemsTestMixin, GMPTestCase
):
    pass


class GMPModifyOperatingSystemTestCase(
    GmpModifyOperatingSystemTestMixin, GMPTestCase
):
    pass
