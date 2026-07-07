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
from ...gmpv225 import GMPTestCase


class Gmpv225DeleteOperatingSystemTestCase(
    GmpDeleteOperatingSystemTestMixin, GMPTestCase
):
    pass


class Gmpv225GetOperatingSystemsTestCase(
    GmpGetOperatingSystemsTestMixin, GMPTestCase
):
    pass


class Gmpv225ModifyOperatingSystemTestCase(
    GmpModifyOperatingSystemTestMixin, GMPTestCase
):
    pass
