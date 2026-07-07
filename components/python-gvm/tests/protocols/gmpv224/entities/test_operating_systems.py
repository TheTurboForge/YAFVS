# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .operating_systems import (
    GmpDeleteOperatingSystemTestMixin,
    GmpGetOperatingSystemsTestMixin,
    GmpModifyOperatingSystemTestMixin,
)


class Gmpv224DeleteOperatingSystemTestCase(
    GmpDeleteOperatingSystemTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetOperatingSystemsTestCase(
    GmpGetOperatingSystemsTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyOperatingSystemTestCase(
    GmpModifyOperatingSystemTestMixin, Gmpv224TestCase
):
    pass
