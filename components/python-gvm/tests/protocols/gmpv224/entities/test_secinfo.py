# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .secinfo import (
    GmpGetCertBundListTestMixin,
    GmpGetCpeListTestMixin,
    GmpGetCveListTestMixin,
    GmpGetDfnCertListTestMixin,
    GmpGetInfoListTestMixin,
    GmpGetInfoTestMixin,
    GmpGetNvtFamiliesTestMixin,
    GmpGetNvtListTestMixin,
    GmpGetNvtTestMixin,
    GmpGetScanConfigNvtsTestMixin,
    GmpGetScanConfigNvtTestMixin,
)


class Gmpv224GetInfoListTestCase(GmpGetInfoListTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetInfoTestCase(GmpGetInfoTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetNvtTestCase(GmpGetNvtTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetScanConfigNvtTestCase(
    GmpGetScanConfigNvtTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetNvtFamiliesTestCase(
    GmpGetNvtFamiliesTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetScanConfigNvtsTestCase(
    GmpGetScanConfigNvtsTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetCertBundListTestCase(
    GmpGetCertBundListTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetCpeListTestCase(GmpGetCpeListTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetCveListTestCase(GmpGetCveListTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetDfnCertListCase(GmpGetDfnCertListTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetNvtListTestCase(GmpGetNvtListTestMixin, Gmpv224TestCase):
    pass
