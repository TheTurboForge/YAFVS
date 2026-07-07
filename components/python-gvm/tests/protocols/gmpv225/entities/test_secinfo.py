# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.secinfo import (
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
from ...gmpv225 import GMPTestCase


class Gmpv225GetInfoListTestCase(GmpGetInfoListTestMixin, GMPTestCase):
    pass


class Gmpv225GetInfoTestCase(GmpGetInfoTestMixin, GMPTestCase):
    pass


class Gmpv225GetNvtTestCase(GmpGetNvtTestMixin, GMPTestCase):
    pass


class Gmpv225GetScanConfigNvtTestCase(
    GmpGetScanConfigNvtTestMixin, GMPTestCase
):
    pass


class Gmpv225GetNvtFamiliesTestCase(GmpGetNvtFamiliesTestMixin, GMPTestCase):
    pass


class Gmpv225GetScanConfigNvtsTestCase(
    GmpGetScanConfigNvtsTestMixin, GMPTestCase
):
    pass


class Gmpv225GetCertBundListTestCase(GmpGetCertBundListTestMixin, GMPTestCase):
    pass


class Gmpv225GetCpeListTestCase(GmpGetCpeListTestMixin, GMPTestCase):
    pass


class Gmpv225GetCveListTestCase(GmpGetCveListTestMixin, GMPTestCase):
    pass


class Gmpv225GetDfnCertListCase(GmpGetDfnCertListTestMixin, GMPTestCase):
    pass


class Gmpv225GetNvtListTestCase(GmpGetNvtListTestMixin, GMPTestCase):
    pass
