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
from ...gmpv227 import GMPTestCase


class GMPGetInfoListTestCase(GmpGetInfoListTestMixin, GMPTestCase):
    pass


class GMPGetInfoTestCase(GmpGetInfoTestMixin, GMPTestCase):
    pass


class GMPGetNvtTestCase(GmpGetNvtTestMixin, GMPTestCase):
    pass


class GMPGetScanConfigNvtTestCase(GmpGetScanConfigNvtTestMixin, GMPTestCase):
    pass


class GMPGetNvtFamiliesTestCase(GmpGetNvtFamiliesTestMixin, GMPTestCase):
    pass


class GMPGetScanConfigNvtsTestCase(GmpGetScanConfigNvtsTestMixin, GMPTestCase):
    pass


class GMPGetCertBundListTestCase(GmpGetCertBundListTestMixin, GMPTestCase):
    pass


class GMPGetCpeListTestCase(GmpGetCpeListTestMixin, GMPTestCase):
    pass


class GMPGetCveListTestCase(GmpGetCveListTestMixin, GMPTestCase):
    pass


class GMPGetDfnCertListCase(GmpGetDfnCertListTestMixin, GMPTestCase):
    pass


class GMPGetNvtListTestCase(GmpGetNvtListTestMixin, GMPTestCase):
    pass
