# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.scanners import (
    GmpCloneScannerTestMixin,
    GmpCreateScannerTestMixin,
    GmpDeleteScannerTestMixin,
    GmpGetScannersTestMixin,
    GmpModifyScannerTestMixin,
    GmpVerifyScannerTestMixin,
)
from ...gmpv225 import GMPTestCase


class Gmpv225DeleteScannerTestCase(GmpDeleteScannerTestMixin, GMPTestCase):
    pass


class Gmpv225GetScannersTestCase(GmpGetScannersTestMixin, GMPTestCase):
    pass


class Gmpv225CloneScannerTestCase(GmpCloneScannerTestMixin, GMPTestCase):
    pass


class Gmpv225CreateScannerTestCase(GmpCreateScannerTestMixin, GMPTestCase):
    pass


class Gmpv225ModifyScannerTestCase(GmpModifyScannerTestMixin, GMPTestCase):
    pass


class Gmpv225VerifyScannerTestCase(GmpVerifyScannerTestMixin, GMPTestCase):
    pass
