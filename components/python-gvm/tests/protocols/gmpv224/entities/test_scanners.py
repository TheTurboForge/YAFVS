# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .scanners import (
    GmpCloneScannerTestMixin,
    GmpCreateScannerTestMixin,
    GmpDeleteScannerTestMixin,
    GmpGetScannersTestMixin,
    GmpModifyScannerTestMixin,
    GmpVerifyScannerTestMixin,
)


class Gmpv224DeleteScannerTestCase(GmpDeleteScannerTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetScannersTestCase(GmpGetScannersTestMixin, Gmpv224TestCase):
    pass


class Gmpv224CloneScannerTestCase(GmpCloneScannerTestMixin, Gmpv224TestCase):
    pass


class Gmpv224CreateScannerTestCase(GmpCreateScannerTestMixin, Gmpv224TestCase):
    pass


class Gmpv224ModifyScannerTestCase(GmpModifyScannerTestMixin, Gmpv224TestCase):
    pass


class Gmpv224VerifyScannerTestCase(GmpVerifyScannerTestMixin, Gmpv224TestCase):
    pass
