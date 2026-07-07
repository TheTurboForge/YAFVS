# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ....gmpv224.entities.scanners import (
    GmpCloneScannerTestMixin,
    GmpDeleteScannerTestMixin,
    GmpGetScannersTestMixin,
    GmpVerifyScannerTestMixin,
)
from .test_create_scanner import GmpCreateScannerTestMixin
from .test_modify_scanner import GmpModifyScannerTestMixin

__all__ = (
    "GmpCloneScannerTestMixin",
    "GmpCreateScannerTestMixin",
    "GmpDeleteScannerTestMixin",
    "GmpGetScannersTestMixin",
    "GmpModifyScannerTestMixin",
    "GmpVerifyScannerTestMixin",
)
