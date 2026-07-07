# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .scan_configs import (
    GmpCreateScanConfigTestMixin,
    GmpDeleteScanConfigTestMixin,
    GmpGetScanConfigsTestMixin,
    GmpGetScanConfigTestMixin,
    GmpImportScanConfigTestMixin,
    GmpModifyScanConfigSetCommentTestMixin,
    GmpModifyScanConfigSetFamilySelectionTestMixin,
    GmpModifyScanConfigSetNameTestMixin,
    GmpModifyScanConfigSetNvtPreferenceTestMixin,
    GmpModifyScanConfigSetNvtSelectionTestMixin,
    GmpModifyScanConfigSetScannerPreferenceTestMixin,
)


class Gmpv224CreateScanConfigTestCase(
    GmpCreateScanConfigTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224DeleteScanConfigTestCase(
    GmpDeleteScanConfigTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224GetScanConfigTestCase(GmpGetScanConfigTestMixin, Gmpv224TestCase):
    pass


class Gmpv224GetScanConfigsTestCase(
    GmpGetScanConfigsTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ImportScanConfigTestCase(
    GmpImportScanConfigTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyScanConfigSetCommentTestCase(
    GmpModifyScanConfigSetCommentTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyScanConfigSetFamilySelectionTestCase(
    GmpModifyScanConfigSetFamilySelectionTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyScanConfigSetNvtSelectionTestCase(
    GmpModifyScanConfigSetNvtSelectionTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyScanConfigSetNameTestCase(
    GmpModifyScanConfigSetNameTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyScanConfigSetNvtPreferenceTestCase(
    GmpModifyScanConfigSetNvtPreferenceTestMixin, Gmpv224TestCase
):
    pass


class Gmpv224ModifyScanConfigSetScannerPreferenceTestCase(
    GmpModifyScanConfigSetScannerPreferenceTestMixin, Gmpv224TestCase
):
    pass
