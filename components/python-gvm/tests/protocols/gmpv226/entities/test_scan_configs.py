# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.scan_configs import (
    GmpDeleteScanConfigTestMixin,
    GmpGetScanConfigsTestMixin,
    GmpGetScanConfigTestMixin,
    GmpModifyScanConfigSetCommentTestMixin,
    GmpModifyScanConfigSetFamilySelectionTestMixin,
    GmpModifyScanConfigSetNameTestMixin,
    GmpModifyScanConfigSetNvtPreferenceTestMixin,
    GmpModifyScanConfigSetNvtSelectionTestMixin,
    GmpModifyScanConfigSetScannerPreferenceTestMixin,
)
from ...gmpv226 import GMPTestCase


class GMPDeleteScanConfigTestCase(GmpDeleteScanConfigTestMixin, GMPTestCase):
    pass


class GMPGetScanConfigTestCase(GmpGetScanConfigTestMixin, GMPTestCase):
    pass


class GMPGetScanConfigsTestCase(GmpGetScanConfigsTestMixin, GMPTestCase):
    pass


class GMPModifyScanConfigSetCommentTestCase(
    GmpModifyScanConfigSetCommentTestMixin, GMPTestCase
):
    pass


class GMPModifyScanConfigSetFamilySelectionTestCase(
    GmpModifyScanConfigSetFamilySelectionTestMixin, GMPTestCase
):
    pass


class GMPModifyScanConfigSetNvtSelectionTestCase(
    GmpModifyScanConfigSetNvtSelectionTestMixin, GMPTestCase
):
    pass


class GMPModifyScanConfigSetNameTestCase(
    GmpModifyScanConfigSetNameTestMixin, GMPTestCase
):
    pass


class GMPModifyScanConfigSetNvtPreferenceTestCase(
    GmpModifyScanConfigSetNvtPreferenceTestMixin, GMPTestCase
):
    pass


class GMPModifyScanConfigSetScannerPreferenceTestCase(
    GmpModifyScanConfigSetScannerPreferenceTestMixin, GMPTestCase
):
    pass
