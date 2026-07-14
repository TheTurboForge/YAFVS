# SPDX-FileCopyrightText: 2023-2025 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpnext import GMPTestCase
from ...gmpv224.entities.credentials import (
    GmpCloneCredentialTestMixin,
    GmpCreateCredentialTestMixin,
    GmpDeleteCredentialTestMixin,
    GmpGetCredentialsTestMixin,
    GmpGetCredentialTestMixin,
    GmpModifyCredentialTestMixin,
)


class GMPCloneCredentialTestCase(GmpCloneCredentialTestMixin, GMPTestCase):
    pass


class GMPCreateCredentialTestCase(
    GmpCreateCredentialTestMixin,
    GMPTestCase,
):
    pass


class GMPDeleteCredentialTestCase(GmpDeleteCredentialTestMixin, GMPTestCase):
    pass


class GMPGetCredentialTestCase(GmpGetCredentialTestMixin, GMPTestCase):
    pass


class GMPGetCredentialsTestCase(GmpGetCredentialsTestMixin, GMPTestCase):
    pass


class GMPModifyCredentialTestCase(
    GmpModifyCredentialTestMixin,
    GMPTestCase,
):
    pass
