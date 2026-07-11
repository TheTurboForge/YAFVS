# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.system.trashcan import GmpRestoreFromTrashcanTestMixin
from ...gmpv225 import GMPTestCase


class Gmpv225RestoreFromTrashcanTestCase(
    GmpRestoreFromTrashcanTestMixin, GMPTestCase
):
    pass
