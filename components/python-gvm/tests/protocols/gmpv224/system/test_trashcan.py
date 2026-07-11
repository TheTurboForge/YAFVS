# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224 import Gmpv224TestCase
from .trashcan import GmpRestoreFromTrashcanTestMixin


class Gmpv224RestoreFromTrashcanTestCase(
    GmpRestoreFromTrashcanTestMixin, Gmpv224TestCase
):
    pass
