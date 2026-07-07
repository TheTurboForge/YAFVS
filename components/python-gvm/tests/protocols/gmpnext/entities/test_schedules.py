# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from ...gmpv224.entities.schedules import (
    GmpCreateScheduleTestMixin,
    GmpGetSchedulesTestMixin,
    GmpGetScheduleTestMixin,
)
from ...gmpv227 import GMPTestCase


class GMPGetScheduleTestCase(GmpGetScheduleTestMixin, GMPTestCase):
    pass


class GMPGetSchedulesTestCase(GmpGetSchedulesTestMixin, GMPTestCase):
    pass


class GMPCreateScheduleTestCase(GmpCreateScheduleTestMixin, GMPTestCase):
    pass
