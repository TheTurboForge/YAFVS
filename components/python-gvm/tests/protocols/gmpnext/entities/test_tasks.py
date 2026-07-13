# SPDX-FileCopyrightText: 2023-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
from ...gmpnext import GMPTestCase
from ...gmpnext.entities.tasks import (
    GmpCloneTaskTestMixin,
    GmpCreateTaskTestMixin,
    GmpDeleteTaskTestMixin,
    GmpGetTasksTestMixin,
    GmpGetTaskTestMixin,
    GmpModifyTaskTestMixin,
    GmpMoveTaskTestMixin,
    GmpStartTaskTestMixin,
    GmpStopTaskTestMixin,
)


class GMPCloneTaskTestCase(GmpCloneTaskTestMixin, GMPTestCase):
    pass


class GMPCreateTaskTestCase(GmpCreateTaskTestMixin, GMPTestCase):
    pass


class GMPDeleteTaskTestCase(GmpDeleteTaskTestMixin, GMPTestCase):
    pass


class GMPGetTaskTestCase(GmpGetTaskTestMixin, GMPTestCase):
    pass


class GMPGetTasksTestCase(GmpGetTasksTestMixin, GMPTestCase):
    pass


class GMPModifyTaskTestCase(GmpModifyTaskTestMixin, GMPTestCase):
    pass


class GMPMoveTaskTestCase(GmpMoveTaskTestMixin, GMPTestCase):
    pass


class GMPStartTaskTestCase(GmpStartTaskTestMixin, GMPTestCase):
    pass


class GMPStopTaskTestCase(GmpStopTaskTestMixin, GMPTestCase):
    pass
