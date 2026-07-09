/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as tasks from 'web/store/entities/tasks';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('task', tasks.entitiesLoadingActions);
testEntityActions('task', tasks.entityLoadingActions);
testReducerForEntities('task', tasks.reducer, tasks.entitiesLoadingActions);
testReducerForEntity('task', tasks.reducer, tasks.entityLoadingActions);
