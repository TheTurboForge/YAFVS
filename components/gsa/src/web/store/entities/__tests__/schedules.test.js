/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as funcs from 'web/store/entities/schedules';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('schedule', funcs.entitiesLoadingActions);
testEntityActions('schedule', funcs.entityLoadingActions);
testReducerForEntities('schedule', funcs.reducer, funcs.entitiesLoadingActions);
testReducerForEntity('schedule', funcs.reducer, funcs.entityLoadingActions);
