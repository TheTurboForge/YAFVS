/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as funcs from 'web/store/entities/results';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('result', funcs.entitiesLoadingActions);
testEntityActions('result', funcs.entityLoadingActions);
testReducerForEntities('result', funcs.reducer, funcs.entitiesLoadingActions);
testReducerForEntity('result', funcs.reducer, funcs.entityLoadingActions);
