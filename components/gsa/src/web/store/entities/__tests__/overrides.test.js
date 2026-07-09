/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as funcs from 'web/store/entities/overrides';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('override', funcs.entitiesLoadingActions);
testEntityActions('override', funcs.entityLoadingActions);
testReducerForEntities('override', funcs.reducer, funcs.entitiesLoadingActions);
testReducerForEntity('override', funcs.reducer, funcs.entityLoadingActions);
