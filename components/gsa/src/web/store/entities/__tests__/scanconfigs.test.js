/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as funcs from 'web/store/entities/scanconfigs';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('scanconfig', funcs.entitiesLoadingActions);
testEntityActions('scanconfig', funcs.entityLoadingActions);
testReducerForEntities('scanconfig', funcs.reducer, funcs.entitiesLoadingActions);
testReducerForEntity('scanconfig', funcs.reducer, funcs.entityLoadingActions);
