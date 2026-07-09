/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as funcs from 'web/store/entities/operatingsystems';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('operatingsystem', funcs.entitiesLoadingActions);
testEntityActions('operatingsystem', funcs.entityLoadingActions);
testReducerForEntities(
  'operatingsystem',
  funcs.reducer,
  funcs.entitiesLoadingActions,
);
testReducerForEntity('operatingsystem', funcs.reducer, funcs.entityLoadingActions);
