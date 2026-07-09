/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as filter from 'web/store/entities/filters';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('filter', filter.entitiesLoadingActions);
testEntityActions('filter', filter.entityLoadingActions);
testReducerForEntities('filter', filter.reducer, filter.entitiesLoadingActions);
testReducerForEntity('filter', filter.reducer, filter.entityLoadingActions);
