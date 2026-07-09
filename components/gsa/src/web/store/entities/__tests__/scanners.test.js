/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as scanners from 'web/store/entities/scanners';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('scanner', scanners.entitiesLoadingActions);
testEntityActions('scanner', scanners.entityLoadingActions);
testReducerForEntities(
  'scanner',
  scanners.reducer,
  scanners.entitiesLoadingActions,
);
testReducerForEntity('scanner', scanners.reducer, scanners.entityLoadingActions);
