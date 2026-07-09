/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as cpe from 'web/store/entities/cpes';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('cpe', cpe.entitiesLoadingActions);
testEntityActions('cpe', cpe.entityLoadingActions);
testReducerForEntities('cpe', cpe.reducer, cpe.entitiesLoadingActions);
testReducerForEntity('cpe', cpe.reducer, cpe.entityLoadingActions);
