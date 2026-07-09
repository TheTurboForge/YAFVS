/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as targets from 'web/store/entities/targets';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('target', targets.entitiesLoadingActions);
testEntityActions('target', targets.entityLoadingActions);
testReducerForEntities('target', targets.reducer, targets.entitiesLoadingActions);
testReducerForEntity('target', targets.reducer, targets.entityLoadingActions);
