/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as alert from 'web/store/entities/alerts';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('alert', alert.entitiesLoadingActions);
testEntityActions('alert', alert.entityLoadingActions);
testReducerForEntities('alert', alert.reducer, alert.entitiesLoadingActions);
testReducerForEntity('alert', alert.reducer, alert.entityLoadingActions);
