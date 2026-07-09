/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as certbund from 'web/store/entities/certbund';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('certbund', certbund.entitiesLoadingActions);
testEntityActions('certbund', certbund.entityLoadingActions);
testReducerForEntities(
  'certbund',
  certbund.reducer,
  certbund.entitiesLoadingActions,
);
testReducerForEntity('certbund', certbund.reducer, certbund.entityLoadingActions);
