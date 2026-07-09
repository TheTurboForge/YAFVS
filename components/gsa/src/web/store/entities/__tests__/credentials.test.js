/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as credentials from 'web/store/entities/credentials';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('credential', credentials.entitiesLoadingActions);
testEntityActions('credential', credentials.entityLoadingActions);
testReducerForEntities(
  'credential',
  credentials.reducer,
  credentials.entitiesLoadingActions,
);
testReducerForEntity(
  'credential',
  credentials.reducer,
  credentials.entityLoadingActions,
);
