/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as portlist from 'web/store/entities/portlists';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('portlist', portlist.entitiesLoadingActions);
testEntityActions('portlist', portlist.entityLoadingActions);
testReducerForEntities(
  'portlist',
  portlist.reducer,
  portlist.entitiesLoadingActions,
);
testReducerForEntity('portlist', portlist.reducer, portlist.entityLoadingActions);
