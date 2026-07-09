/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as host from 'web/store/entities/hosts';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('host', host.entitiesLoadingActions);
testEntityActions('host', host.entityLoadingActions);
testReducerForEntities('host', host.reducer, host.entitiesLoadingActions);
testReducerForEntity('host', host.reducer, host.entityLoadingActions);
