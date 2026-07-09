/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as nvts from 'web/store/entities/nvts';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('nvt', nvts.entitiesLoadingActions);
testEntityActions('nvt', nvts.entityLoadingActions);
testReducerForEntities('nvt', nvts.reducer, nvts.entitiesLoadingActions);
testReducerForEntity('nvt', nvts.reducer, nvts.entityLoadingActions);
