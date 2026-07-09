/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as funcs from 'web/store/entities/vulns';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('vuln', funcs.entitiesLoadingActions);
testEntityActions('vuln', funcs.entityLoadingActions);
testReducerForEntities('vuln', funcs.reducer, funcs.entitiesLoadingActions);
testReducerForEntity('vuln', funcs.reducer, funcs.entityLoadingActions);
