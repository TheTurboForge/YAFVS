/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import * as cve from 'web/store/entities/cves';
import {
  testEntitiesActions,
  testEntityActions,
  testReducerForEntities,
  testReducerForEntity,
} from 'web/store/entities/utils/testing';

testEntitiesActions('cve', cve.entitiesLoadingActions);
testEntityActions('cve', cve.entityLoadingActions);
testReducerForEntities('cve', cve.reducer, cve.entitiesLoadingActions);
testReducerForEntity('cve', cve.reducer, cve.entityLoadingActions);
