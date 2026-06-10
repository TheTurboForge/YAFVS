/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  entitiesActions,
  loadEntities,
  reducer,
} from 'web/store/entities/reports';
import {
  testEntitiesActions,
  testLoadEntities,
  testReducerForEntities,
} from 'web/store/entities/utils/testing';

testEntitiesActions('report', entitiesActions);
testLoadEntities('report', loadEntities);
testReducerForEntities('report', reducer, entitiesActions);
