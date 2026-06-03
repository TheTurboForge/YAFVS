/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {isFunction} from 'gmp/utils/identity';
import entitiesReducer from 'web/store/entities/reducers';

const initState = {
  byId: {},
  errors: {},
  isLoading: {},
};

describe('entities reducer tests', () => {
  test('should be a function', () => {
    expect(isFunction(entitiesReducer)).toEqual(true);
  });

  test('should create initial state', () => {
    expect(entitiesReducer(undefined, {})).toEqual({
      alert: initState,
      certbund: initState,
      cpe: initState,
      credential: initState,
      cve: initState,
      deltaReport: initState,
      dfncert: initState,
      filter: initState,
      host: initState,
      nvt: initState,
      operatingsystem: initState,
      override: initState,
      portlist: initState,
      reportconfig: initState,
      reportformat: initState,
      report: initState,
      result: initState,
      scanconfig: initState,
      scanner: initState,
      schedule: initState,
      tag: initState,
      target: initState,
      task: initState,
      tlscertificate: initState,
      user: initState,
      vuln: initState,
    });
  });
});
