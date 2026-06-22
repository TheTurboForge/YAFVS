/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  entitiesActions,
  loadEntities,
  reducer,
} from 'web/store/entities/reports';
import {
  createState,
  testEntitiesActions,
  testReducerForEntities,
} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

testEntitiesActions('report', entitiesActions);
testReducerForEntities('report', reducer, entitiesActions);

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('report native API loading', () => {
  test('loads raw report list through same-origin native API', async () => {
    const filter = Filter.fromString('sort-reverse=date first=1 rows=10');
    const rootState = createState('report', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 10,
          total: 13,
          sort: '-creation_time',
          filter: '',
        },
        items: [
          {
            id: '261d4f44-ebd2-4a68-97f2-ff57b88126bc',
            name: 'metasploitable',
            status: 'Done',
            task: {
              id: 'task-1',
              name: 'metasploitable',
            },
            target: {
              id: 'target-1',
              name: 'metasploitable target',
            },
            creation_time: '2026-06-14T06:27:42Z',
            scan_start: '2026-06-14T06:28:11Z',
            scan_end: '2026-06-14T07:05:51Z',
            result_count: 626,
            vulnerability_count: 527,
            host_count: 1,
            cve_count: 1069,
            max_severity: 10,
            severity: {
              critical: 99,
              high: 152,
              medium: 256,
              low: 31,
              log: 88,
              false_positive: 0,
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      buildUrl: testing.fn(path => `https://turbovas.example/${path}`),
      session: {token: 'test-token'},
    };

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/reports', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: '-creation_time',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/reports',
      {
        credentials: 'include',
        headers: {Accept: 'application/json'},
      },
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(13);
    expect(successAction.data[0].id).toEqual(
      '261d4f44-ebd2-4a68-97f2-ff57b88126bc',
    );
    expect(successAction.data[0].report.result_count.critical.filtered).toEqual(
      99,
    );
    expect(successAction.data[0].report.task.target.name).toEqual(
      'metasploitable target',
    );
  });
});
