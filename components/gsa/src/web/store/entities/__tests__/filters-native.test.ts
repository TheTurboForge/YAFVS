/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import Filter from 'gmp/models/filter';
import {
  fetchNativeFilter,
  fetchNativeFilters,
  nativeFiltersQueryFromFilter,
} from 'gmp/native-api/filters';
import {loadEntities, loadEntity} from 'web/store/entities/filters';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API filters', () => {
  test('fetches top-level filters as inherited Filter models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'f8df35ce-e8a2-4c27-90a6-76b29a1e1b41',
            name: 'High Severity Reports',
            comment: 'operator filter',
            filter_type: 'report',
            term: 'severity>7.0 rows=10',
            alert_count: 1,
            alerts: [],
            created_at: '2026-06-18T18:00:00Z',
            modified_at: '2026-06-18T20:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeFilters(gmp, {
      page: 1,
      pageSize: 25,
      sort: 'name',
      filter: '',
      filterType: 'result',
    });

    const filter = response.filters[0];
    expect(response.counts.filtered).toEqual(1);
    expect(filter.id).toEqual('f8df35ce-e8a2-4c27-90a6-76b29a1e1b41');
    expect(filter.name).toEqual('High Severity Reports');
    expect(filter.comment).toEqual('operator filter');
    expect(filter.filter_type).toEqual('report');
    expect(filter.toFilterString()).toEqual('severity>7.0 rows=10');
    expect(filter.isInUse()).toEqual(true);
    expect(filter.isWritable()).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/filters', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: '',
      filter_type: 'result',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/filters',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('fetches filter details with alert backlinks', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'f8df35ce-e8a2-4c27-90a6-76b29a1e1b41',
        name: 'High Severity Reports',
        filter_type: 'report',
        term: 'severity>7.0',
        alerts: [
          {
            id: 'a9483e36-b9e4-43df-9ddc-d28ec1df9c23',
            name: 'Notify SecOps',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const filter = await fetchNativeFilter(
      gmp,
      'f8df35ce-e8a2-4c27-90a6-76b29a1e1b41',
    );

    expect(filter.id).toEqual('f8df35ce-e8a2-4c27-90a6-76b29a1e1b41');
    expect(filter.alerts).toHaveLength(1);
    expect(filter.alerts[0].id).toEqual('a9483e36-b9e4-43df-9ddc-d28ec1df9c23');
    expect(filter.alerts[0].name).toEqual('Notify SecOps');
  });

  test('maps inherited filter type criteria to the native filter_type query', () => {
    expect(
      nativeFiltersQueryFromFilter(Filter.fromString('type=result rows=10')),
    ).toEqual({
      page: 1,
      pageSize: 10,
      sort: 'name',
      filter: '',
      filterType: 'result',
    });
  });

  test('loads the filter store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort=name type=report');
    const rootState = createState('filter', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: 'name', filter: ''},
        items: [
          {
            id: 'f8df35ce-e8a2-4c27-90a6-76b29a1e1b41',
            name: 'High Severity Reports',
            filter_type: 'report',
            term: 'severity>7.0',
            alert_count: 1,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/filters', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'name',
      filter: '',
      filter_type: 'report',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('High Severity Reports');
    expect(successAction.data[0].filter_type).toEqual('report');
  });

  test('loads filter detail store entries through same-origin native API', async () => {
    const id = 'f8df35ce-e8a2-4c27-90a6-76b29a1e1b41';
    const rootState = createState('filter', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'High Severity Reports',
        filter_type: 'report',
        term: 'severity>7.0',
        alerts: [
          {
            id: 'a9483e36-b9e4-43df-9ddc-d28ec1df9c23',
            name: 'Notify SecOps',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntity(gmp)(id)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/filters/f8df35ce-e8a2-4c27-90a6-76b29a1e1b41',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.name).toEqual('High Severity Reports');
    expect(successAction.data.alerts).toHaveLength(1);
  });
});
