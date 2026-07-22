/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeAlert,
  fetchNativeAlerts,
  nativeAlertsQueryFromFilter,
} from 'gmp/native-api/alerts';
import Filter from 'gmp/models/filter';
import {loadEntities, loadEntity} from 'web/store/entities/alerts';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

const createGmp = ({
  jwt,
  token = 'test-token',
}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API alerts', () => {
  test('fetches redacted alert list metadata as inherited Alert models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 2,
          page_size: 10,
          total: 11,
          sort: '-event',
          filter: 'secops',
        },
        items: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Notify SecOps',
            comment: 'Native metadata only',
            owner: {name: 'admin'},
            active: true,
            in_use: true,
            task_count: 2,
            event: {type: 'Task run status changed'},
            condition: {type: 'Filter count at least'},
            method: {type: 'SCP'},
            method_data_redacted: true,
            filter: {
              id: 'filter-1',
              name: 'High results',
            },
            created_at: '2026-06-20T12:00:00Z',
            modified_at: '2026-06-20T12:30:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeAlerts(gmp, {
      page: 2,
      pageSize: 10,
      sort: '-event',
      filter: 'secops',
    });

    const alert = response.alerts[0];
    expect(response.counts.first).toEqual(11);
    expect(response.counts.filtered).toEqual(11);
    expect(alert.id).toEqual('4e110580-5281-4e8e-bbc5-322f3ef8d9e8');
    expect(alert.name).toEqual('Notify SecOps');
    expect(alert.comment).toEqual('Native metadata only');
    expect(alert.owner?.name).toEqual('admin');
    expect(alert.isActive()).toEqual(true);
    expect(alert.isInUse()).toEqual(true);
    expect(alert.event?.type).toEqual('Task run status changed');
    expect(alert.event?.data).toEqual({});
    expect(alert.condition?.type).toEqual('Filter count at least');
    expect(alert.condition?.data).toEqual({});
    expect(alert.method?.type).toEqual('SCP');
    expect(alert.method?.data).toEqual({});
    expect(alert.filter?.id).toEqual('filter-1');
    expect(alert.filter?.name).toEqual('High results');
    expect(alert.userCapabilities.mayEdit('alert')).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/alerts', {
      token: 'test-token',
      page: 2,
      page_size: 10,
      sort: '-event',
      filter: 'secops',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/alerts',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('maps GSA filter state to the native alert collection query', () => {
    const filter = Filter.fromString(
      'first=26 rows=25 sort-reverse=event search=secops',
    );

    expect(nativeAlertsQueryFromFilter(filter)).toEqual({
      page: 2,
      pageSize: 25,
      sort: '-event',
      filter: 'secops',
    });
  });

  test('fetches redacted alert detail metadata with task backlinks', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
        name: 'Notify SecOps',
        comment: 'Native detail metadata only',
        owner: {name: 'admin'},
        active: true,
        in_use: true,
        task_count: 1,
        event: {type: 'Task run status changed'},
        condition: {type: 'Filter count at least'},
        method: {type: 'SCP'},
        method_data_redacted: true,
        filter: {
          id: 'filter-1',
          name: 'High results',
        },
        tasks: [
          {
            id: '65da9d26-9e74-4b56-af0f-63825a851a23',
            name: 'Authorized LAN task',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const alert = await fetchNativeAlert(
      gmp,
      '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
    );

    expect(alert.id).toEqual('4e110580-5281-4e8e-bbc5-322f3ef8d9e8');
    expect(alert.name).toEqual('Notify SecOps');
    expect(alert.comment).toEqual('Native detail metadata only');
    expect(alert.method?.type).toEqual('SCP');
    expect(alert.method?.data).toEqual({});
    expect(alert.tasks).toHaveLength(1);
    expect(alert.tasks[0].id).toEqual('65da9d26-9e74-4b56-af0f-63825a851a23');
    expect(alert.tasks[0].name).toEqual('Authorized LAN task');
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/alerts/4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/alerts/4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('loads the alert store through same-origin native API', async () => {
    const filter = Filter.fromString(
      'first=1 rows=10 sort=condition search=secops',
    );
    const rootState = createState('alert', {
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
          total: 1,
          sort: 'condition',
          filter: 'secops',
        },
        items: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Notify SecOps',
            active: true,
            in_use: false,
            task_count: 0,
            event: {type: 'Task run status changed'},
            condition: {type: 'Filter count at least'},
            method: {type: 'SCP'},
            method_data_redacted: true,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/alerts', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: 'condition',
      filter: 'secops',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0].name).toEqual('Notify SecOps');
    expect(successAction.data[0].condition.type).toEqual(
      'Filter count at least',
    );
  });

  test('loads alert detail store entries through same-origin native API', async () => {
    const id = '4e110580-5281-4e8e-bbc5-322f3ef8d9e8';
    const rootState = createState('alert', {
      isLoading: {
        [id]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
        name: 'Notify SecOps',
        active: true,
        in_use: false,
        task_count: 1,
        event: {type: 'Task run status changed'},
        condition: {type: 'Filter count at least'},
        method: {type: 'SCP'},
        method_data_redacted: true,
        tasks: [
          {
            id: '65da9d26-9e74-4b56-af0f-63825a851a23',
            name: 'Authorized LAN task',
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
      'api/v1/alerts/4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
      {token: 'test-token'},
    );
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITY_LOADING_SUCCESS');
    expect(successAction.data.name).toEqual('Notify SecOps');
    expect(successAction.data.method.data).toEqual({});
    expect(successAction.data.tasks).toHaveLength(1);
    expect(successAction.data.tasks[0].name).toEqual('Authorized LAN task');
  });
});
