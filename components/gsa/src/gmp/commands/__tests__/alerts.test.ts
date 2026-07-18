/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import AlertsCommand from 'gmp/commands/alerts';
import {createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  fakeHttp.buildUrl = testing.fn(
    (path: string) => `https://yafvs.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('AlertsCommand tests', () => {
  test('should fetch alerts through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: 'name',
          filter: 'secops',
        },
        items: [
          {
            id: '4e110580-5281-4e8e-bbc5-322f3ef8d9e8',
            name: 'Notify SecOps',
            owner: {name: 'admin'},
            active: true,
            in_use: false,
            task_count: 0,
            event: {type: 'Task run status changed'},
            condition: {type: 'Filter count at least'},
            method: {type: 'SCP'},
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new AlertsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=secops'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('4e110580-5281-4e8e-bbc5-322f3ef8d9e8');
    expect(result.data[0].name).toEqual('Notify SecOps');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/alerts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
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

  test('should bulk export selected alerts through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'a1',
          name: 'Notify SecOps',
          method_data_redacted: true,
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'a2',
          name: 'Notify Owner',
          method_data_redacted: true,
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new AlertsCommand(fakeHttp);

    const result = await cmd.exportByIds(['a1', 'a2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/alerts/a1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/alerts/a2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).alerts).toEqual([
      {id: 'a1', name: 'Notify SecOps', method_data_redacted: true},
      {id: 'a2', name: 'Notify Owner', method_data_redacted: true},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'secops',
          },
          items: [{id: 'a2', name: 'Notify Owner'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'a2',
          name: 'Notify Owner',
          method_data_redacted: true,
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new AlertsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=secops');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/alerts', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'secops',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/alerts/a2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).alerts).toEqual([
      {id: 'a2', name: 'Notify Owner', method_data_redacted: true},
    ]);
  });

  test('should bulk export all filtered alerts through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'secops',
          },
          items: [{id: 'a1', name: 'Notify SecOps'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'secops',
          },
          items: [{id: 'a2', name: 'Notify Owner'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'a1',
          name: 'Notify SecOps',
          method_data_redacted: true,
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'a2',
          name: 'Notify Owner',
          method_data_redacted: true,
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new AlertsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=secops').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/alerts', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'secops',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/alerts', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'secops',
    });
    expect(JSON.parse(result.data).alerts).toEqual([
      {id: 'a1', name: 'Notify SecOps', method_data_redacted: true},
      {id: 'a2', name: 'Notify Owner', method_data_redacted: true},
    ]);
  });
});
