/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  HostsCommand,
  type NativeHostBulkDeleteError,
} from 'gmp/native-api/hosts';
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

describe('HostsCommand tests', () => {
  test('should fetch hosts through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-severity',
          filter: 'web',
        },
        items: [
          {
            id: 'host-1',
            name: '192.0.2.10',
            hostname: 'web.example.test',
            ip: '192.0.2.10',
            best_os_cpe: 'cpe:/o:example:linux',
            severity: 7.5,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new HostsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=web'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('host-1');
    expect(result.data[0].severity).toEqual(7.5);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'severity',
      filter: 'web',
    });
  });

  test('should fetch all hosts through bounded native pages', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'host-1', name: '192.0.2.10', severity: 7.5}],
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
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'host-2', name: '192.0.2.20', severity: 5.0}],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);

    const result = await cmd.getAll({filter: 'first=1 rows=1 search=web'});

    expect(result.data.map(host => host.id)).toEqual(['host-1', 'host-2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/hosts', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
  });

  test('should bulk export selected hosts through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({asset: {id: 'host-1'}}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({asset: {id: 'host-2'}}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);

    const result = await cmd.exportByIds(['host-1', 'host-2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/hosts/host-1/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).hosts).toEqual([
      {asset: {id: 'host-1'}},
      {asset: {id: 'host-2'}},
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
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'host-2', name: '192.0.2.20', severity: 5.0}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({asset: {id: 'host-2'}}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=web');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/hosts', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'severity',
      filter: 'web',
    });
    expect(JSON.parse(result.data).hosts).toEqual([{asset: {id: 'host-2'}}]);
  });

  test('should bulk export all filtered hosts through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'host-1', name: '192.0.2.10', severity: 7.5}],
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
            sort: 'severity',
            filter: 'web',
          },
          items: [{id: 'host-2', name: '192.0.2.20', severity: 5.0}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({asset: {id: 'host-1'}}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({asset: {id: 'host-2'}}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=web').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/hosts', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
    expect(JSON.parse(result.data).hosts).toEqual([
      {asset: {id: 'host-1'}},
      {asset: {id: 'host-2'}},
    ]);
  });

  test('should delete selected hosts sequentially through the native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);

    const result = await cmd.deleteByIds(['host-1', 'host-2']);

    expect(result.data).toEqual(['host-1', 'host-2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/hosts/host-1');
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/hosts/host-2');
  });

  test('should report the completed and pending IDs after a partial bulk delete', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: false, status: 503});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);

    await expect(
      cmd.deleteByIds(['host-1', 'host-2', 'host-3']),
    ).rejects.toMatchObject({
      name: 'NativeHostBulkDeleteError',
      deletedIds: ['host-1'],
      failedId: 'host-2',
      pendingIds: ['host-2', 'host-3'],
    } satisfies Partial<NativeHostBulkDeleteError>);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledTimes(2);
  });

  test('should delete every host matching an all-filter sequentially', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'severity',
            filter: 'web',
          },
          items: [
            {id: 'host-1', name: '192.0.2.10', severity: 7.5},
            {id: 'host-2', name: '192.0.2.20', severity: 5.0},
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 0,
            sort: 'severity',
            filter: 'web',
          },
          items: [],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new HostsCommand(fakeHttp);

    const result = await cmd.deleteByFilter(
      Filter.fromString('first=1 rows=1 search=web').all(),
    );

    expect(result.data.map(host => host.id)).toEqual(['host-1', 'host-2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/hosts', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'severity',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/hosts/host-1');
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(3, 'api/v1/hosts/host-2');
  });
});
