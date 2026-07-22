/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {
  type NativePortListBulkDeleteError,
  NativePortRangeDeleteError,
  PortListCommand,
  PortListsCommand,
} from 'gmp/native-api/port-lists';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const http = createHttp(undefined) as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };

  http.buildUrl = testing.fn((path: string) => `https://yafvs.example/${path}`);
  http.session = createSession();
  http.session.token = 'test-token';
  http.session.jwt = 'jwt-token';

  return http;
};

describe('PortListsCommand', () => {
  test('should fetch port lists through native api when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'alpha'},
        items: [
          {
            id: 'p1',
            name: 'Alpha Port List',
            comment: 'Native metadata',
            port_count: {all: 3, tcp: 2, udp: 1},
            port_ranges: [{id: 'r1', protocol: 'tcp', start: 1, end: 1000}],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    const result = await command.get({
      filter: 'first=1 rows=25 search=alpha predefined=1',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('p1');
    expect(result.data[0].name).toEqual('Alpha Port List');
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'alpha',
      predefined: '1',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/port-lists',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should fetch all port lists through native api with pagination', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'alpha',
          },
          items: [
            {
              id: 'p1',
              name: 'Alpha Port List',
            },
          ],
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
            filter: 'alpha',
          },
          items: [
            {
              id: 'p2',
              name: 'Beta Port List',
            },
          ],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    const result = await command.getAll({filter: 'search=alpha'});

    expect(http.request).not.toHaveBeenCalled();
    expect(result.data.map(portList => portList.id)).toEqual(['p1', 'p2']);
    expect(http.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(http.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/port-lists', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'alpha',
    });
    expect(result.meta.counts.first).toEqual(1);
    expect(result.meta.counts.rows).toEqual(2);
    expect(result.meta.counts.length).toEqual(2);
    expect(result.meta.counts.all).toEqual(2);
    expect(result.meta.counts.filtered).toEqual(2);
  });

  test('should bulk export selected port lists through native api', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p1', name: 'Alpha'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p2', name: 'Beta'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    const result = await command.exportByIds(['p1', 'p2']);

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/port-lists/p1/export',
      {token: 'test-token'},
    );
    expect(http.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/port-lists/p2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).port_lists).toEqual([
      {id: 'p1', name: 'Alpha'},
      {id: 'p2', name: 'Beta'},
    ]);
  });

  test('should bulk export current page filter through native api', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'a'},
          items: [{id: 'p2', name: 'Beta'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p2', name: 'Beta'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);
    const filter = Filter.fromString('first=2 rows=1 search=a');

    const result = await command.exportByFilter(filter);

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/port-lists', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'a',
    });
    expect(http.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/port-lists/p2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).port_lists).toEqual([
      {id: 'p2', name: 'Beta'},
    ]);
  });

  test('should bulk export all filtered port lists through native api', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'a'},
          items: [{id: 'p1', name: 'Alpha'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'a'},
          items: [{id: 'p2', name: 'Beta'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p1', name: 'Alpha'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p2', name: 'Beta'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);
    const filter = Filter.fromString('first=1 rows=1 search=a').all();

    const result = await command.exportByFilter(filter);

    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'a',
    });
    expect(http.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/port-lists', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'a',
    });
    expect(JSON.parse(result.data).port_lists).toEqual([
      {id: 'p1', name: 'Alpha'},
      {id: 'p2', name: 'Beta'},
    ]);
  });
});

describe('native port-list command family', () => {
  test('exposes the complete native command method inventory', () => {
    expect(Object.getOwnPropertyNames(PortListCommand.prototype)).toEqual(
      expect.arrayContaining([
        'get',
        'export',
        'create',
        'save',
        'clone',
        'delete',
        'createPortRange',
        'deletePortRange',
        'import',
      ]),
    );
    expect(Object.getOwnPropertyNames(PortListsCommand.prototype)).toEqual(
      expect.arrayContaining([
        'get',
        'getAll',
        'export',
        'exportByIds',
        'exportByFilter',
        'delete',
        'deleteByIds',
        'deleteByFilter',
      ]),
    );
  });

  test('rejects unsupported task detail filters without a legacy request', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    await expect(command.get({id: 'p1'}, {filter: 'tasks=1'})).rejects.toThrow(
      'Native port list detail filter is not supported',
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(http.request).not.toHaveBeenCalled();
  });

  test('uses native endpoints for detail and retained single-resource actions', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'p1',
          name: 'Web ports',
          port_ranges: [{id: 'r1', protocol: 'tcp', start: 80, end: 443}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p2'}),
        ok: true,
        status: 201,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'p3'}),
        ok: true,
        status: 201,
      })
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    expect((await command.get({id: 'p1'})).data.id).toBe('p1');
    expect(
      (await command.create({name: 'Web', portRange: 'tcp:80-443'})).data.id,
    ).toBe('p2');
    expect((await command.save({id: 'p1', name: 'Web'})).data.id).toBe('p1');
    expect((await command.clone({id: 'p1'})).data.id).toBe('p3');
    await command.delete({id: 'p1'});

    expect(http.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  test('uses native import and preserves the GSA response shape', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'imported'}),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    const result = await command.import({
      xmlFile: new File(['<port-list />'], 'port-list.xml'),
    });

    expect(result.data).toEqual({id: 'imported'});
    expect(http.request).not.toHaveBeenCalled();
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/port-list-imports');
  });

  test('creates ranges through the atomic native endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id: 'p1',
        name: 'Web ports',
        port_ranges: [{id: 'r1', protocol: 'tcp', start: 80, end: 443}],
      }),
      ok: true,
      status: 201,
    });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    const result = await command.createPortRange({
      portListId: 'p1',
      portRangeStart: 443,
      portRangeEnd: 80,
      portType: 'TCP',
    });

    expect(result.data).toEqual({
      id: 'r1',
      message: 'OK',
      action: 'create_port_range',
    });
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/port-lists/p1/ranges');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/port-lists/p1/ranges',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({protocol: 'tcp', start: 80, end: 443}),
      }),
    );
  });

  test('deletes ranges transactionally and refetches native detail', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'p1',
          name: 'Web ports',
          port_ranges: [],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    const result = await command.deletePortRange({id: 'r1', portListId: 'p1'});

    expect(result.data.id).toBe('p1');
    expect(http.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/port-lists/p1/ranges/r1',
    );
    expect(http.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/port-lists/p1', {
      token: 'test-token',
    });
    expect(http.request).not.toHaveBeenCalled();
  });

  test('returns an explicit native error for stale range deletion', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: false, status: 404});
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    await expect(
      command.deletePortRange({id: 'stale', portListId: 'p1'}),
    ).rejects.toMatchObject({
      name: 'NativePortRangeDeleteError',
      portListId: 'p1',
      portRangeId: 'stale',
    } satisfies Partial<NativePortRangeDeleteError>);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(http.request).not.toHaveBeenCalled();
  });

  test('does not claim deletion failed when only the detail refresh fails', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: false, status: 503});
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListCommand(http);

    const error = await command
      .deletePortRange({id: 'r1', portListId: 'p1'})
      .catch(cause => cause);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(NativePortRangeDeleteError);
    expect((error as Error).message).toContain('status 503');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(http.request).not.toHaveBeenCalled();
  });

  test('reports committed, failed, and pending IDs after partial bulk deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: false, status: 503});
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    await expect(command.deleteByIds(['p1', 'p2', 'p3'])).rejects.toMatchObject(
      {
        name: 'NativePortListBulkDeleteError',
        deletedIds: ['p1'],
        failedId: 'p2',
        pendingIds: ['p2', 'p3'],
      } satisfies Partial<NativePortListBulkDeleteError>,
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(http.request).not.toHaveBeenCalled();
  });

  test('drains page one repeatedly for all-filter bulk deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'daily',
          },
          items: [
            {id: 'p1', name: 'Daily A'},
            {id: 'p2', name: 'Daily B'},
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
            sort: 'name',
            filter: 'daily',
          },
          items: [],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();
    const command = new PortListsCommand(http);

    const result = await command.deleteByFilter(
      Filter.fromString('first=1 rows=-1 search=daily'),
    );

    expect(result.data.map(portList => portList.id)).toEqual(['p1', 'p2']);
    expect(http.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
    expect(http.buildUrl).toHaveBeenNthCalledWith(4, 'api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'daily',
    });
    expect(http.request).not.toHaveBeenCalled();
  });
});
