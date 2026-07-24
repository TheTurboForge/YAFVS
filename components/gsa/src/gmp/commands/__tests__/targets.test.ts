/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TargetsCommand, {
  NativeTargetBulkDeleteError,
} from 'gmp/commands/targets';
import {createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import Target from 'gmp/models/target';
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

const targetPageResponse = (
  items: Array<{id?: string; name?: string}>,
  total: number,
  page: number,
) => ({
  json: testing.fn().mockResolvedValue({
    page: {page, page_size: 500, total},
    items,
  }),
  ok: true,
  status: 200,
});

describe('TargetsCommand tests', () => {
  test('should refuse target lists locally when native API is unavailable', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createHttp(undefined);
    const cmd = new TargetsCommand(fakeHttp);

    await expect(cmd.get()).rejects.toThrow(
      'Native target API is required for targets command',
    );
    await expect(cmd.getAll()).rejects.toThrow(
      'Native target API is required for targets command',
    );
    expect(() => cmd.exportByIds(['target-id'])).toThrow(
      'Native target API is required for targets command',
    );
    await expect(
      cmd.exportByFilter(Filter.fromString('first=1 rows=10')),
    ).rejects.toThrow('Native target API is required for targets command');
    await expect(cmd.delete([new Target({id: 'target-id'})])).rejects.toThrow(
      'Native target API is required for targets command',
    );
    await expect(cmd.deleteByIds(['target-id'])).rejects.toThrow(
      'Native target API is required for targets command',
    );
    await expect(
      cmd.deleteByFilter(Filter.fromString('first=1 rows=10')),
    ).rejects.toThrow('Native target API is required for targets command');
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should fetch targets through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'web'},
        items: [
          {
            id: 'target-1',
            name: 'Web Target',
            comment: 'native target metadata',
            hosts: ['192.0.2.10'],
            exclude_hosts: [],
            max_hosts: 1,
            alive_tests: ['icmp-ping'],
            allow_simultaneous_ips: true,
            reverse_lookup_only: false,
            reverse_lookup_unify: false,
            port_list: {id: 'pl-1', name: 'Default'},
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new TargetsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=web'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('target-1');
    expect(result.data[0].name).toEqual('Web Target');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/targets', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'web',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/targets',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should bulk export selected targets through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'target-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'target-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    const result = await cmd.export([
      new Target({id: 'target-1'}),
      new Target({id: 'target-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/targets/target-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/targets/target-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).targets).toEqual([
      {id: 'target-1', name: 'One'},
      {id: 'target-2', name: 'Two'},
    ]);
  });

  test('should bulk export current page targets through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'web'},
          items: [{id: 'target-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'target-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=web');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/targets', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'web',
    });
    expect(JSON.parse(result.data).targets).toEqual([
      {id: 'target-2', name: 'Two'},
    ]);
  });

  test('should bulk export all filtered targets through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'web',
          },
          items: [{id: 'target-1', name: 'One'}],
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
            filter: 'web',
          },
          items: [{id: 'target-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'target-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'target-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=web').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/targets', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/targets', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'web',
    });
    expect(JSON.parse(result.data).targets).toEqual([
      {id: 'target-1', name: 'One'},
      {id: 'target-2', name: 'Two'},
    ]);
  });

  test('should delete selected target models sequentially through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);
    const targets = [
      new Target({id: 'target-2'}),
      new Target({id: 'target-1'}),
    ];

    const result = await cmd.delete(targets);

    expect(result.data).toEqual(targets);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/targets/target-2',
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/targets/target-1',
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://yafvs.example/api/v1/targets/target-2',
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://yafvs.example/api/v1/targets/target-1',
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('should delete selected target IDs sequentially through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    const result = await cmd.deleteByIds(['target-1', 'target-2']);

    expect(result.data).toEqual(['target-1', 'target-2']);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://yafvs.example/api/v1/targets/target-1',
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://yafvs.example/api/v1/targets/target-2',
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('should reject missing and duplicate selected target IDs before mutation', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.delete([new Target({id: 'target-1'}), new Target({})]),
    ).rejects.toThrow('requires an ID at index 1');
    await expect(cmd.deleteByIds(['target-1', ''])).rejects.toThrow(
      'requires an ID at index 1',
    );
    await expect(
      cmd.delete([new Target({id: 'target-1'}), new Target({id: 'target-1'})]),
    ).rejects.toThrow('received duplicate ID target-1');
    await expect(cmd.deleteByIds(['target-1', 'target-1'])).rejects.toThrow(
      'received duplicate ID target-1',
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('should report immutable partial progress and stop after native failure', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: false, status: 409});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    let error: unknown;
    try {
      await cmd.deleteByIds(['target-1', 'target-2', 'target-3']);
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(NativeTargetBulkDeleteError);
    expect(error).toMatchObject({
      name: 'NativeTargetBulkDeleteError',
      deletedIds: ['target-1'],
      failedId: 'target-2',
      pendingIds: ['target-3'],
      cause: expect.objectContaining({
        message: 'Native API request failed with status 409',
      }),
    });
    const nativeError = error as NativeTargetBulkDeleteError;
    expect(Object.isFrozen(nativeError)).toEqual(true);
    expect(Object.isFrozen(nativeError.deletedIds)).toEqual(true);
    expect(Object.isFrozen(nativeError.pendingIds)).toEqual(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).not.toHaveBeenCalledWith(
      'api/v1/targets/target-3',
    );
  });

  test('should snapshot and delete the exact current filtered page', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 2, total: 5, sort: 'name', filter: 'web'},
          items: [
            {id: 'target-3', name: 'Three'},
            {id: 'target-4', name: 'Four'},
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);
    const filter = Filter.fromString('first=3 rows=2 search=web');

    const result = await cmd.deleteByFilter(filter);

    expect(result.data.map(target => target.id)).toEqual([
      'target-3',
      'target-4',
    ]);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/targets', {
      token: 'test-token',
      page: 2,
      page_size: 2,
      sort: 'name',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/targets/target-3',
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      3,
      'api/v1/targets/target-4',
    );
  });

  test('should stabilize every all-filter page before ordered deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(targetPageResponse([{id: 'target-2'}], 2, 1))
      .mockResolvedValueOnce(targetPageResponse([{id: 'target-1'}], 2, 2))
      .mockResolvedValueOnce(
        targetPageResponse([{id: 'target-2', name: 'Two'}], 2, 1),
      )
      .mockResolvedValueOnce(
        targetPageResponse([{id: 'target-1', name: 'One'}], 2, 2),
      )
      .mockResolvedValueOnce({ok: true, status: 204})
      .mockResolvedValueOnce({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=web').all();

    const result = await cmd.deleteByFilter(filter);

    expect(result.data.map(target => target.id)).toEqual([
      'target-2',
      'target-1',
    ]);
    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/targets', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/targets', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(3, 'api/v1/targets', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(4, 'api/v1/targets', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'web',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      5,
      'api/v1/targets/target-2',
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      6,
      'api/v1/targets/target-1',
    );
  });

  test('should reject same-total replacement between passes before deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(targetPageResponse([{id: 'target-1'}], 2, 1))
      .mockResolvedValueOnce(targetPageResponse([{id: 'target-2'}], 2, 2))
      .mockResolvedValueOnce(targetPageResponse([{id: 'target-1'}], 2, 1))
      .mockResolvedValueOnce(targetPageResponse([{id: 'target-3'}], 2, 2));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.deleteByFilter(Filter.fromString('rows=1').all()),
    ).rejects.toThrow('stabilization detected candidate-set drift');
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('should reject same-size reorder between passes before deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        targetPageResponse([{id: 'target-1'}, {id: 'target-2'}], 2, 1),
      )
      .mockResolvedValueOnce(
        targetPageResponse([{id: 'target-2'}, {id: 'target-1'}], 2, 1),
      );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.deleteByFilter(Filter.fromString('rows=1').all()),
    ).rejects.toThrow('stabilization detected candidate-set drift');
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('should require two empty all-filter observations without deleting', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(targetPageResponse([], 0, 1))
      .mockResolvedValueOnce(targetPageResponse([], 0, 1));
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    const result = await cmd.deleteByFilter(Filter.fromString('rows=1').all());

    expect(result.data).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('should complete two 501-target traversals before deletion', async () => {
    const targets = Array.from({length: 501}, (_, index) => ({
      id: 'target-' + (index + 1),
    }));
    const pages = [
      targetPageResponse(targets.slice(0, 500), targets.length, 1),
      targetPageResponse(targets.slice(500), targets.length, 2),
      targetPageResponse(targets.slice(0, 500), targets.length, 1),
      targetPageResponse(targets.slice(500), targets.length, 2),
    ];
    const fetchMock = testing
      .fn()
      .mockImplementation(() =>
        Promise.resolve(pages.shift() ?? {ok: true, status: 204}),
      );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    const result = await cmd.deleteByFilter(Filter.fromString('rows=1').all());

    expect(result.data.map(target => target.id)).toEqual(
      targets.map(target => target.id),
    );
    expect(fetchMock).toHaveBeenCalledTimes(505);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(4, 'api/v1/targets', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      5,
      'api/v1/targets/target-1',
    );
  });

  test('should reject all-filter total drift before any delete', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2},
          items: [{id: 'target-1'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 3},
          items: [{id: 'target-2'}],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.deleteByFilter(Filter.fromString('rows=1').all()),
    ).rejects.toThrow('preflight detected collection drift');
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject all-filter duplicate-ID drift before any delete', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2},
          items: [{id: 'target-1'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2},
          items: [{id: 'target-1'}],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.deleteByFilter(Filter.fromString('rows=1').all()),
    ).rejects.toThrow('preflight detected duplicate-ID drift');
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject a short all-filter snapshot before any delete', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2},
          items: [{id: 'target-1'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2},
          items: [],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.deleteByFilter(Filter.fromString('rows=1').all()),
    ).rejects.toThrow('preflight detected collection drift');
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });

  test('should reject a missing filtered target ID before any delete', async () => {
    const fetchMock = testing.fn().mockResolvedValueOnce({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 1, total: 1},
        items: [{name: 'Missing ID'}],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TargetsCommand(fakeHttp);

    await expect(
      cmd.deleteByFilter(Filter.fromString('first=1 rows=1')),
    ).rejects.toThrow('requires an ID at index 0');
    expect(fetchMock).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({method: 'DELETE'}),
    );
    expect(fakeHttp.request).not.toHaveBeenCalled();
  });
});
