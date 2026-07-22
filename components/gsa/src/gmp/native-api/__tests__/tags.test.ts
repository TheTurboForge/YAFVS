/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import {
  canUseNativeTagResourceNames,
  NativeTagBulkDeleteError,
  TagCommand,
  TagsCommand,
  updateNativeTagResources,
} from 'gmp/native-api/tags';
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

const jsonResponse = (payload: unknown, ok = true, status = 200) => ({
  json: testing.fn().mockResolvedValue(payload),
  ok,
  status,
});

describe('TagsCommand', () => {
  test('fetches the tag collection through the native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue(
      jsonResponse({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: 'name',
          filter: 'critical',
        },
        items: [
          {
            id: 'tag-1',
            name: 'Critical',
            resource_type: 'task',
            resource_count: 2,
          },
        ],
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    const response = await new TagsCommand(http).get({
      filter: 'first=1 rows=25 search=critical',
    });

    expect(http.request).not.toHaveBeenCalled();
    expect(response.data[0].id).toEqual('tag-1');
    expect(response.data[0].resourceType).toEqual('task');
    expect(response.data[0].resourceCount).toEqual(2);
    expect(response.data[0].isWritable()).toEqual(false);
    expect(http.buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'critical',
      active: '',
      resource_type: '',
      value: '',
    });
  });

  test('fetches all tags with bounded native pagination', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [{id: 'tag-1', name: 'One'}],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [{id: 'tag-2', name: 'Two'}],
        }),
      );
    testing.stubGlobal('fetch', fetchMock);

    const response = await new TagsCommand(createNativeHttp()).getAll();

    expect(response.data.map(tag => tag.id)).toEqual(['tag-1', 'tag-2']);
    expect(response.meta.counts.all).toEqual(2);
  });

  test('reports exact partial progress when native bulk delete fails', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({id: 'tag-1', name: 'One', writable: true}),
      )
      .mockResolvedValueOnce(
        jsonResponse({id: 'tag-2', name: 'Two', writable: true}),
      )
      .mockResolvedValueOnce(
        jsonResponse({id: 'tag-3', name: 'Three', writable: true}),
      )
      .mockResolvedValueOnce(jsonResponse({}, true, 204))
      .mockResolvedValueOnce(jsonResponse({}, false, 409));
    testing.stubGlobal('fetch', fetchMock);

    const promise = new TagsCommand(createNativeHttp()).deleteByIds([
      'tag-1',
      'tag-2',
      'tag-3',
    ]);

    await expect(promise).rejects.toBeInstanceOf(NativeTagBulkDeleteError);
    await expect(promise).rejects.toMatchObject({
      deletedIds: ['tag-1'],
      failedId: 'tag-2',
      pendingIds: ['tag-3'],
    });
    expect(fetchMock).toHaveBeenCalledTimes(5);
    for (const call of [1, 2, 3]) {
      expect(fetchMock.mock.calls[call - 1][1]).not.toHaveProperty('method');
    }
    for (const call of [4, 5]) {
      expect(fetchMock.mock.calls[call - 1][1]).toEqual(
        expect.objectContaining({method: 'DELETE'}),
      );
    }
  });

  test('rejects duplicate selected ids before any native request', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);

    await expect(
      new TagsCommand(createNativeHttp()).deleteByIds(['tag-1', 'tag-1']),
    ).rejects.toThrow('Native tag bulk delete requires unique tag ids');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('rejects value filters whose native semantics are not exact', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);

    await expect(
      new TagsCommand(createNativeHttp()).deleteByFilter(
        Filter.fromString('rows=-1 value=production'),
      ),
    ).rejects.toThrow(
      'Native tag bulk delete requires a losslessly supported filter',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('allows assigned writable tags to be moved to trash', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          id: 'tag-1',
          name: 'Assigned',
          resource_count: 2,
          writable: true,
          in_use: false,
        }),
      )
      .mockResolvedValueOnce(jsonResponse({}, true, 204));
    testing.stubGlobal('fetch', fetchMock);

    await new TagsCommand(createNativeHttp()).deleteByIds(['tag-1']);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][1]).toEqual(
      expect.objectContaining({method: 'DELETE'}),
    );
  });

  test('rejects unsupported destructive filters before any request', async () => {
    const fetchMock = testing.fn();
    testing.stubGlobal('fetch', fetchMock);

    await expect(
      new TagsCommand(createNativeHttp()).deleteByFilter(
        Filter.fromString('rows=-1 name=production'),
      ),
    ).rejects.toThrow(
      'Native tag bulk delete requires a losslessly supported filter',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('snapshots all filtered tags before native deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'x'},
          items: [{id: 'tag-1', name: 'One', writable: true}],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'x'},
          items: [{id: 'tag-2', name: 'Two', writable: true}],
        }),
      )
      .mockResolvedValueOnce(jsonResponse({}, true, 204))
      .mockResolvedValueOnce(jsonResponse({}, true, 204));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    const response = await new TagsCommand(http).deleteByFilter(
      Filter.fromString('first=2 rows=1 search=x'),
    );

    expect(response.data.map(tag => tag.id)).toEqual(['tag-1', 'tag-2']);
    expect(fetchMock).toHaveBeenCalledTimes(4);
    for (const call of [1, 2]) {
      expect(fetchMock.mock.calls[call - 1][1]).not.toHaveProperty('method');
    }
    for (const call of [3, 4]) {
      expect(fetchMock.mock.calls[call - 1][1]).toEqual(
        expect.objectContaining({method: 'DELETE'}),
      );
    }
    expect(http.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'x',
      active: '',
      resource_type: '',
      value: '',
    });
  });

  test('rejects duplicate ids across snapshot pages before deletion', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'x'},
          items: [{id: 'tag-1', name: 'One', writable: true}],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'x'},
          items: [{id: 'tag-1', name: 'One', writable: true}],
        }),
      );
    testing.stubGlobal('fetch', fetchMock);

    await expect(
      new TagsCommand(createNativeHttp()).deleteByFilter(
        Filter.fromString('rows=-1 search=x'),
      ),
    ).rejects.toThrow(
      'Native tag bulk delete preflight detected collection drift',
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [, options] of fetchMock.mock.calls) {
      expect(options).not.toHaveProperty('method');
    }
  });

  test('rejects mixed writable selection before any native delete', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({id: 'tag-1', name: 'One', writable: true}),
      )
      .mockResolvedValueOnce(
        jsonResponse({id: 'tag-2', name: 'Global', writable: false}),
      );
    testing.stubGlobal('fetch', fetchMock);

    await expect(
      new TagsCommand(createNativeHttp()).deleteByIds(['tag-1', 'tag-2']),
    ).rejects.toThrow('Native tag bulk delete refused non-writable tag tag-2');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [, options] of fetchMock.mock.calls) {
      expect(options).not.toHaveProperty('method');
    }
  });

  test('rejects collection drift before deleting an all-filtered snapshot', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'x'},
          items: [{id: 'tag-1', name: 'One', writable: true}],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 2, page_size: 500, total: 3, sort: 'name', filter: 'x'},
          items: [
            {id: 'tag-2', name: 'Two', writable: true},
            {id: 'tag-3', name: 'Three', writable: true},
          ],
        }),
      );
    testing.stubGlobal('fetch', fetchMock);

    await expect(
      new TagsCommand(createNativeHttp()).deleteByFilter(
        Filter.fromString('rows=-1 search=x'),
      ),
    ).rejects.toThrow(
      'Native tag bulk delete preflight detected collection drift',
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [, options] of fetchMock.mock.calls) {
      expect(options).not.toHaveProperty('method');
    }
  });
});

describe('TagCommand', () => {
  test('creates a tag with explicit resource ids through native JSON', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(jsonResponse({id: 'tag-1'}));
    testing.stubGlobal('fetch', fetchMock);

    const response = await new TagCommand(createNativeHttp()).create({
      active: true,
      comment: 'note',
      name: 'Critical',
      resourceIds: ['task-1'],
      resourceType: 'task',
      value: 'high',
    });

    expect(response.data.id).toEqual('tag-1');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/tags',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          active: true,
          comment: 'note',
          name: 'Critical',
          resource_ids: ['task-1'],
          resource_type: 'task',
          value: 'high',
        }),
      }),
    );
  });

  test('saves metadata and replacement assignments atomically', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(jsonResponse({id: 'tag-1'}));
    testing.stubGlobal('fetch', fetchMock);

    await new TagCommand(createNativeHttp()).save({
      active: false,
      comment: 'changed',
      id: 'tag-1',
      name: 'Renamed',
      resourceIds: [],
      resourceType: 'target',
      resourcesAction: 'set',
      value: 'critical',
    });

    const options = fetchMock.mock.calls[0][1];
    expect(options.method).toEqual('PATCH');
    expect(JSON.parse(options.body)).toEqual({
      active: false,
      comment: 'changed',
      name: 'Renamed',
      value: 'critical',
      resource_type: 'target',
      resources: {action: 'set', resource_ids: []},
    });
  });

  test('rejects the retired raw filtered assignment input', () => {
    const command = new TagCommand(createNativeHttp());
    expect(() =>
      command.save({
        active: true,
        id: 'tag-1',
        name: 'High severity',
        resourceType: 'result',
        resourcesAction: 'add',
        filter: 'rows=-1 severity>7',
      } as Parameters<typeof command.save>[0] & {filter: string}),
    ).toThrow('Raw tag resource filters are not supported');
  });

  test('saves a typed port-list collection selection', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(jsonResponse({id: 'tag-1'}));
    testing.stubGlobal('fetch', fetchMock);

    await new TagCommand(createNativeHttp()).save({
      active: true,
      id: 'tag-1',
      name: 'Managed port lists',
      resourceSelection: {
        resourceType: 'port_list',
        search: 'office',
        predefined: false,
        expectedCount: 7,
      },
      resourceType: 'portlist',
      resourcesAction: 'add',
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.resources).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'port_list',
        search: 'office',
        predefined: false,
        expected_count: 7,
      },
    });
    expect(body.resource_type).toBeUndefined();
  });

  test('rejects a detail filter outside the native detail contract', async () => {
    await expect(
      new TagCommand(createNativeHttp()).get(
        {id: 'tag-1'},
        {filter: 'results=1'},
      ),
    ).rejects.toThrow('Native tag detail filter is not supported');
  });
});

describe('native tag resource assignments', () => {
  test('supports filter updates and explicit empty set', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(jsonResponse({id: 'tag-1'}));
    testing.stubGlobal('fetch', fetchMock);
    const http = createNativeHttp();

    await updateNativeTagResources(http, 'tag-1', {
      action: 'set',
      resourceIds: [],
    });
    await updateNativeTagResources(http, 'tag-1', {
      action: 'add',
      resourceSelection: {
        resourceType: 'port_list',
        expectedCount: 2,
      },
    });
    await updateNativeTagResources(http, 'tag-1', {
      action: 'add',
      resourceSelection: {
        resourceType: 'credential',
        search: 'operations',
        credentialType: 'up',
        expectedCount: 3,
      },
    });
    await updateNativeTagResources(http, 'tag-1', {
      action: 'add',
      resourceSelection: {
        resourceType: 'scanner',
        search: 'remote',
        expectedCount: 4,
      },
    });
    await updateNativeTagResources(http, 'tag-1', {
      action: 'add',
      resourceSelection: {
        resourceType: 'target',
        search: 'production',
        expectedCount: 5,
      },
    });
    await updateNativeTagResources(http, 'tag-1', {
      action: 'add',
      resourceSelection: {
        resourceType: 'user',
        search: 'alice',
        expectedCount: 2,
      },
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      action: 'set',
      resource_ids: [],
    });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'port_list',
        expected_count: 2,
      },
    });
    expect(JSON.parse(fetchMock.mock.calls[4][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'target',
        search: 'production',
        expected_count: 5,
      },
    });
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'credential',
        search: 'operations',
        credential_type: 'up',
        expected_count: 3,
      },
    });
    expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'scanner',
        search: 'remote',
        expected_count: 4,
      },
    });
    expect(JSON.parse(fetchMock.mock.calls[5][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'user',
        search: 'alice',
        expected_count: 2,
      },
    });
  });

  test('supports every retained tag-dialog resource type', () => {
    const gmp = createNativeHttp();
    for (const type of ['credential', 'filter', 'override', 'user'] as const) {
      expect(canUseNativeTagResourceNames(gmp, type)).toEqual(true);
    }
  });
});
