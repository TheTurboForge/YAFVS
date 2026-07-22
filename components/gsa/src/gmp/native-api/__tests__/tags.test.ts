/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
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
  });

  test('deletes all filtered tags from page one until empty', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 1, page_size: 500, total: 1, sort: 'name', filter: 'x'},
          items: [{id: 'tag-1', name: 'One'}],
        }),
      )
      .mockResolvedValueOnce(jsonResponse({}, true, 204))
      .mockResolvedValueOnce(
        jsonResponse({
          page: {page: 1, page_size: 500, total: 0, sort: 'name', filter: 'x'},
          items: [],
        }),
      );
    testing.stubGlobal('fetch', fetchMock);

    const response = await new TagsCommand(createNativeHttp()).deleteByFilter(
      Filter.fromString('rows=-1 search=x'),
    );

    expect(response.data.map(tag => tag.id)).toEqual(['tag-1']);
    expect(fetchMock).toHaveBeenCalledTimes(3);
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

  test('saves all-filtered assignment without exposing GMP or XML', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValue(jsonResponse({id: 'tag-1'}));
    testing.stubGlobal('fetch', fetchMock);

    await new TagCommand(createNativeHttp()).save({
      active: true,
      filter: 'rows=-1 severity>7',
      id: 'tag-1',
      name: 'High severity',
      resourceType: 'result',
      resourcesAction: 'add',
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.resources).toEqual({
      action: 'add',
      resource_filter: 'rows=-1 severity>7',
    });
    expect(body.resource_type).toBeUndefined();
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
      action: 'add',
      filter: 'rows=-1 name~production',
    });
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

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      action: 'add',
      resource_filter: 'rows=-1 name~production',
    });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      action: 'set',
      resource_ids: [],
    });
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'port_list',
        expected_count: 2,
      },
    });
    expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({
      action: 'add',
      resource_selection: {
        resource_type: 'credential',
        search: 'operations',
        credential_type: 'up',
        expected_count: 3,
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
