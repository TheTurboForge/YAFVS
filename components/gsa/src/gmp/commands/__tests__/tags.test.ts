/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TagsCommand from 'gmp/commands/tags';
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
    (path: string) => `https://turbovas.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('TagsCommand tests', () => {
  test('should fetch tags through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'owner'},
        items: [
          {
            id: 'tag-1',
            name: 'Owner',
            value: 'SecOps',
            resource_type: 'task',
            resource_count: 2,
            active: true,
            writable: true,
            permissions: ['get_tags', 'modify_tag'],
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new TagsCommand(fakeHttp);
    const result = await cmd.get({
      filter: 'first=1 rows=25 search=owner resource_type=task active=1',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('tag-1');
    expect(result.data[0].name).toEqual('Owner');
    expect(result.data[0].resourceType).toEqual('task');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'owner',
      active: '1',
      resource_type: 'task',
      value: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tags',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 2, total: 3, sort: 'name', filter: ''},
        items: [
          {
            id: 'tag-1',
            name: 'One',
            resource_type: 'task',
            resource_count: 1,
            active: true,
            writable: true,
          },
          {
            id: 'tag-2',
            name: 'Two',
            resource_type: 'host',
            resource_count: 2,
            active: true,
            writable: true,
          },
        ],
      },
      {
        page: {page: 2, page_size: 2, total: 3, sort: 'name', filter: ''},
        items: [
          {
            id: 'tag-3',
            name: 'Three',
            resource_type: 'result',
            resource_count: 3,
            active: false,
            writable: true,
          },
        ],
      },
    ];
    const fetchMock = testing.fn().mockImplementation(() =>
      Promise.resolve({
        json: testing.fn().mockResolvedValue(responses.shift()),
        ok: true,
        status: 200,
      }),
    );
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new TagsCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(result.data.map(tag => tag.id)).toEqual(['tag-1', 'tag-2', 'tag-3']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
      active: '',
      resource_type: '',
      value: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/tags', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: '',
      active: '',
      resource_type: '',
      value: '',
    });
  });

  test('should bulk export selected tags through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tag-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tag-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TagsCommand(fakeHttp);

    const result = await cmd.exportByIds(['tag-1', 'tag-2']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/tags/tag-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/tags/tag-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).tags).toEqual([
      {id: 'tag-1', name: 'One'},
      {id: 'tag-2', name: 'Two'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'name', filter: 'owner'},
          items: [{id: 'tag-2', name: 'Two', resource_type: 'task'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tag-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TagsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=owner');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/tags', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'owner',
      active: '',
      resource_type: '',
      value: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/tags/tag-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).tags).toEqual([
      {id: 'tag-2', name: 'Two'},
    ]);
  });

  test('should bulk export all filtered tags through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: 'owner'},
          items: [{id: 'tag-1', name: 'One', resource_type: 'task'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: 'owner'},
          items: [{id: 'tag-2', name: 'Two', resource_type: 'task'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tag-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'tag-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new TagsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=owner').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/tags', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'owner',
      active: '',
      resource_type: '',
      value: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/tags', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'owner',
      active: '',
      resource_type: '',
      value: '',
    });
    expect(JSON.parse(result.data).tags).toEqual([
      {id: 'tag-1', name: 'One'},
      {id: 'tag-2', name: 'Two'},
    ]);
  });
});
