/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TagsCommand from 'gmp/commands/tags';
import {createEntitiesResponse, createHttp} from 'gmp/commands/testing';
import Tag from 'gmp/models/tag';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TagsCommand tests', () => {
  test('should fetch with default params', async () => {
    const response = createEntitiesResponse('tag', [
      {_id: '1', name: 'Tag 1', resources: {type: 'scanner'}},
      {_id: '2', name: 'Tag 2', resources: {type: 'task'}},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TagsCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_tags'},
    });
    expect(result.data).toEqual([
      new Tag({
        id: '1',
        name: 'Tag 1',
        resourceType: 'scanner',
      }),
      new Tag({
        id: '2',
        name: 'Tag 2',
        resourceType: 'task',
      }),
    ]);
  });

  test('should fetch with custom params', async () => {
    const response = createEntitiesResponse('tag', [
      {_id: '3', name: 'Tag 1', resources: {type: 'scanner'}},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TagsCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Tag 1'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_tags', filter: "name='Tag 1'"},
    });
    expect(result.data).toEqual([
      new Tag({
        id: '3',
        name: 'Tag 1',
        resourceType: 'scanner',
      }),
    ]);
  });

  test('should get all tags', async () => {
    const response = createEntitiesResponse('tag', [
      {_id: '1', name: 'Tag 1', resources: {type: 'scanner'}},
      {_id: '2', name: 'Tag 2', resources: {type: 'task'}},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new TagsCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_tags', filter: 'first=1 rows=-1'},
    });
    expect(result.data).toEqual([
      new Tag({
        id: '1',
        name: 'Tag 1',
        resourceType: 'scanner',
      }),
      new Tag({
        id: '2',
        name: 'Tag 2',
        resourceType: 'task',
      }),
    ]);
  });

  test('should fetch tags through native API when available', async () => {
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
});
