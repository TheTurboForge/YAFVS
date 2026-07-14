/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {createHttp} from 'gmp/commands/testing';
import UsersCommand from 'gmp/commands/users';
import Filter from 'gmp/models/filter';
import User from 'gmp/models/user';
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

describe('UsersCommand tests', () => {
  test('should preserve collection query and count mappings on user-management reads', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 75,
          sort: 'name',
          filter: 'Alice',
        },
        items: [
          {
            id: 'user-1',
            name: 'Alice',
            comment: 'operator',
            auth_method: 'ldap',
            created_at: '2026-07-07T00:00:00Z',
            modified_at: '2026-07-07T01:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);

    const result = await cmd.get({filter: 'first=1 rows=25 search=Alice'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith(
      'api/v1/user-management/users',
      {
        token: 'test-token',
        page: 1,
        page_size: 25,
        sort: 'name',
        filter: 'Alice',
      },
    );
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/user-management/users',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'X-TurboVAS-Token': 'test-token',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
    expect(result.data[0]).toMatchObject({
      id: 'user-1',
      name: 'Alice',
      comment: 'operator',
      authMethod: 'ldap',
    });
    expect(result.data[0].creationTime?.toISOString()).toEqual(
      '2026-07-07T00:00:00.000Z',
    );
    expect(result.meta.counts.all).toBe(75);
  });

  test('should page through the management collection for getAll', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [{id: 'user-1', name: 'Alice', auth_method: 'password'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [{id: 'user-2', name: 'Ada', auth_method: 'radius'}],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);

    const result = await cmd.getAll();

    expect(result.data).toHaveLength(2);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/user-management/users',
      {token: 'test-token', page: 1, page_size: 500, sort: 'name', filter: ''},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/user-management/users',
      {token: 'test-token', page: 2, page_size: 500, sort: 'name', filter: ''},
    );
  });

  test('should keep selected metadata exports on the redacted users route', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({id: 'user-1', name: 'Alice'}),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);

    const result = await cmd.export([new User({id: 'user-1'})]);

    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/users/user-1', {
      token: 'test-token',
    });
    expect(JSON.parse(result.data)).toEqual({
      users: [{id: 'user-1', name: 'Alice'}],
    });
  });

  test('should use management reads to select redacted exports by filter', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [
            {id: 'user-1', name: 'Alice', auth_method: 'password'},
            {id: 'user-2', name: 'Ada', auth_method: 'radius'},
          ],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'user-1', name: 'Alice'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'user-2', name: 'Ada'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);

    const result = await cmd.exportByFilter(Filter.fromString('rows=-1'));

    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/user-management/users',
      {token: 'test-token', page: 1, page_size: 500, sort: 'name', filter: ''},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/users/user-1',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      3,
      'api/v1/users/user-2',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).users).toEqual([
      {id: 'user-1', name: 'Alice'},
      {id: 'user-2', name: 'Ada'},
    ]);
  });

  test('should delete selected users through detail routes', async () => {
    const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);

    await cmd.delete([new User({id: 'user-1'}), new User({id: 'user-2'})], {
      inheritor_id: 'owner-id',
    });

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/user-management/users/user-1',
      {inheritor_id: 'owner-id'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/user-management/users/user-2',
      {inheritor_id: 'owner-id'},
    );
  });
});
