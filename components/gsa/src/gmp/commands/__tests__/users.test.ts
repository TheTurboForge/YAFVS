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
  test('should fetch users through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'admin'},
        items: [
          {
            id: '9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001',
            name: 'admin',
            comment: 'redacted native account metadata',
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
    const result = await cmd.get({filter: 'first=1 rows=25 search=admin'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('9f6c71ce-4f9c-41e2-8c8d-74b8a1aef001');
    expect(result.data[0].name).toEqual('admin');
    expect(result.data[0].comment).toEqual('redacted native account metadata');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/users', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'admin',
    });
  });

  test('should page through native API for getAll', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [{id: 'user-1', name: 'Alice'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'name', filter: ''},
          items: [{id: 'user-2', name: 'Bob'}],
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new UsersCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data).toHaveLength(2);
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/users', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: '',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/users', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: '',
    });
  });

  test('should bulk export selected redacted users through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'user-1', name: 'Alice'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'user-2', name: 'Bob'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);

    const result = await cmd.export([
      new User({id: 'user-1'}),
      new User({id: 'user-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/users/user-1',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/users/user-2',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).users).toEqual([
      {id: 'user-1', name: 'Alice'},
      {id: 'user-2', name: 'Bob'},
    ]);
  });

  test('should bulk export current page redacted users through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'a',
          },
          items: [{id: 'user-2', name: 'Alice'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'user-2',
          name: 'Alice',
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=a');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/users', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'a',
    });
    expect(JSON.parse(result.data).users).toEqual([
      {id: 'user-2', name: 'Alice'},
    ]);
  });

  test('should bulk export all filtered redacted users through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'a',
          },
          items: [{id: 'user-1', name: 'Alice'}],
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
            filter: 'a',
          },
          items: [{id: 'user-2', name: 'Ada'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'user-1',
          name: 'Alice',
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          id: 'user-2',
          name: 'Ada',
        }),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new UsersCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=a').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/users', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'a',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/users', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'a',
    });
    expect(JSON.parse(result.data).users).toEqual([
      {id: 'user-1', name: 'Alice'},
      {id: 'user-2', name: 'Ada'},
    ]);
  });
});
