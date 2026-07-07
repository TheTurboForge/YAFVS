/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CpesCommand from 'gmp/commands/cpes';
import {createAggregatesResponse, createHttp} from 'gmp/commands/testing';
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

describe('CpesCommand tests', () => {
  test('should fetch cpes through native API', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-modified', filter: 'Admin'},
        items: [
          {
            id: 'cpe:/a:admin:admin:1.0',
            name: 'Admin',
            title: 'Admin 1.0',
            cpe_name_id: 'cpe:/a:admin:admin:1.0',
            deprecated: false,
            severity: 7.1,
            cve_refs: 2,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=Admin'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('cpe:/a:admin:admin:1.0');
    expect(result.data[0].title).toEqual('Admin 1.0');
    expect(result.data[0].severity).toEqual(7.1);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/cpes', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'modified',
      filter: 'Admin',
    });
    expect(fetchMock).toHaveBeenCalledWith('https://turbovas.example/api/v1/cpes', {
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer jwt-token',
      },
    });
  });

  test('should page through native API for getAll', async () => {
    const responses = [
      {
        page: {page: 1, page_size: 2, total: 3, sort: '-modified', filter: ''},
        items: [
          {id: 'cpe:/a:admin:admin:1.0', name: 'Admin', title: 'Admin 1.0'},
          {id: 'cpe:/a:user:user:1.0', name: 'User', title: 'User 1.0'},
        ],
      },
      {
        page: {page: 2, page_size: 2, total: 3, sort: '-modified', filter: ''},
        items: [
          {id: 'cpe:/a:ops:ops:1.0', name: 'Ops', title: 'Ops 1.0'},
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

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.getAll();

    expect(result.data.map(cpe => cpe.id)).toEqual([
      'cpe:/a:admin:admin:1.0',
      'cpe:/a:user:user:1.0',
      'cpe:/a:ops:ops:1.0',
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('should bulk export selected CPEs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'cpe:/a:admin:admin:1.0'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'cpe:/a:user:user:1.0'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CpesCommand(fakeHttp);

    const result = await cmd.exportByIds([
      'cpe:/a:admin:admin:1.0',
      'cpe:/a:user:user:1.0',
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/cpes/cpe%3A%2Fa%3Aadmin%3Aadmin%3A1.0',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).cpes).toEqual([
      {id: 'cpe:/a:admin:admin:1.0'},
      {id: 'cpe:/a:user:user:1.0'},
    ]);
  });

  test('should bulk export current page filter through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 1, total: 3, sort: 'modified', filter: 'Admin'},
          items: [{id: 'cpe:/a:user:user:1.0'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'cpe:/a:user:user:1.0'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CpesCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=Admin');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/cpes', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'modified',
      filter: 'Admin',
    });
    expect(JSON.parse(result.data).cpes).toEqual([
      {id: 'cpe:/a:user:user:1.0'},
    ]);
  });

  test('should bulk export all filtered CPEs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 1, page_size: 500, total: 2, sort: 'modified', filter: 'Admin'},
          items: [{id: 'cpe:/a:admin:admin:1.0'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'modified', filter: 'Admin'},
          items: [{id: 'cpe:/a:user:user:1.0'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'cpe:/a:admin:admin:1.0'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'cpe:/a:user:user:1.0'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new CpesCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=Admin').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/cpes', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'modified',
      filter: 'Admin',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/cpes', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'modified',
      filter: 'Admin',
    });
    expect(JSON.parse(result.data).cpes).toEqual([
      {id: 'cpe:/a:admin:admin:1.0'},
      {id: 'cpe:/a:user:user:1.0'},
    ]);
  });

  test('should fetch severity aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'cpe',
        group_column: 'severity',
        info_type: 'cpe',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch created aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.getCreatedAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'cpe',
        group_column: 'created',
        info_type: 'cpe',
      },
    });
    expect(result.data).toEqual({groups: []});
  });
});
