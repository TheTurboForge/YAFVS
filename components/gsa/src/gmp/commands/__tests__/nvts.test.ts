/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import NvtsCommand from 'gmp/commands/nvts';
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
    (path: string) => `https://yafvs.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

describe('NvtsCommand tests', () => {
  test('should fetch nvts through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {
          page: 1,
          page_size: 25,
          total: 1,
          sort: '-created',
          filter: 'ssh',
        },
        items: [
          {
            id: '1.3.6.1.4.1.25623.1.0.10330',
            oid: '1.3.6.1.4.1.25623.1.0.10330',
            name: 'SSH Default Credentials',
            family: 'Brute force attacks',
            severity: 7.5,
            qod: 80,
            qod_type: 'remote_banner',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=ssh'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('1.3.6.1.4.1.25623.1.0.10330');
    expect(result.data[0].family).toEqual('Brute force attacks');
    expect(result.data[0].severity).toEqual(7.5);
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/nvts', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'created',
      filter: 'ssh',
    });
  });

  test('should bulk export selected NVTs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: '1.2.3', name: 'NVT 1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: '2.3.4', name: 'NVT 2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new NvtsCommand(fakeHttp);

    const result = await cmd.exportByIds(['1.2.3', '2.3.4']);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/nvts/1.2.3/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).nvts).toEqual([
      {id: '1.2.3', name: 'NVT 1'},
      {id: '2.3.4', name: 'NVT 2'},
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
            sort: 'created',
            filter: 'ssh',
          },
          items: [{id: '2.3.4', oid: '2.3.4', name: 'NVT 2'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: '2.3.4', name: 'NVT 2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new NvtsCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=ssh');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/nvts', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'created',
      filter: 'ssh',
    });
    expect(JSON.parse(result.data).nvts).toEqual([
      {id: '2.3.4', name: 'NVT 2'},
    ]);
  });

  test('should bulk export all filtered NVTs through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'created',
            filter: 'ssh',
          },
          items: [{id: '1.2.3', oid: '1.2.3', name: 'NVT 1'}],
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
            sort: 'created',
            filter: 'ssh',
          },
          items: [{id: '2.3.4', oid: '2.3.4', name: 'NVT 2'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: '1.2.3', name: 'NVT 1'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: '2.3.4', name: 'NVT 2'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new NvtsCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=ssh').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/nvts', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'created',
      filter: 'ssh',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/nvts', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'created',
      filter: 'ssh',
    });
    expect(JSON.parse(result.data).nvts).toEqual([
      {id: '1.2.3', name: 'NVT 1'},
      {id: '2.3.4', name: 'NVT 2'},
    ]);
  });
});
