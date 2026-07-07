/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import ScannersCommand from 'gmp/commands/scanners';
import {createEntitiesResponse, createHttp} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import Scanner, {
  OPENVAS_SCANNER_TYPE,
  OPENVASD_SCANNER_TYPE,
} from 'gmp/models/scanner';
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

describe('ScannersCommand tests', () => {
  test('should fetch with default params', async () => {
    const response = createEntitiesResponse('scanner', [
      {_id: '1', name: 'Scanner 1', type: OPENVASD_SCANNER_TYPE},
      {_id: '2', name: 'Scanner 2', type: OPENVAS_SCANNER_TYPE},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new ScannersCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_scanners'},
    });
    expect(result.data).toEqual([
      new Scanner({
        id: '1',
        name: 'Scanner 1',
        scannerType: OPENVASD_SCANNER_TYPE,
      }),
      new Scanner({
        id: '2',
        name: 'Scanner 2',
        scannerType: OPENVAS_SCANNER_TYPE,
      }),
    ]);
  });

  test('should fetch with custom params', async () => {
    const response = createEntitiesResponse('scanner', [
      {_id: '3', name: 'Scanner 1', type: OPENVASD_SCANNER_TYPE},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new ScannersCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Scanner 1'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_scanners', filter: "name='Scanner 1'"},
    });
    expect(result.data).toEqual([
      new Scanner({
        id: '3',
        name: 'Scanner 1',
        scannerType: OPENVASD_SCANNER_TYPE,
      }),
    ]);
  });

  test('should all roles', async () => {
    const response = createEntitiesResponse('scanner', [
      {_id: '4', name: 'Scanner 1', type: OPENVASD_SCANNER_TYPE},
      {_id: '5', name: 'Scanner 2', type: OPENVAS_SCANNER_TYPE},
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new ScannersCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_scanners', filter: 'first=1 rows=-1'},
    });
    expect(result.data).toEqual([
      new Scanner({
        id: '4',
        name: 'Scanner 1',
        scannerType: OPENVASD_SCANNER_TYPE,
      }),
      new Scanner({
        id: '5',
        name: 'Scanner 2',
        scannerType: OPENVAS_SCANNER_TYPE,
      }),
    ]);
  });

  test('should fetch scanners through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: 'name', filter: 'OpenVAS'},
        items: [
          {
            id: '08b69003-5fc2-4037-a479-93b440211c73',
            name: 'OpenVAS Default',
            comment: 'native scanner metadata',
            host: '/runtime/run/ospd/ospd-openvas.sock',
            port: 0,
            scanner_type: 2,
            credential: {
              id: '6d799e1f-a81b-4b33-8090-5d4b0ed8ec77',
              name: 'Scanner credential',
            },
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

    const cmd = new ScannersCommand(fakeHttp);
    const result = await cmd.get({filter: 'first=1 rows=25 search=OpenVAS'});

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(result.data[0].id).toEqual('08b69003-5fc2-4037-a479-93b440211c73');
    expect(result.data[0].name).toEqual('OpenVAS Default');
    expect(result.data[0].scannerType).toEqual('2');
    expect(fakeHttp.buildUrl).toHaveBeenCalledWith('api/v1/scanners', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: 'name',
      filter: 'OpenVAS',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/scanners',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });

  test('should bulk export selected scanners through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'scanner-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'scanner-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScannersCommand(fakeHttp);

    const result = await cmd.export([
      new Scanner({id: 'scanner-1'}),
      new Scanner({id: 'scanner-2'}),
    ]);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      1,
      'api/v1/scanners/scanner-1/export',
      {token: 'test-token'},
    );
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(
      2,
      'api/v1/scanners/scanner-2/export',
      {token: 'test-token'},
    );
    expect(JSON.parse(result.data).scanners).toEqual([
      {id: 'scanner-1', name: 'One'},
      {id: 'scanner-2', name: 'Two'},
    ]);
  });

  test('should bulk export current page scanners through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 2,
            page_size: 1,
            total: 3,
            sort: 'name',
            filter: 'OpenVAS',
          },
          items: [{id: 'scanner-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'scanner-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScannersCommand(fakeHttp);
    const filter = Filter.fromString('first=2 rows=1 search=OpenVAS');

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/scanners', {
      token: 'test-token',
      page: 2,
      page_size: 1,
      sort: 'name',
      filter: 'OpenVAS',
    });
    expect(JSON.parse(result.data).scanners).toEqual([
      {id: 'scanner-2', name: 'Two'},
    ]);
  });

  test('should bulk export all filtered scanners through native API', async () => {
    const fetchMock = testing
      .fn()
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {
            page: 1,
            page_size: 500,
            total: 2,
            sort: 'name',
            filter: 'OpenVAS',
          },
          items: [{id: 'scanner-1', name: 'One'}],
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
            filter: 'OpenVAS',
          },
          items: [{id: 'scanner-2', name: 'Two'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'scanner-1', name: 'One'}),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({id: 'scanner-2', name: 'Two'}),
        ok: true,
        status: 200,
      });
    testing.stubGlobal('fetch', fetchMock);
    const fakeHttp = createNativeHttp();
    const cmd = new ScannersCommand(fakeHttp);
    const filter = Filter.fromString('first=1 rows=1 search=OpenVAS').all();

    const result = await cmd.exportByFilter(filter);

    expect(fakeHttp.request).not.toHaveBeenCalled();
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(1, 'api/v1/scanners', {
      token: 'test-token',
      page: 1,
      page_size: 500,
      sort: 'name',
      filter: 'OpenVAS',
    });
    expect(fakeHttp.buildUrl).toHaveBeenNthCalledWith(2, 'api/v1/scanners', {
      token: 'test-token',
      page: 2,
      page_size: 500,
      sort: 'name',
      filter: 'OpenVAS',
    });
    expect(JSON.parse(result.data).scanners).toEqual([
      {id: 'scanner-1', name: 'One'},
      {id: 'scanner-2', name: 'Two'},
    ]);
  });
});
