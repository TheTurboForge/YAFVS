/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import NvtsCommand from 'gmp/commands/nvts';
import {
  createAggregatesResponse,
  createHttp,
  createInfoEntitiesResponse,
} from 'gmp/commands/testing';
import Filter from 'gmp/models/filter';
import Nvt from 'gmp/models/nvt';
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

describe('NvtsCommand tests', () => {
  test('should fetch nvts with default params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        nvt: {
          _oid: '1.2.3',
        },
      },
      {
        _id: '2',
        name: 'User',
        nvt: {
          _oid: '2.3.4',
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'nvt'},
    });
    expect(result.data).toEqual([
      new Nvt({
        id: '1.2.3',
        name: 'Admin',
        oid: '1.2.3',
      }),
      new Nvt({
        id: '2.3.4',
        name: 'User',
        oid: '2.3.4',
      }),
    ]);
  });

  test('should fetch nvts with custom params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        nvt: {
          _oid: '1.2.3',
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Admin'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_info',
        info_type: 'nvt',
        filter: "name='Admin'",
      },
    });
    expect(result.data).toEqual([
      new Nvt({id: '1.2.3', name: 'Admin', oid: '1.2.3'}),
    ]);
  });

  test('should fetch all nvts', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        nvt: {
          _oid: '1.2.3',
        },
      },
      {
        _id: '2',
        name: 'User',
        nvt: {
          _oid: '2.3.4',
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'nvt', filter: 'first=1 rows=-1'},
    });
    expect(result.data).toEqual([
      new Nvt({
        id: '1.2.3',
        name: 'Admin',
        oid: '1.2.3',
      }),
      new Nvt({
        id: '2.3.4',
        name: 'User',
        oid: '2.3.4',
      }),
    ]);
  });

  test('should fetch nvts through native API when available', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-created', filter: 'ssh'},
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

  test('should use inherited bulk export on non-native http', async () => {
    const fakeHttp = createHttp();
    const cmd = new NvtsCommand(fakeHttp);

    await cmd.exportByIds(['1.2.3', '2.3.4']);

    expect(fakeHttp.request).toHaveBeenCalledWith('post', {
      data: {
        cmd: 'bulk_export',
        resource_type: 'info',
        bulk_select: 1,
        'bulk_selected:1.2.3': 1,
        'bulk_selected:2.3.4': 1,
      },
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
          page: {page: 2, page_size: 1, total: 3, sort: 'created', filter: 'ssh'},
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
          page: {page: 1, page_size: 500, total: 2, sort: 'created', filter: 'ssh'},
          items: [{id: '1.2.3', oid: '1.2.3', name: 'NVT 1'}],
        }),
        ok: true,
        status: 200,
      })
      .mockResolvedValueOnce({
        json: testing.fn().mockResolvedValue({
          page: {page: 2, page_size: 500, total: 2, sort: 'created', filter: 'ssh'},
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

  test('should fetch severity aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.getSeverityAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'nvt',
        group_column: 'severity',
        info_type: 'nvt',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch created aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.getCreatedAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'nvt',
        group_column: 'created',
        info_type: 'nvt',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch family aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.getFamilyAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'nvt',
        group_column: 'family',
        info_type: 'nvt',
        'data_columns:0': 'severity',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch qod aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.getQodAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'nvt',
        group_column: 'qod',
        info_type: 'nvt',
      },
    });
    expect(result.data).toEqual({groups: []});
  });

  test('should fetch qod type aggregates', async () => {
    const response = createAggregatesResponse({});
    const fakeHttp = createHttp(response);

    const cmd = new NvtsCommand(fakeHttp);
    const result = await cmd.getQodTypeAggregates();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_aggregate',
        aggregate_type: 'nvt',
        group_column: 'qod_type',
        info_type: 'nvt',
      },
    });
    expect(result.data).toEqual({groups: []});
  });
});
