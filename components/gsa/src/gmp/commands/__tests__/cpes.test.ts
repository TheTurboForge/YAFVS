/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import CpesCommand from 'gmp/commands/cpes';
import {
  createAggregatesResponse,
  createHttp,
  createInfoEntitiesResponse,
} from 'gmp/commands/testing';
import Cpe from 'gmp/models/cpe';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('CpesCommand tests', () => {
  test('should fetch cpes with default params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        cpe: {
          cpe_name_id: 'cpe:/a:admin:admin:1.0',
        },
      },
      {
        _id: '2',
        name: 'User',
        cpe: {
          cpe_name_id: 'cpe:/a:user:user:1.0',
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.get();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'cpe'},
    });
    expect(result.data).toEqual([
      new Cpe({
        id: '1',
        name: 'Admin',
        cpeNameId: 'cpe:/a:admin:admin:1.0',
      }),
      new Cpe({
        id: '2',
        name: 'User',
        cpeNameId: 'cpe:/a:user:user:1.0',
      }),
    ]);
  });

  test('should fetch cpes with custom params', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        cpe: {
          cpe_name_id: 'cpe:/a:admin:admin:1.0',
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.get({filter: "name='Admin'"});
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        cmd: 'get_info',
        info_type: 'cpe',
        filter: "name='Admin'",
      },
    });
    expect(result.data).toEqual([
      new Cpe({id: '1', name: 'Admin', cpeNameId: 'cpe:/a:admin:admin:1.0'}),
    ]);
  });

  test('should fetch all cpes', async () => {
    const response = createInfoEntitiesResponse([
      {
        _id: '1',
        name: 'Admin',
        cpe: {
          cpe_name_id: 'cpe:/a:admin:admin:1.0',
        },
      },
      {
        _id: '2',
        name: 'User',
        cpe: {
          cpe_name_id: 'cpe:/a:user:user:1.0',
        },
      },
    ]);
    const fakeHttp = createHttp(response);

    const cmd = new CpesCommand(fakeHttp);
    const result = await cmd.getAll();
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_info', info_type: 'cpe', filter: 'first=1 rows=-1'},
    });
    expect(result.data).toEqual([
      new Cpe({
        id: '1',
        name: 'Admin',
        cpeNameId: 'cpe:/a:admin:admin:1.0',
      }),
      new Cpe({
        id: '2',
        name: 'User',
        cpeNameId: 'cpe:/a:user:user:1.0',
      }),
    ]);
  });

  test('should fetch cpes through native API when available', async () => {
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
